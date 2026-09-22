# ------------------------------------------------------------------
# PATENT NOTICE -- Quantamix Solutions B.V.
#
# This module implements methods covered by European Patent
# Applications EP26162901.8 and EP26166054.2, owned by
# Quantamix Solutions B.V.
#
# Use of this software is permitted under the graqle license.
# Reimplementation of the patented methods outside this software
# requires a separate patent license.
#
# Contact: support@quantamixsolutions.com
# ------------------------------------------------------------------

"""Governed Execution Trace Schema (R18 ADR-201).

Defines the Pydantic trace model for capturing governed execution events,
tool calls, and governance decisions. Every MCP tool call produces a
GovernedTrace record that is validated, persisted, and ingested into the KG.

Public serialization (to_public_dict) excludes governance_decisions.
Internal serialization (to_internal_dict) preserves the full trace.

TS-2 Gate: GovernanceDecision structure is internal IP.
"""

from __future__ import annotations

import logging
import math
import os
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

logger = logging.getLogger("graqle.governance.trace_schema")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class GateType(str, Enum):
    """Types of governance gates that can produce decisions."""

    CLEARANCE = "CLEARANCE"
    IP_TRADE = "IP_TRADE"
    GIT_GOVERNANCE = "GIT_GOVERNANCE"
    BUDGET = "BUDGET"


class Decision(str, Enum):
    """Outcome of a governance gate evaluation."""

    PASS = "PASS"
    BLOCK = "BLOCK"
    WARN = "WARN"


class ClearanceLevel(str, Enum):
    """Classification level for trace records.

    Aligned with core/types.ClearanceLevel (int, Enum).
    R18 spec uses 'SECRET' for the highest level; implementation uses
    'RESTRICTED' to match the existing core/types convention.
    Mapping: spec SECRET = implementation RESTRICTED.
    """

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class Outcome(str, Enum):
    """Overall outcome of a governed tool execution."""

    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Nested Models
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """Record of a nested tool invocation within a governed execution."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    result_summary: str | None = None


class GovernanceDecision(BaseModel):
    """A single governance gate decision. TS-2 gated internal IP."""

    model_config = ConfigDict(extra="forbid")

    gate_id: str
    gate_type: GateType
    decision: Decision
    reason: str = Field(max_length=200)
    auto_corrected: bool = False


# ---------------------------------------------------------------------------
# Main Trace Model
# ---------------------------------------------------------------------------

_QUERY_MAX_LENGTH = 4000
_NON_PRINTABLE_RE = re.compile(r"[^\x20-\x7E\t\n]")


# -- cr-017: schema-versioning constants -------------------------------------
#
# Sentinel returned when reading a pre-v0.58.0 record that never carried a
# ``policy_version`` field (the field was added in cr-017). Helpers that need
# a non-null content-addressed identifier read the field; if it is missing
# OR ``None``, they return this sentinel so downstream tooling (compliance
# export, KG ingestion, OPSF Use B PCT validators) can distinguish
# "trace pre-dates policy binding" from "policy binding intentionally absent".
LEGACY_POLICY_VERSION_SENTINEL: str = "legacy_pre_v058_unknown"

# Current wire-format schema version. Bumped to "2" in cr-017 (was implicit
# "1" before this CR introduced explicit versioning). Pre-cr-017 records on
# disk have NO ``schema_version`` field at all and are treated as v1 by
# :func:`classify_schema_version`.
CURRENT_SCHEMA_VERSION: str = "3"

# Every wire version this module can READ. Bumped to include "3" in CR-012
# PR-012b, which adds the optional ``assurance`` projection (INV-TS-1: the v3
# field set is a strict superset of v2, so every v2 record validates under the
# v3 model).
SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1", "2", "3"})


def classify_schema_version(raw: dict[str, Any] | None) -> str:
    """Classify a serialized trace record's schema version.

    Args:
        raw: A trace dict parsed from JSONL/JSON. ``None`` is treated as v1
            for symmetry with empty-record edge cases.

    Returns:
        ``"2"`` (or higher) if the record explicitly declares
        ``schema_version``. ``"1"`` if the field is absent (pre-cr-017
        records). The returned value is a string for forward compatibility
        with future schema bumps (``"3"`` etc.).
    """
    if raw is None:
        return "1"
    version = raw.get("schema_version")
    if isinstance(version, str) and version:
        return version
    return "1"


def _pinned_version() -> str:
    """Reader pin. Unset means the current writer version (CR-012 §5.5)."""
    return (
        os.environ.get("GRAQLE_TRACE_SCHEMA_VERSION", CURRENT_SCHEMA_VERSION).strip()
        or CURRENT_SCHEMA_VERSION
    )


def _strict() -> bool:
    """``GRAQLE_TRACE_SCHEMA_STRICT`` — positive allowlist, anything else OFF."""
    return os.environ.get("GRAQLE_TRACE_SCHEMA_STRICT", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def read_trace(raw: dict[str, Any], *, strict: bool | None = None) -> GovernedTrace:
    """Read a serialized trace of ANY supported schema version.

    This is the ONLY correct way to deserialize a trace record read from disk.
    Constructing ``GovernedTrace.model_validate(raw)`` directly stamps a legacy
    record (which carries no ``schema_version`` on disk) with the current
    default, asserting a schema generation the record predates. That value
    reaches ``governance_metadata`` inside the frozen ``LEAF_HASH_FIELDS``
    allowlist, so a relabelled record hashes to a different Merkle leaf than it
    did when committed. This function preserves the original version instead.

    ``raw`` is never mutated.

    Args:
        raw: a trace dict parsed from JSONL.
        strict: override the ``GRAQLE_TRACE_SCHEMA_STRICT`` environment switch.

    Returns:
        A validated :class:`GovernedTrace` whose ``schema_version`` is the
        version the record was WRITTEN under, not the current one.

    Raises:
        ValueError: if the record fails validation, or if its version is
            unsupported while strict mode is on.
    """
    strict = _strict() if strict is None else strict
    version = classify_schema_version(raw)

    if version not in SUPPORTED_SCHEMA_VERSIONS:
        if strict:
            raise ValueError(
                f"trace schema_version {version!r} unsupported "
                f"(pinned {_pinned_version()!r}); STRICT is on"
            )
        known = set(GovernedTrace.model_fields)
        dropped = sorted(key for key in raw if key not in known)
        logger.warning(
            "trace schema_version %r is newer than pinned %r; best-effort read, "
            "dropped unknown keys %s",
            version,
            _pinned_version(),
            dropped,
        )
        raw = {key: value for key, value in raw.items() if key in known}

    data = dict(raw)
    if version in ("1", "2"):
        # Preserve the version the record was written under (v1 records carry
        # no field at all) and make the additive v3 field explicit.
        data.setdefault("schema_version", version)
        data.setdefault("assurance", None)

    try:
        return GovernedTrace.model_validate(data)
    except ValidationError as exc:
        raise ValueError(
            f"trace {raw.get('id')} failed v{version} validation: "
            f"{exc.errors(include_url=False)}"
        ) from exc


def get_policy_version_or_sentinel(raw: dict[str, Any] | None) -> str:
    """Read ``policy_version`` from a serialized trace, returning the sentinel
    if absent or ``None``. Used by audit-export, OPSF Use B validation, and
    KG-ingestion paths that need a non-null content-addressed identifier.
    """
    if raw is None:
        return LEGACY_POLICY_VERSION_SENTINEL
    value = raw.get("policy_version")
    if isinstance(value, str) and value:
        return value
    return LEGACY_POLICY_VERSION_SENTINEL


class GateVerdictRef(BaseModel):
    """Stable projection of a DAG-2026 gate verdict carried on a trace.

    This shape is DUPLICATED from :class:`graqle.assurance.verdict.GateVerdictRef`
    on purpose: ``graqle.governance`` must never import ``graqle.assurance``
    (CR-012 AC-21, enforced by the import-linter contract). ``outcome`` is a
    plain ``str`` here rather than the ``GateOutcome`` enum for the same reason.
    A parity test keeps the two definitions field-identical (CR-012 OQ-3).

    Carries hashes, codes and counts only -- never a confidence vector, never a
    weight, never a threshold (TS-1/TS-2).
    """

    model_config = ConfigDict(extra="forbid")

    verdict_schema_version: str
    outcome: str
    reason_codes: list[str]
    decisive_rule: str | None = None
    cap_applied: bool = False
    inputs_hash: str
    config_version: str
    evaluation_error_count: int = 0


class GovernedTrace(BaseModel):
    """A single governed execution trace record.

    Every MCP tool call produces one GovernedTrace. The trace is validated
    at creation time, persisted to the append-only trace store, and
    asynchronously ingested into the knowledge graph.

    Invariants:
        - id is UUID v4 (auto-generated)
        - timestamp is always UTC-aware
        - query is sanitized and non-empty
        - confidence is finite and in [0.0, 1.0]
        - override_reason is required iff human_override is True
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    tool_name: str
    query: str
    context_nodes: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    governance_decisions: list[GovernanceDecision] = Field(
        default_factory=list,
        repr=False,
        json_schema_extra={"internal": True},
    )
    clearance_level: ClearanceLevel = ClearanceLevel.INTERNAL
    outcome: Outcome
    confidence: float = Field(ge=0.0, le=1.0)
    cost_usd: float = Field(ge=0.0, default=0.0)
    latency_ms: float = Field(ge=0.0, default=0.0)
    human_override: bool = False
    override_reason: str | None = None
    error: str | None = None

    # -- cr-017: schema versioning + content-addressed policy binding -----
    #
    # ``schema_version`` marks the record's wire-format generation. Default
    # ``"2"`` for any newly-constructed trace; legacy JSONL records persisted
    # before cr-017 will be missing this field on disk and surface as
    # implicitly v1 to readers (see :func:`SchemaVersion.classify`).
    #
    # ``policy_version`` is a content-addressed SHA-256 binding to the active
    # baseline-doc at trace creation time (the ``baseline_id`` produced by
    # :class:`graqle.compliance.baseline_doc.BaselineDoc.baseline_id`). When
    # ``None``, the reader-side sentinel ``"legacy_pre_v058_unknown"`` is
    # returned by helpers that need a non-null value (see Research-Team
    # v0.58.x directive item #2; OPSF PCT comment 4 alignment).
    schema_version: str = "3"
    policy_version: str | None = None

    # -- CR-012 PR-012b: DAG-2026 assurance projection (ADDITIVE) -----------
    #
    # ``None`` on every trace until CR-015 writes a verdict, and excluded from
    # serialisation while it is None (see :meth:`to_internal_dict`) so an
    # on-disk v3 record with no verdict stays byte-compatible with a v0.83.0
    # reader under ``extra="forbid"``.
    #
    # TS-2: excluded from :meth:`to_public_dict` -- reason codes and hard-gate
    # results are internal.
    assurance: GateVerdictRef | None = Field(
        default=None,
        repr=False,
        json_schema_extra={"internal": True},
    )

    # -- Validators --------------------------------------------------------

    @field_validator("query")
    @classmethod
    def sanitize_query(cls, value: str) -> str:
        """Strip whitespace, remove non-printable chars, truncate, reject empty."""
        sanitized = _NON_PRINTABLE_RE.sub("", value).strip()
        sanitized = sanitized[:_QUERY_MAX_LENGTH]
        if not sanitized:
            raise ValueError("query must not be empty after sanitization")
        return sanitized

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        """Ensure timestamp is UTC-aware. Naive datetimes are assumed UTC."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("confidence")
    @classmethod
    def validate_confidence_finite(cls, value: float) -> float:
        """Reject NaN and Infinity values."""
        if math.isnan(value) or math.isinf(value):
            raise ValueError("confidence must be a finite number")
        return value

    @model_validator(mode="after")
    def validate_override(self) -> GovernedTrace:
        """Enforce override_reason consistency with human_override flag."""
        if self.human_override:
            if self.override_reason is None or not self.override_reason.strip():
                raise ValueError(
                    "override_reason is required when human_override is True"
                )
            self.override_reason = self.override_reason.strip()
        else:
            self.override_reason = None
        return self

    # -- Serialization -----------------------------------------------------

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize excluding TS-2 gated fields.

        ``assurance`` joins ``governance_decisions`` in the exclusion set
        (INV-TS-3): reason codes and hard-gate results are internal.
        """
        return self.model_dump(
            mode="json",
            exclude={"governance_decisions", "assurance"},
        )

    def to_internal_dict(self) -> dict[str, Any]:
        """Full serialization including all governance fields.

        CR-012 PR-012b: ``assurance`` is omitted entirely while it is ``None``
        (rather than emitted as ``null``) so that a v3 record written before
        CR-015 ships remains readable by a v0.83.0 reader, whose model is
        ``extra="forbid"`` and would otherwise reject the unknown key. Once a
        verdict is attached the key is present and only v3 readers accept it.

        The omission lives here rather than at the call site because this method
        IS the write path -- ``TraceStore.append`` serialises with it and is its
        only production caller -- and because every writer must agree on the
        on-disk shape. ``assurance is None`` and "key absent" are the same state
        on read: :func:`read_trace` restores it with ``setdefault``, so the
        round trip is lossless.
        """
        data = self.model_dump(mode="json")
        if self.assurance is None:
            data.pop("assurance", None)
        return data
