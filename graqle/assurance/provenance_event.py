"""ProvenanceEvent v0.1.0: the per-trajectory, hash-chained decision record.

CR-018 PR-018a (spec section 4.1, 5.1). This module defines the event schema,
the *committed form* ``E-`` of an event (``integrity`` removed, every present
redactable field replaced by a salted commitment) and ``canonical_hash``.

Rules (CR-018 AC-14, reviewer checklist 018a):

* Events carry references and closed codes only. No weight, threshold, cap or
  confidence-dimension value may appear as a key anywhere in ``canon(E-)``
  (:data:`FORBIDDEN_ANCHOR_KEYS`), checked on every hash computation.
* This module holds no numeric literal other than 0, 1, 32 and 64. Structural
  bounds come from :mod:`graqle.assurance._provenance_limits`; the clock-skew
  tolerance comes from ``GRAQLE_DAG_CLOCK_SKEW_TOLERANCE_S``.
* Only ``TamperEvidenceError`` is caught around ``canon``; it is re-raised as
  :class:`ProvenanceBuildError` and never coerced. A present redactable field
  with no salt fails closed.
* The canonicaliser is reused, not re-implemented.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.provenance_event
# risk: LOW (new module, no runtime consumers in PR-018a)
# dependencies: pydantic, hashlib, hmac, graqle.core.exceptions,
#   graqle.assurance._provenance_limits,
#   graqle.governance.tamper_evidence.canonicalize (lazy),
#   graqle.assurance.reason_codes (lazy)
# constraints: never imported by graqle.governance.*; no latch import
#   (GENESIS_HASH is asserted equal to the latch value by test, not imported)
# -- /graqle:intelligence --
import hashlib
import hmac
import os
import re
import secrets
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from graqle.assurance import _provenance_limits as _lim
from graqle.core.exceptions import GraqleError

__all__ = [
    "SCHEMA_VERSION",
    "GENESIS_HASH",
    "SKEW_ENV_VAR",
    "REDACTABLE_FIELDS",
    "FORBIDDEN_ANCHOR_KEYS",
    "ProvenanceBuildError",
    "EventType",
    "IdentityAssurance",
    "ActorType",
    "Actor",
    "Activity",
    "Inputs",
    "HardGateResult",
    "Assessment",
    "Ordering",
    "Signature",
    "AnchorRef",
    "Integrity",
    "ProvenanceEvent",
    "committed_form",
    "canonical_hash",
    "event_canonical_hash",
    "generate_salts",
    "verify_disclosure",
]

SCHEMA_VERSION = "0.1.0"
# Equals compliance.eu_ai_act_latch._GENESIS_HASH; asserted equal by test, NOT
# imported (no latch dependency).
GENESIS_HASH = "0" * 64
SKEW_ENV_VAR = "GRAQLE_DAG_CLOCK_SKEW_TOLERANCE_S"

_HEX64 = r"^[0-9a-f]{64}$"
_ULID_BODY = r"[0-9A-HJKMNP-TV-Z]{26}"  # Crockford base32, 26 chars
_COMMIT_KEY = "__commit"


class ProvenanceBuildError(GraqleError):
    """An event cannot be built, committed or hashed. Always fail closed."""


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------


def _parse(ts: str) -> datetime:
    """Parse an RFC 3339 UTC timestamp that ends with ``Z``."""
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("timestamp must be RFC 3339 UTC ending with 'Z'")
    parsed = datetime.fromisoformat(ts[:-1] + "+00:00")
    return parsed.astimezone(timezone.utc)


def _skew_tolerance() -> timedelta:
    """Clock-skew tolerance from the environment.

    Unset means zero tolerance (strictest). A set but malformed or non-positive
    value raises, so a typo can never silently loosen the ordering check.
    """
    raw = os.environ.get(SKEW_ENV_VAR)
    if raw is None:
        return timedelta(0)
    try:
        seconds = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{SKEW_ENV_VAR} must be an integer number of seconds") from exc
    if seconds < 1:
        raise ValueError(f"{SKEW_ENV_VAR} must be at least 1 when set")
    return timedelta(seconds=seconds)


# --------------------------------------------------------------------------
# Enums and sub-models
# --------------------------------------------------------------------------


class EventType(str, Enum):
    DECISION_GATE_EVALUATED = "decision_gate_evaluated"
    EVIDENCE_ADMITTED = "evidence_admitted"
    CLAIM_EXTRACTED = "claim_extracted"
    CONTRADICTION_RECORDED = "contradiction_recorded"
    RESOLUTION_APPLIED = "resolution_applied"
    INVALIDATION_PROPAGATED = "invalidation_propagated"
    ACTION_APPROVED = "action_approved"
    ACTION_EXECUTED = "action_executed"
    REPLAN_REQUESTED = "replan_requested"
    ESCALATION_OPENED = "escalation_opened"
    # additions beyond charter Appendix B (the charter list is "incl."):
    KEY_ROTATED = "key_rotated"  # rotation audit event (blueprint B3)
    CAPTURE_RECONCILED = "capture_reconciled"  # reconciliation-job result


class IdentityAssurance(str, Enum):
    IAL1 = "IAL1"  # self-asserted (unsigned runtime, or shared/unregistered key)
    IAL2 = "IAL2"  # registered ed25519 kid under Ed25519KeyManifest, key on disk
    IAL3 = "IAL3"  # kid backed by an HSM/KMS signing callback (reserved; OQ-1)


class ActorType(str, Enum):
    SOFTWARE_AGENT = "software_agent"
    HUMAN = "human"
    SYSTEM = "system"


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=_lim.AGENT_ID_MAX)  # REDACTABLE
    type: ActorType
    identity_assurance: IdentityAssurance
    kid: str | None = None  # kid the runtime claims to sign with


class Activity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_id: str = Field(pattern=r"^dec_" + _ULID_BODY + r"$")
    trajectory_id: str = Field(pattern=r"^trj_" + _ULID_BODY + r"$")
    checkpoint: int = Field(ge=0)
    attempt: int = Field(ge=0, default=0)  # REPLAN attempt counter (linear chain)
    parent_trajectory_ref: str | None = None  # set only when ESCALATE spawns a trajectory
    model_version: str = Field(min_length=1, max_length=_lim.MODEL_VERSION_MAX)
    rule_set_version: str = Field(min_length=1, max_length=_lim.RULE_SET_VERSION_MAX)
    policy_bundle_version: str = Field(min_length=1, max_length=_lim.POLICY_BUNDLE_VERSION_MAX)
    config_version: str = Field(min_length=1, max_length=_lim.CONFIG_VERSION_MAX)


class Inputs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_refs: list[str] = Field(
        default_factory=list, max_length=_lim.EVIDENCE_REFS_MAX
    )  # REDACTABLE
    claim_refs: list[str] = Field(
        default_factory=list, max_length=_lim.CLAIM_REFS_MAX
    )  # REDACTABLE
    instruction_refs: list[str] = Field(
        default_factory=list, max_length=_lim.INSTRUCTION_REFS_MAX
    )  # REDACTABLE
    policy_refs: list[str] = Field(
        default_factory=list, max_length=_lim.POLICY_REFS_MAX
    )  # never redacted: policies are governed artefacts
    candidate_action_hash: str | None = Field(default=None, pattern=_HEX64)
    candidate_action_hash_algo: str | None = None  # algorithm id stored alongside (M1)


class HardGateResult(BaseModel):
    """Mirrors the CR-013 shape: booleans and codes, never thresholds."""

    model_config = ConfigDict(extra="forbid")
    gate_id: str = Field(pattern=r"^HG-0[1-7]$")
    passed: bool
    reason_code: str | None = Field(default=None, pattern=r"^DAG-(HG0[1-7]|CV|TR|PV)-[A-Z0-9_-]+$")
    rule_version: str
    inputs_hash: str = Field(pattern=_HEX64)
    probabilistic: bool = False


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # sha256(canon(ConfidenceVector record)) -- VALUES NEVER INLINE
    confidence_vector_ref: str | None = Field(default=None, pattern=_HEX64)
    confidence_vector_schema_version: str | None = None
    projection_id: str | None = None  # policy projection id, not the weights
    trajectory_reliability_ref: str | None = Field(default=None, pattern=_HEX64)
    hard_gate_results: list[HardGateResult] = Field(
        default_factory=list, max_length=_lim.HARD_GATE_RESULTS_MAX
    )
    unresolved_conflicts: list[str] = Field(
        default_factory=list, max_length=_lim.UNRESOLVED_CONFLICTS_MAX
    )
    # GateOutcome value (CR-012); None for non-decision events
    outcome: Literal["EXECUTE", "REPLAN", "HOLD", "REJECT", "ESCALATE"] | None = None
    reason_codes: list[str] = Field(default_factory=list, max_length=_lim.REASON_CODES_MAX)
    evaluation_errors: list[str] = Field(
        default_factory=list, max_length=_lim.EVALUATION_ERRORS_MAX
    )

    @field_validator("reason_codes")
    @classmethod
    def _closed_registry(cls, v: list[str]) -> list[str]:
        from graqle.assurance.reason_codes import REGISTRY  # CR-012 closed registry

        unknown = [c for c in v if c not in REGISTRY]
        if unknown:
            raise ValueError(f"unknown reason codes {unknown}")
        return v


class Ordering(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sequence_number: int = Field(ge=0)
    previous_event_hash: str = Field(pattern=_HEX64)


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alg: Literal["ed25519"] = "ed25519"
    kid: str
    key_version: int = Field(ge=1)
    sig: str = Field(pattern=r"^[0-9a-f]{128}$")
    signed_at: str  # RFC 3339 UTC with "Z"

    @field_validator("signed_at")
    @classmethod
    def _signed_at_format(cls, v: str) -> str:
        _parse(v)
        return v


class AnchorRef(BaseModel):
    """Reuse pointer into the Committer's ``CommitRecord`` (no new anchoring)."""

    model_config = ConfigDict(extra="forbid")
    batch_id: str
    merkle_root_hex: str = Field(pattern=_HEX64)
    leaf_hash: str = Field(pattern=_HEX64)
    rekor_log_index: int | None = None
    rekor_log_id: str | None = None
    commit_status: Literal["pending", "committed", "anchored", "replay_queued", "failed"]


class Integrity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    canonicalization: Literal["JCS-RFC8785"] = "JCS-RFC8785"
    hash_alg: Literal["sha256"] = "sha256"
    canonical_hash: str = Field(pattern=_HEX64)
    # path -> commitment hex, only for redactable fields present
    field_commitments: dict[str, str] = Field(default_factory=dict)
    signature: Signature
    signature_ref: str  # "sig:" + sha256(canon(signature))[:32]  (join key)
    anchor_ref: AnchorRef | None = None  # None until the Committer reports; OUTSIDE canonical_hash


class ProvenanceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    event_id: str = Field(pattern=r"^evt_" + _ULID_BODY + r"$")
    event_type: EventType
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    occurred_at: str  # asserted by the RUNTIME (gate): instant the decision was taken
    captured_at: str  # asserted by the RECORDER: instant the event was built
    actor: Actor
    activity: Activity
    inputs: Inputs
    assessment: Assessment
    ordering: Ordering
    integrity: Integrity

    @model_validator(mode="after")
    def _time_order(self) -> ProvenanceEvent:
        if _parse(self.captured_at) < _parse(self.occurred_at) - _skew_tolerance():
            raise ValueError("captured_at precedes occurred_at beyond clock_skew_tolerance_s")
        return self


REDACTABLE_FIELDS: tuple[str, ...] = (
    "actor.agent_id",
    "inputs.evidence_refs",
    "inputs.claim_refs",
    "inputs.instruction_refs",
)
# NOT redactable by design: event_id, event_type, activity.*, inputs.policy_refs,
# inputs.candidate_action_hash*, assessment.* (references, closed codes and
# booleans), ordering.*, integrity.* -- no personal data, load-bearing for
# verification.

FORBIDDEN_ANCHOR_KEYS: frozenset[str] = frozenset(
    {
        "weight",
        "weights",
        "threshold",
        "thresholds",
        "cap",
        "cap_value",
        "calibrator_params",
        "temperature",
        "half_life",
        "retry_budget",
        "confidence_vector",
        "source",
        "extraction",
        "corroboration",
        "temporal_validity",
        "context_fit",
        "reasoning_support",
        "operational_reliability",
    }
)  # AC-14: none may appear as a key anywhere in canon(E-)


# --------------------------------------------------------------------------
# Committed form and canonical hash (spec 5.1)
# --------------------------------------------------------------------------


def _canon(obj: Any) -> bytes:
    """RFC 8785 bytes via the shared canonicaliser; never coerces."""
    from graqle.governance.tamper_evidence.canonicalize import canon
    from graqle.governance.tamper_evidence.errors import TamperEvidenceError

    try:
        return canon(obj)
    except TamperEvidenceError as exc:
        raise ProvenanceBuildError(f"non-canonical event: {exc}") from exc


def _walk(event_dict: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    """Return ``(parent, key)`` for a dotted path; structural errors fail closed."""
    *parents, key = path.split(".")
    node: Any = event_dict
    for part in parents:
        if not isinstance(node, dict) or part not in node:
            raise ProvenanceBuildError(f"structural error: {path} has no parent {part!r}")
        node = node[part]
    if not isinstance(node, dict):
        raise ProvenanceBuildError(f"structural error: parent of {path} is not an object")
    return node, key


def _present(event_dict: dict[str, Any], path: str) -> bool:
    parent, key = _walk(event_dict, path)
    return key in parent


def _commit(value: Any, salt: bytes) -> str:
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise ProvenanceBuildError("salt must be exactly 32 bytes")
    return hashlib.sha256(salt + _canon(value)).hexdigest()


def committed_form(event_dict: dict[str, Any], salts: dict[str, bytes]) -> dict[str, Any]:
    """Return ``E-``: ``integrity`` removed, present redactable fields committed.

    ``event_dict`` must already be JSON-native (``model_dump(mode="json")``).
    A present redactable field with no salt raises; an absent one is skipped.
    """
    e = deepcopy(event_dict)
    e.pop("integrity", None)
    for path in REDACTABLE_FIELDS:
        parent, key = _walk(e, path)
        if key not in parent:
            continue
        salt = salts.get(path)
        if salt is None:
            raise ProvenanceBuildError(f"missing salt for present redactable field {path}")
        parent[key] = {_COMMIT_KEY: _commit(parent[key], salt)}
    return e


def _assert_no_forbidden_keys(node: Any) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in FORBIDDEN_ANCHOR_KEYS:
                raise ProvenanceBuildError(f"forbidden key in anchored payload: {key!r}")
            _assert_no_forbidden_keys(value)
    elif isinstance(node, list):
        for item in node:
            _assert_no_forbidden_keys(item)


def canonical_hash(
    event_dict: dict[str, Any], salts: dict[str, bytes]
) -> tuple[str, dict[str, str]]:
    """``(hex(H(canon(E-))), {path: commitment})`` for a JSON-native event dict."""
    cf = committed_form(event_dict, salts)
    payload = _canon(cf)  # raises ProvenanceBuildError on NaN, -0.0, non-native, depth
    _assert_no_forbidden_keys(cf)  # AC-14 runtime guard
    commits: dict[str, str] = {}
    for path in REDACTABLE_FIELDS:
        parent, key = _walk(cf, path)
        if key in parent:
            commits[path] = parent[key][_COMMIT_KEY]
    return hashlib.sha256(payload).hexdigest(), commits


def event_canonical_hash(
    event: ProvenanceEvent, salts: dict[str, bytes]
) -> tuple[str, dict[str, str]]:
    """:func:`canonical_hash` for a validated :class:`ProvenanceEvent`."""
    return canonical_hash(event.model_dump(mode="json"), salts)


def generate_salts(event_dict: dict[str, Any]) -> dict[str, bytes]:
    """One fresh 32-byte CSPRNG salt per redactable field present in the event."""
    return {
        path: secrets.token_bytes(32)
        for path in REDACTABLE_FIELDS
        if _present(event_dict, path)
    }


def verify_disclosure(commitment_hex: str, value: Any, salt: bytes) -> bool:
    """Open a commitment: recompute and compare in constant time.

    A malformed salt or a non-canonical value is a failed disclosure (False),
    never an exception that a caller could mistake for success.
    """
    try:
        recomputed = _commit(value, salt)
    except ProvenanceBuildError:
        return False
    # A commitment that is not 64 lowercase hex characters can never match.
    if not isinstance(commitment_hex, str) or not re.fullmatch(_HEX64, commitment_hex):
        return False
    return hmac.compare_digest(recomputed.encode("ascii"), commitment_hex.encode("ascii"))
