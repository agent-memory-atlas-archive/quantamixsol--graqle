"""DAG-2026 gate verdict schema (CR-012 §4.3).

What a Decision Assurance Gate evaluation produces. Every model here is
``extra="forbid"``: an unknown field is a schema error, never silently carried.

Fail-closed invariants (enforced by validators, not by convention):
  * EXECUTE is impossible when any hard gate failed.
  * EXECUTE is impossible when ``evaluation_errors`` is non-empty.
  * A :class:`HardGateResultRef` carrying an ``error`` must not be ``passed``.

``confidence_vector`` and ``trajectory_reliability`` stay optional until CR-014
and CR-015 populate them.
"""

# -- graqle:intelligence --
# module: graqle.assurance.verdict
# risk: LOW (impact radius: 0 modules -- new file, no existing callers)
# dependencies: pydantic, graqle.assurance.outcomes, graqle.assurance.reason_codes
# constraints: never imported by graqle.governance.*
# -- /graqle:intelligence --

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.reason_codes import validate as _validate_codes

__all__ = [
    "VERDICT_SCHEMA_VERSION",
    "DeterminismRecord",
    "GateVerdict",
    "GateVerdictRef",
    "HardGateResultRef",
]

#: Wire-format version of the verdict shape itself (independent of the trace
#: schema version).
VERDICT_SCHEMA_VERSION = "1"


class DeterminismRecord(BaseModel):
    """Why this verdict is reproducible.

    ``inputs_hash`` is ``sha256:<hex>`` over the RFC 8785 canonical bytes of the
    evaluation inputs (``graqle.governance.tamper_evidence.canonicalize.canon``).
    ``config_version`` is the salt-keyed HMAC commitment over ``DagSettings``
    (CR-012 §5.1, ruling N2) -- a commitment, never the values themselves.
    """

    model_config = ConfigDict(extra="forbid")

    inputs_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    rule_id: str
    rule_version: str
    config_version: str
    decisive_conditions: list[str] = Field(default_factory=list)
    probabilistic: bool = False
    variance: float | None = None

    @model_validator(mode="after")
    def _prob_needs_variance(self) -> DeterminismRecord:
        if self.probabilistic and self.variance is None:
            raise ValueError("probabilistic signals must report variance")
        return self


class HardGateResultRef(BaseModel):
    """Compact projection of a CR-013 HardGateResult carried in the verdict."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_version: str
    passed: bool
    decisive_conditions: list[str] = Field(default_factory=list)
    inputs_hash: str
    evaluated_at: datetime
    error: str | None = None

    @model_validator(mode="after")
    def _error_implies_fail(self) -> HardGateResultRef:
        if self.error is not None and self.passed:
            raise ValueError("a hard gate with error must not pass")
        return self


class GateVerdict(BaseModel):
    """The full verdict. Stored by CR-018; the trace keeps :class:`GateVerdictRef`."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = VERDICT_SCHEMA_VERSION
    outcome: GateOutcome
    reason_codes: list[str] = Field(default_factory=list)
    hard_gate_results: list[HardGateResultRef] = Field(default_factory=list)
    confidence_vector: dict[str, float] | None = None
    trajectory_reliability: float | None = Field(default=None, ge=0.0, le=1.0)
    residual_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    implicated_nodes: list[str] = Field(default_factory=list)
    decisive_rule: str | None = None
    evaluation_errors: list[str] = Field(default_factory=list)
    determinism_record: DeterminismRecord
    cap_applied: bool = False
    evaluated_at: datetime

    @field_validator("reason_codes")
    @classmethod
    def _codes_registered(cls, value: list[str]) -> list[str]:
        return _validate_codes(value)

    @model_validator(mode="after")
    def _consistency(self) -> GateVerdict:
        if self.outcome == GateOutcome.EXECUTE:
            if any(not h.passed for h in self.hard_gate_results):
                raise ValueError("EXECUTE is impossible with a failed hard gate")
            if self.evaluation_errors:
                raise ValueError(
                    "EXECUTE is impossible with evaluation_errors (fail-closed)"
                )
        if self.confidence_vector is not None:
            for key, score in self.confidence_vector.items():
                if not 0.0 <= score <= 1.0:
                    raise ValueError(f"confidence_vector[{key}] out of range")
        return self


class GateVerdictRef(BaseModel):
    """Stable projection of a verdict for embedding in a governed trace.

    A byte-identical copy of this shape lives in
    :mod:`graqle.governance.trace_schema` so that ``graqle.governance`` never
    imports ``graqle.assurance`` (CR-012 AC-21). ``outcome`` is a plain ``str``
    on purpose -- the trace side must not import the enum. A parity test keeps
    the two definitions field-identical (CR-012 OQ-3).

    Carries hashes and codes only: never a confidence vector, never a weight.
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
