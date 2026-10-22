"""Structural bounds for :class:`~graqle.assurance.provenance_event.ProvenanceEvent`.

CR-018 PR-018a. These are schema-shape limits (maximum identifier lengths and
list sizes), not tuning values. They live apart from ``provenance_event.py``
so that module stays free of numeric literals (CR-018 AC-14: an AST test
allows only 0, 1, 32 and 64 there).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# -- graqle:intelligence --
# module: graqle.assurance._provenance_limits
# risk: LOW (new module, one consumer: graqle.assurance.provenance_event)
# dependencies: none
# constraints: plain constants only; never imported by graqle.governance.*
# -- /graqle:intelligence --

__all__ = [
    "AGENT_ID_MAX",
    "MODEL_VERSION_MAX",
    "RULE_SET_VERSION_MAX",
    "POLICY_BUNDLE_VERSION_MAX",
    "CONFIG_VERSION_MAX",
    "EVIDENCE_REFS_MAX",
    "CLAIM_REFS_MAX",
    "INSTRUCTION_REFS_MAX",
    "POLICY_REFS_MAX",
    "HARD_GATE_RESULTS_MAX",
    "UNRESOLVED_CONFLICTS_MAX",
    "REASON_CODES_MAX",
    "EVALUATION_ERRORS_MAX",
]



class _Limits(BaseModel):
    """Typed home of the structural bounds."""

    model_config = ConfigDict(frozen=True)

    agent_id: int = Field(default=200)
    model_version: int = Field(default=200)
    rule_set_version: int = Field(default=64)
    policy_bundle_version: int = Field(default=128)
    config_version: int = Field(default=64)

    evidence_refs: int = Field(default=500)
    claim_refs: int = Field(default=500)
    instruction_refs: int = Field(default=100)
    policy_refs: int = Field(default=100)

    hard_gate_results: int = Field(default=7)
    unresolved_conflicts: int = Field(default=200)
    reason_codes: int = Field(default=50)
    evaluation_errors: int = Field(default=50)


_LIMITS = _Limits()

AGENT_ID_MAX = _LIMITS.agent_id
MODEL_VERSION_MAX = _LIMITS.model_version
RULE_SET_VERSION_MAX = _LIMITS.rule_set_version
POLICY_BUNDLE_VERSION_MAX = _LIMITS.policy_bundle_version
CONFIG_VERSION_MAX = _LIMITS.config_version

EVIDENCE_REFS_MAX = _LIMITS.evidence_refs
CLAIM_REFS_MAX = _LIMITS.claim_refs
INSTRUCTION_REFS_MAX = _LIMITS.instruction_refs
POLICY_REFS_MAX = _LIMITS.policy_refs

HARD_GATE_RESULTS_MAX = _LIMITS.hard_gate_results
UNRESOLVED_CONFLICTS_MAX = _LIMITS.unresolved_conflicts
REASON_CODES_MAX = _LIMITS.reason_codes
EVALUATION_ERRORS_MAX = _LIMITS.evaluation_errors
