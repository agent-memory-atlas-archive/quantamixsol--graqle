"""Structural bounds for :class:`~graqle.assurance.provenance_event.ProvenanceEvent`.

CR-018 PR-018a. These are schema-shape limits (maximum identifier lengths and
list sizes), not tuning values. They live apart from ``provenance_event.py``
so that module stays free of numeric literals (CR-018 AC-14: an AST test
allows only 0, 1, 32 and 64 there).
"""

from __future__ import annotations

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

AGENT_ID_MAX = 200
MODEL_VERSION_MAX = 200
RULE_SET_VERSION_MAX = 64
POLICY_BUNDLE_VERSION_MAX = 128
CONFIG_VERSION_MAX = 64

EVIDENCE_REFS_MAX = 500
CLAIM_REFS_MAX = 500
INSTRUCTION_REFS_MAX = 100
POLICY_REFS_MAX = 100

HARD_GATE_RESULTS_MAX = 7
UNRESOLVED_CONFLICTS_MAX = 200
REASON_CODES_MAX = 50
EVALUATION_ERRORS_MAX = 50
