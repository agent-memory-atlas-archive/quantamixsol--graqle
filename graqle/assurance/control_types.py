"""DAG-2026 control typology (CR-013 §4.3-§4.4, §5.10, PR-013c).

Every control in the decision path carries exactly one :class:`ControlType`
that states what it may and may not do. Arbitration is the total order
HARD > CAP > THRESHOLD > COMPENSATORY > DESCRIPTIVE.

The registry is CLOSED (INV-TYPE-1): a control that is not listed here cannot
be classified. This module is PUBLIC content only (ids, enum values, sources);
the rationale for each assignment is private and stays in the private repo.

DRACE is classified DESCRIPTIVE and is not modified (INV-TYPE-2); its pillar
names are referenced here as strings, never imported.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.control_types
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015 later)
# dependencies: pydantic, types, enum
# constraints: stdlib + pydantic only; imports neither drace.py nor
#   core/governance.py (sources are strings, resolved by tests)
# -- /graqle:intelligence --
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict

__all__ = [
    "CONTROL_REGISTRY",
    "ControlDescriptor",
    "ControlType",
    "assert_typology_invariants",
    "classify",
]

_SINCE = "0.85.0"


class ControlType(str, Enum):
    DESCRIPTIVE = "descriptive"  # reported, never changes the outcome
    COMPENSATORY = "compensatory"  # enters a weighted sum
    THRESHOLD = "threshold"  # scalar compared to a symbol; can be offset upstream
    HARD = "hard"  # boolean, non-compensatory, evaluated first
    CAP = "cap"  # bounds an aggregate after a hard failure


class ControlDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    control_id: str
    control_type: ControlType
    #: ``<repo-relative file>:<dotted symbol>``.
    source: str
    may_change_outcome: bool
    may_be_offset: bool
    evaluated_before_aggregate: bool
    since_version: str


def _d(
    control_id: str,
    control_type: ControlType,
    source: str,
    *,
    outcome: bool,
    offset: bool,
    before: bool,
) -> ControlDescriptor:
    return ControlDescriptor(
        control_id=control_id,
        control_type=control_type,
        source=source,
        may_change_outcome=outcome,
        may_be_offset=offset,
        evaluated_before_aggregate=before,
        since_version=_SINCE,
    )


_GOV = "graqle/core/governance.py"
_DRACE = "graqle/intelligence/governance/drace.py"
_HG = "graqle/assurance/hard_gates.py"
_CV = "graqle/assurance/confidence_vector.py"
_T = ControlType

_ENTRIES: tuple[ControlDescriptor, ...] = (
    _d(
        "TS-BLOCK",
        _T.HARD,
        f"{_GOV}:_check_pattern_leakage",
        outcome=True,
        offset=False,
        before=True,
    ),
    _d(
        "GOV.review_threshold",
        _T.THRESHOLD,
        f"{_GOV}:GovernanceConfig.review_threshold",
        outcome=True,
        offset=True,
        before=False,
    ),
    _d(
        "GOV.block_threshold",
        _T.THRESHOLD,
        f"{_GOV}:GovernanceConfig.block_threshold",
        outcome=True,
        offset=True,
        before=False,
    ),
    _d(
        "GOV.secret_exposure_floor",
        _T.THRESHOLD,
        f"{_GOV}:_check_secret_exposure",
        outcome=True,
        offset=True,
        before=False,
    ),
    _d(
        "GOV.cumulative_radius_cap",
        _T.THRESHOLD,
        f"{_GOV}:GovernanceConfig.cumulative_radius_cap",
        outcome=True,
        offset=False,
        before=False,
    ),
    _d(
        "ART14.human_review_required_threshold",
        _T.THRESHOLD,
        "graqle/compliance/article_14_gate.py:DEFAULT_HUMAN_REVIEW_THRESHOLD",
        outcome=True,
        offset=True,
        before=False,
    ),
    _d(
        "DRACE.D",
        _T.COMPENSATORY,
        f"{_DRACE}:evaluate_dependency",
        outcome=False,
        offset=True,
        before=False,
    ),
    _d(
        "DRACE.R",
        _T.COMPENSATORY,
        f"{_DRACE}:evaluate_reasoning",
        outcome=False,
        offset=True,
        before=False,
    ),
    _d(
        "DRACE.A",
        _T.COMPENSATORY,
        f"{_DRACE}:evaluate_auditability",
        outcome=False,
        offset=True,
        before=False,
    ),
    _d(
        "DRACE.C",
        _T.COMPENSATORY,
        f"{_DRACE}:evaluate_constraint",
        outcome=False,
        offset=True,
        before=False,
    ),
    _d(
        "DRACE.E",
        _T.COMPENSATORY,
        f"{_DRACE}:evaluate_explainability",
        outcome=False,
        offset=True,
        before=False,
    ),
    _d(
        "DRACE.C.blocking_cap",
        _T.CAP,
        f"{_DRACE}:evaluate_constraint",
        outcome=False,
        offset=False,
        before=False,
    ),
    _d(
        "DRACE.total",
        _T.DESCRIPTIVE,
        f"{_DRACE}:DRACEScore.total",
        outcome=False,
        offset=False,
        before=False,
    ),
    _d(
        "DRACE.grade",
        _T.DESCRIPTIVE,
        f"{_DRACE}:DRACEScore.grade",
        outcome=False,
        offset=False,
        before=False,
    ),
    *(
        _d(
            f"CV.{dim}",
            _T.COMPENSATORY,
            f"{_CV}:ConfidenceVector.dims",
            outcome=True,
            offset=True,
            before=False,
        )
        for dim in (
            "source_reliability",
            "extraction_reliability",
            "corroboration",
            "temporal_validity",
            "context_fit",
            "reasoning_support",
            "operational_reliability",
        )
    ),
    _d(
        "CV.extraction_reliability.floor",
        _T.THRESHOLD,
        f"{_CV}:ConfidenceVector.dims",
        outcome=True,
        offset=False,
        before=False,
    ),
    _d(
        "CV.operational_reliability.activation_floor",
        _T.THRESHOLD,
        f"{_CV}:ConfidenceVector.dims",
        outcome=True,
        offset=False,
        before=False,
    ),
    _d(
        "CV.corroboration.min",
        _T.THRESHOLD,
        f"{_CV}:ConfidenceVector.dims",
        outcome=True,
        offset=False,
        before=False,
    ),
    _d("HG-01", _T.HARD, f"{_HG}:HG01MandatoryPolicy", outcome=True, offset=False, before=True),
    _d("HG-02", _T.HARD, f"{_HG}:HG02InvalidatedEvidence", outcome=True, offset=False, before=True),
    _d(
        "HG-03",
        _T.HARD,
        f"{_HG}:HG03ProvenanceForHighImpact",
        outcome=True,
        offset=False,
        before=True,
    ),
    _d("HG-04", _T.HARD, f"{_HG}:HG04ArgsBinding", outcome=True, offset=False, before=True),
    _d("HG-05", _T.HARD, f"{_HG}:HG05Poisoning", outcome=True, offset=False, before=True),
    _d("HG-06", _T.HARD, f"{_HG}:HG06ActorAuthorized", outcome=True, offset=False, before=True),
    _d(
        "HG-07",
        _T.HARD,
        f"{_HG}:HG07MaterialContradiction",
        outcome=True,
        offset=False,
        before=True,
    ),
    _d(
        "CAP",
        _T.CAP,
        "graqle/assurance/critical_cap.py:CriticalFailureCap",
        outcome=True,
        offset=False,
        before=False,
    ),
)


def _build(entries: tuple[ControlDescriptor, ...]) -> Mapping[str, ControlDescriptor]:
    registry: dict[str, ControlDescriptor] = {}
    for entry in entries:
        if entry.control_id in registry:
            raise ValueError(f"duplicate control id {entry.control_id!r}")
        registry[entry.control_id] = entry
    return MappingProxyType(registry)


#: Closed, read-only registry (INV-TYPE-1). Keys equal ``control_id``.
CONTROL_REGISTRY: Mapping[str, ControlDescriptor] = _build(_ENTRIES)


def classify(control_id: str) -> ControlDescriptor:
    """The descriptor of a registered control; ``KeyError`` for any other id."""
    try:
        return CONTROL_REGISTRY[control_id]
    except KeyError:
        raise KeyError(
            f"unregistered control {control_id!r}; add to "
            "control_types.CONTROL_REGISTRY (closed, INV-TYPE-1)"
        ) from None


def assert_typology_invariants(
    registry: Mapping[str, ControlDescriptor] = CONTROL_REGISTRY,
) -> None:
    """Raise ``AssertionError`` if any descriptor breaks the typology rules.

    Explicit ``raise`` rather than ``assert`` so the check survives ``python -O``.
    """
    for key, d in registry.items():
        problems: list[str] = []
        if key != d.control_id:
            problems.append("registry key differs from control_id")
        if d.control_type is ControlType.HARD and not (
            d.may_change_outcome and not d.may_be_offset and d.evaluated_before_aggregate
        ):
            problems.append("a hard control changes the outcome, cannot be offset, runs first")
        if d.control_type is ControlType.DESCRIPTIVE and d.may_change_outcome:
            problems.append("a descriptive control never changes the outcome")
        if d.control_type is ControlType.CAP and d.may_be_offset:
            problems.append("a cap cannot be offset")
        if d.control_type is ControlType.COMPENSATORY and not d.may_be_offset:
            problems.append("a compensatory control can be offset")
        if d.evaluated_before_aggregate and d.control_type is not ControlType.HARD:
            problems.append("only hard controls are evaluated before the aggregate")
        if problems:
            raise AssertionError(f"typology invariant broken for {key!r}: {'; '.join(problems)}")
