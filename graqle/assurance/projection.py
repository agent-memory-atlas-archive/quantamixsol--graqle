"""Policy-specific projection of a ConfidenceVector to a decision score.

The projection is defined only after the hard gates have passed. When any gate
failed, ``project`` returns a bottom result (no score, not admitted) without
calling any strategy. Otherwise::

    decision_score = min(cap, S(calibrated vector) - penalties)

with four pluggable strategies that all read the same calibrated vector and the
same penalties. Every degraded input fails closed: a missing or errored
mandatory dimension, a strategy that cannot run, or a non-finite score all
produce a non-admission, never a default.

No weight, threshold, knot, floor or penalty value lives in this module; they
are read from configuration. ``policy_threshold_ref`` is a symbol, not a value.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.projection
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.confidence_vector, graqle.assurance._hashing
# constraints: pure strategies; hard gates first; fail closed; no tuned values
# -- /graqle:intelligence --
import json
import math
from collections.abc import Iterable, Mapping
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from graqle.assurance._hashing import inputs_hash as _inputs_hash
from graqle.assurance.confidence_vector import (
    Availability,
    ConfidenceVector,
    DimensionName,
    EntityClass,
)
from graqle.assurance.reason_codes import validate as _validate_codes
from graqle.config.exceptions import ConfigurationError

if TYPE_CHECKING:  # pragma: no cover
    from graqle.assurance.cv_settings import ConfidenceVectorSettings

__all__ = [
    "CalibratedTreeProjection",
    "CapLike",
    "HardGateSummary",
    "LinearProjection",
    "MonotonicProjection",
    "Penalties",
    "PenaltyInputs",
    "ProjectionResult",
    "ProjectionStrategy",
    "ProjectionStrategyName",
    "RuleOnlyProjection",
    "build_strategy",
    "project",
]

RULE_VERSION_PROJ = "1"

CODE_SKIPPED = "DAG-CV-004-PROJECTION_SKIPPED_HG_FAIL"
CODE_BELOW = "DAG-CV-005-BELOW_POLICY_THRESHOLD"
CODE_CONFIG_INVALID = "DAG-CV-008-CONFIG_INVALID"
CODE_CAP = "DAG-CV-010-CRITICAL_CAP_APPLIED"
_CODE_NA = "DAG-CV-001-DIM_NOT_AVAILABLE"
_CODE_STALE = "DAG-CV-002-CALIBRATION_STALE"
_CODE_DIVERGED = "DAG-CV-003-DIVERGENCE_EXCEEDED"
_CODE_ERROR = "DAG-CV-007-PROVIDER_ERROR"

_NO_RESULTS_GATE = "hard_gate_results_absent"


class ProjectionStrategyName(str, Enum):
    LINEAR = "linear"
    MONOTONIC = "monotonic"
    CALIBRATED_TREE = "calibrated_tree"
    RULE_ONLY = "rule_only"


def _positive_finite(value: float) -> bool:
    return isinstance(value, (int, float)) and math.isfinite(value) and value > 0


class Penalties(BaseModel):
    """Penalty coefficients. Values are private; zero or non-finite is rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contradiction: float
    staleness: float
    dependency: float

    @model_validator(mode="after")
    def _non_zero(self) -> Penalties:
        for name, value in self.as_items():
            if not _positive_finite(value):
                raise ConfigurationError(f"DAG-CV config {name} must be a positive number")
        return self

    def as_items(self) -> list[tuple[str, float]]:
        return [
            ("penalty_contradiction", self.contradiction),
            ("penalty_staleness", self.staleness),
            ("penalty_dependency", self.dependency),
        ]


class PenaltyInputs(BaseModel):
    """Measured penalty drivers for one candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    unresolved_contradictions: int = Field(ge=0)
    staleness: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    dependency_penalty: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)


class HardGateSummary(BaseModel):
    """Aggregate of the hard-gate results for one candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    all_passed: bool
    failed_gate_ids: tuple[str, ...] = ()

    @classmethod
    def from_results(cls, results: Iterable[Any]) -> HardGateSummary:
        """Build from hard-gate results. An empty set is NOT a pass (fail closed)."""
        items = list(results)
        if not items:
            return cls(all_passed=False, failed_gate_ids=(_NO_RESULTS_GATE,))
        failed = tuple(r.rule_id for r in items if not r.passed)
        return cls(all_passed=not failed, failed_gate_ids=failed)

    @model_validator(mode="after")
    def _consistent(self) -> HardGateSummary:
        if self.all_passed and self.failed_gate_ids:
            raise ValueError("a passing summary names no failed gate")
        if not self.all_passed and not self.failed_gate_ids:
            raise ValueError("a failing summary names at least one gate")
        return self


class CapLike(Protocol):
    """The part of the critical-failure cap result that projection reads."""

    cap_applied: bool
    output_value: float


class ProjectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    strategy: ProjectionStrategyName
    decision_score: float | None  # None means bottom: gates failed or mandatory dim missing
    admitted: bool
    policy_threshold_ref: str  # symbolic name, never the value
    penalty_total: float | None
    capped_by_critical_cap: bool
    reason_codes: tuple[str, ...]
    inputs_hash: str
    rule_id: str = "DAG-CV-PROJ"
    rule_version: str
    config_version: str
    decisive_conditions: tuple[str, ...]

    @field_validator("reason_codes")
    @classmethod
    def _registered(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_codes(list(value)))

    @model_validator(mode="after")
    def _consistent(self) -> ProjectionResult:
        if self.decision_score is None and self.admitted:
            raise ValueError("a bottom result is never admitted")
        if self.decision_score is not None and not math.isfinite(self.decision_score):
            raise ValueError("decision score must be finite")
        return self


class ProjectionStrategy(Protocol):
    name: ProjectionStrategyName

    def score(
        self,
        x: Mapping[DimensionName, float],
        s: ConfidenceVectorSettings,
        entity_class: EntityClass,
    ) -> float: ...


def _unit(value: float) -> float:
    return min(max(value, 0.0), 1.0)


class LinearProjection:
    """Weighted sum. Absent dimensions are dropped; weights are NOT renormalised."""

    name = ProjectionStrategyName.LINEAR

    def score(
        self,
        x: Mapping[DimensionName, float],
        s: ConfidenceVectorSettings,
        entity_class: EntityClass,
    ) -> float:
        return sum(s.weights[d] * v for d, v in x.items())


def _piecewise(value: float, knots: tuple[tuple[float, float], ...]) -> float:
    if value <= knots[0][0]:
        return knots[0][1]
    for (x0, y0), (x1, y1) in zip(knots, knots[1:]):
        if value <= x1:
            return y0 + (y1 - y0) * (value - x0) / (x1 - x0)
    return knots[-1][1]


class MonotonicProjection:
    """Weighted sum of per-dimension monotone piecewise-linear maps (private knots)."""

    name = ProjectionStrategyName.MONOTONIC

    def score(
        self,
        x: Mapping[DimensionName, float],
        s: ConfidenceVectorSettings,
        entity_class: EntityClass,
    ) -> float:
        total = 0.0
        for d, v in x.items():
            knots = s.monotonic_knots.get(d)
            if knots is None:
                raise ConfigurationError(f"no monotone knots configured for {d.value}")
            total += s.weights[d] * _piecewise(v, knots)
        return total


class RuleOnlyProjection:
    """1 when every mandatory dimension meets its floor, else 0. No weights."""

    name = ProjectionStrategyName.RULE_ONLY

    def score(
        self,
        x: Mapping[DimensionName, float],
        s: ConfidenceVectorSettings,
        entity_class: EntityClass,
    ) -> float:
        for d in s.mandatory_dims[entity_class]:
            floor = s.rule_floors.get(d)
            if floor is None:
                raise ConfigurationError(f"no rule floor configured for {d.value}")
            if d not in x or x[d] < floor:
                return 0.0
        return 1.0


class CalibratedTreeProjection:
    """Depth-bounded decision tree loaded from a private JSON file.

    Node forms: ``{"leaf": value}`` or ``{"feature": dim, "threshold": t,
    "left": node, "right": node}``; the left branch is taken when the feature is
    strictly below the threshold. Leaf values are expected to be calibrated
    offline. A missing feature makes the tree return 0 (fail closed).
    """

    name = ProjectionStrategyName.CALIBRATED_TREE

    def __init__(self, tree_path: Path, max_depth: int) -> None:
        try:
            raw = json.loads(Path(tree_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigurationError(
                f"projection tree could not be loaded ({type(exc).__name__})"
            ) from None
        self._tree = raw
        self._check(raw, max_depth, 0)

    @classmethod
    def _check(cls, node: Any, max_depth: int, depth: int) -> None:
        if depth > max_depth or not isinstance(node, dict):
            raise ConfigurationError("projection tree exceeds its depth bound or is malformed")
        if set(node) == {"leaf"}:
            leaf = node["leaf"]
            if not isinstance(leaf, (int, float)) or isinstance(leaf, bool):
                raise ConfigurationError("projection tree leaf must be a number")
            if not math.isfinite(leaf) or leaf < 0.0 or leaf > 1.0:
                raise ConfigurationError("projection tree leaf must be inside the unit interval")
            return
        if set(node) != {"feature", "threshold", "left", "right"}:
            raise ConfigurationError("projection tree node is malformed")
        try:
            DimensionName(node["feature"])
        except ValueError:
            raise ConfigurationError("projection tree names an unknown dimension") from None
        thr = node["threshold"]
        if not isinstance(thr, (int, float)) or isinstance(thr, bool) or not math.isfinite(thr):
            raise ConfigurationError("projection tree threshold must be a finite number")
        cls._check(node["left"], max_depth, depth + 1)
        cls._check(node["right"], max_depth, depth + 1)

    def score(
        self,
        x: Mapping[DimensionName, float],
        s: ConfidenceVectorSettings,
        entity_class: EntityClass,
    ) -> float:
        node = self._tree
        while "leaf" not in node:
            feature = DimensionName(node["feature"])
            if feature not in x:
                return 0.0
            node = node["left"] if x[feature] < node["threshold"] else node["right"]
        return float(node["leaf"])


def build_strategy(s: ConfidenceVectorSettings) -> ProjectionStrategy:
    """Instantiate the strategy named in the settings; fails closed if it cannot run."""
    name = s.projection_strategy
    if name is ProjectionStrategyName.LINEAR:
        return LinearProjection()
    if name is ProjectionStrategyName.MONOTONIC:
        return MonotonicProjection()
    if name is ProjectionStrategyName.RULE_ONLY:
        return RuleOnlyProjection()
    if s.tree_path is None or s.tree_max_depth is None:
        raise ConfigurationError("calibrated_tree needs a tree path and a depth bound")
    return CalibratedTreeProjection(s.tree_path, s.tree_max_depth)


def _theta_ref(entity_class: EntityClass) -> str:
    return f"θ_POLICY[{entity_class.value}]"


def _not_admitted(
    cv: ConfidenceVector,
    strategy: ProjectionStrategy,
    s: ConfidenceVectorSettings,
    codes: Iterable[str],
    decisive: tuple[str, ...],
    *,
    digest: str | None = None,
) -> ProjectionResult:
    return ProjectionResult(
        strategy=strategy.name,
        decision_score=None,
        admitted=False,
        policy_threshold_ref=_theta_ref(cv.entity_class),
        penalty_total=None,
        capped_by_critical_cap=False,
        reason_codes=tuple(dict.fromkeys(codes)),
        inputs_hash=digest or cv.inputs_hash,
        rule_version=RULE_VERSION_PROJ,
        config_version=s.config_version,
        decisive_conditions=decisive,
    )


def project(
    cv: ConfidenceVector,
    hg: HardGateSummary,
    cap: CapLike,
    s: ConfidenceVectorSettings,
    strategy: ProjectionStrategy,
    penalties_in: PenaltyInputs,
) -> ProjectionResult:
    """Project ``cv`` to a decision score. Defined only after the hard gates pass."""
    if not hg.all_passed:
        return _not_admitted(cv, strategy, s, (CODE_SKIPPED,), tuple(hg.failed_gate_ids))

    mandatory = s.mandatory_dims[cv.entity_class]
    x: dict[DimensionName, float] = {}
    codes: list[str] = []
    for d, dim in cv.dims.items():
        if dim.availability is Availability.PROVIDER_ERROR:
            # A provider error blocks regardless of whether the dimension is mandatory.
            return _not_admitted(
                cv, strategy, s, (*codes, _CODE_ERROR), (f"provider_error={d.value}",)
            )
        if dim.availability is not Availability.AVAILABLE or dim.raw is None:
            if d in mandatory:
                return _not_admitted(
                    cv, strategy, s, (*codes, _CODE_NA), (f"mandatory_dim_missing={d.value}",)
                )
            continue  # compensatory: dropped, weights are NOT renormalised
        if dim.divergence_exceeded:
            codes.append(_CODE_DIVERGED)
            if d in mandatory:
                return _not_admitted(
                    cv, strategy, s, codes, (f"mandatory_dim_diverged={d.value}",)
                )
            x[d] = dim.raw  # compensatory: the raw value is the more honest signal
        else:
            x[d] = dim.calibrated if dim.calibrated is not None else dim.raw
        if dim.calibration_stale:
            codes.append(_CODE_STALE)

    try:
        raw_score = float(strategy.score(x, s, cv.entity_class))
    except Exception as exc:  # fail closed: a strategy that cannot run never admits
        return _not_admitted(
            cv, strategy, s, (*codes, CODE_CONFIG_INVALID), (f"strategy_error={type(exc).__name__}",)
        )
    if not math.isfinite(raw_score):
        return _not_admitted(
            cv, strategy, s, (*codes, CODE_CONFIG_INVALID), ("strategy_score_not_finite",)
        )

    pen = (
        s.penalties.contradiction * penalties_in.unresolved_contradictions
        + s.penalties.staleness * penalties_in.staleness
        + s.penalties.dependency * penalties_in.dependency_penalty
    )
    score = raw_score - pen

    capped = False
    if cap.cap_applied:
        ceiling = cap.output_value
        if not isinstance(ceiling, (int, float)) or not math.isfinite(ceiling):
            return _not_admitted(
                cv, strategy, s, (*codes, CODE_CONFIG_INVALID), ("cap_value_not_finite",)
            )
        if score > ceiling:
            score, capped = ceiling, True
            codes.append(CODE_CAP)
    score = _unit(score)

    admitted = score >= s.policy_thresholds[cv.entity_class]
    if not admitted:
        codes.append(CODE_BELOW)
    digest = _inputs_hash(
        {
            "cv": cv.inputs_hash,
            "strategy": strategy.name.value,
            "x": {k.value: v for k, v in sorted(x.items(), key=lambda kv: kv[0].value)},
            "pen_inputs": penalties_in.model_dump(mode="json"),
        }
    )
    return ProjectionResult(
        strategy=strategy.name,
        decision_score=score,
        admitted=admitted,
        policy_threshold_ref=_theta_ref(cv.entity_class),
        penalty_total=pen,
        capped_by_critical_cap=capped,
        reason_codes=tuple(dict.fromkeys(codes)),
        inputs_hash=digest,
        rule_version=RULE_VERSION_PROJ,
        config_version=s.config_version,
        decisive_conditions=tuple(f"{k.value}={v:.4f}" for k, v in sorted(x.items(), key=lambda kv: kv[0].value)),
    )
