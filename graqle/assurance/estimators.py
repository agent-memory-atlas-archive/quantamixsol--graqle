"""DAG-2026 trajectory estimators and their registry (CR-015 §4, §5.2, PR-015a).

``CausalBaselineEstimator`` maps a :class:`HistoryView` onto the CR-014
``CausalBaselineInput`` and returns the deterministic ``b_combined`` score as the
trajectory reliability. It reads only the view, so it cannot see past step ``t``.

Fail-closed rules:
* evidence freshness NA (``None``) is scored as the worst case, not a default;
* a missing deployment salt is a ``ConfigurationError`` at construction, not at
  the first estimate.

Trade-secret rule (CR-015 §12): the baseline maps and exponents are private and
arrive in ``EstimatorDeps.baseline_params``; nothing here carries a value.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.estimators
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015b)
# dependencies: logging, pydantic, graqle.assurance.causal_baselines,
#   graqle.assurance.trajectory, graqle.assurance.trajectory_settings
# constraints: never imported by graqle.governance.*; no numeric literal for
#   any private map knot, exponent or window
# -- /graqle:intelligence --
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from graqle.assurance.causal_baselines import (
    CausalBaselineInput,
    CausalBaselineParams,
    baseline_scores,
)
from graqle.assurance.settings import ConfigurationError, DagSettings
from graqle.assurance.trajectory import HistoryView
from graqle.assurance.trajectory_settings import BASELINE_ESTIMATOR, TrajectorySettings

__all__ = [
    "RULE_VERSION_TRJ",
    "CausalBaselineEstimator",
    "EstimatorDeps",
    "EstimatorRegistry",
    "TrajectoryEstimate",
    "TrajectoryEstimator",
]

logger = logging.getLogger(__name__)

RULE_VERSION_TRJ = "1"


class TrajectoryEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reliability: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    probabilistic: bool
    variance: float | None = Field(default=None, ge=0.0, allow_inf_nan=False)
    estimator_id: str
    estimator_version: str
    inputs_hash: str
    rule_version: str
    config_version: str
    features_used: tuple[str, ...]
    decisive_conditions: tuple[str, ...]

    @model_validator(mode="after")
    def _variance_only_if_probabilistic(self) -> TrajectoryEstimate:
        if not self.probabilistic and self.variance is not None:
            raise ValueError("a deterministic estimate carries no variance")
        return self


@runtime_checkable
class TrajectoryEstimator(Protocol):
    id: str
    version: str

    def estimate(self, view: HistoryView) -> TrajectoryEstimate: ...


@dataclass(frozen=True)
class EstimatorDeps:
    """Private inputs an estimator factory may need. ``repr`` shows no values."""

    dag_settings: DagSettings
    baseline_params: CausalBaselineParams | None = None

    def __repr__(self) -> str:
        return "EstimatorDeps(<private>)"


class CausalBaselineEstimator:
    id = BASELINE_ESTIMATOR
    version = "1"

    def __init__(self, settings: TrajectorySettings, deps: EstimatorDeps) -> None:
        if deps.baseline_params is None:
            raise ConfigurationError("DAG-TR-003: the causal baseline needs its private parameters")
        salt = deps.dag_settings.config_salt
        if salt is None or not salt.get_secret_value().strip():
            raise ConfigurationError("DAG-TR-003: the causal baseline needs GRAQLE_DAG_CONFIG_SALT")
        self.window = settings.history_window_steps
        self._params = deps.baseline_params
        self._dag = deps.dag_settings

    def estimate(self, view: HistoryView) -> TrajectoryEstimate:
        freshness = view.evidence_freshness()
        inp = CausalBaselineInput(
            elapsed_steps=view.elapsed_steps(),
            retry_count=view.retry_count(),
            unresolved_contradictions=view.unresolved_contradictions(),
            # NA freshness is the worst case (fail-closed), never a neutral default.
            evidence_freshness=freshness if freshness is not None else 0.0,
            tool_failure_history=view.tool_failure_history(self.window),
        )
        scores = baseline_scores(inp, params=self._params, settings=self._dag)
        return TrajectoryEstimate(
            reliability=scores.b_combined,
            probabilistic=False,
            variance=None,
            estimator_id=self.id,
            estimator_version=self.version,
            inputs_hash=scores.inputs_hash,
            rule_version=RULE_VERSION_TRJ,
            config_version=scores.config_version,
            features_used=(
                "elapsed_steps",
                "retry_count",
                "unresolved_contradictions",
                "evidence_freshness",
                "tool_failure_history",
            ),
            decisive_conditions=(f"freshness_na={freshness is None}",),
        )


EstimatorFactory = Callable[[TrajectorySettings, EstimatorDeps], TrajectoryEstimator]


class EstimatorRegistry:
    _factories: dict[str, EstimatorFactory] = {BASELINE_ESTIMATOR: CausalBaselineEstimator}

    @classmethod
    def names(cls) -> tuple[str, ...]:
        return tuple(sorted(cls._factories))

    @classmethod
    def register(cls, name: str, factory: EstimatorFactory) -> None:
        if not name or not name.strip():
            raise ConfigurationError("estimator name must be non-empty")
        if name in cls._factories:
            raise ConfigurationError(f"estimator {name!r} already registered")
        cls._factories[name] = factory

    @classmethod
    def resolve(cls, ts: TrajectorySettings, deps: EstimatorDeps) -> TrajectoryEstimator:
        factory = cls._factories.get(ts.estimator)
        if factory is None:
            raise ConfigurationError(f"DAG-TR-003: unknown estimator {ts.estimator!r}")
        est = factory(ts, deps)
        logger.info("DAG trajectory estimator active: id=%s version=%s", est.id, est.version)
        return est
