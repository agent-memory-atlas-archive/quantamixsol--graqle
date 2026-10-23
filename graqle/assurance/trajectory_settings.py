"""DAG-2026 trajectory settings (CR-015 §3.3, PR-015a).

Kept beside ``settings`` and re-exported lazily from it (as ``cv_settings`` is) so
importing ``graqle.assurance.settings`` never loads the estimator code
(flag-off isolation).

The estimator name is validated against :class:`EstimatorRegistry` at
construction: an unknown name raises ``ConfigurationError`` (DAG-TR-003).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.trajectory_settings
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015a estimators)
# dependencies: pydantic, graqle.assurance.settings, graqle.assurance.estimators (lazy)
# constraints: never imported by graqle.governance.*; no configured value
# -- /graqle:intelligence --
from pathlib import Path

from pydantic import BaseModel, ConfigDict, model_validator

from graqle.assurance.settings import ConfigurationError, DagSettings

__all__ = ["BASELINE_ESTIMATOR", "TrajectorySettings"]

#: Name of the shipped deterministic estimator.
BASELINE_ESTIMATOR = "causal_baseline"

# Operational default for the history window, in steps. It is a non-inferential
# placeholder, not a tuned value; deployments set their own (W_HIST is a private-config value).
_SAFE_DEFAULT_W_HIST = 8


class TrajectorySettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    estimator: str
    history_window_steps: int = _SAFE_DEFAULT_W_HIST
    estimator_weights_path: Path | None = None

    @model_validator(mode="after")
    def _validate(self) -> TrajectorySettings:
        from graqle.assurance.estimators import EstimatorRegistry  # lazy: avoids a cycle

        if self.estimator not in EstimatorRegistry.names():
            raise ConfigurationError(
                f"DAG-TR-003: unknown trajectory estimator {self.estimator!r}; "
                f"known={EstimatorRegistry.names()}"
            )
        if self.estimator != BASELINE_ESTIMATOR and self.estimator_weights_path is None:
            raise ConfigurationError("DAG-TR-003: estimator weights path required for non-baseline estimator")
        if isinstance(self.history_window_steps, bool) or self.history_window_steps < 1:
            raise ConfigurationError("DAG-TR-003: history window must be a positive number of steps")
        return self

    @classmethod
    def from_dag_settings(cls, dag: DagSettings) -> TrajectorySettings:
        """Build from the flat ``DagSettings``; a missing estimator name fails closed."""
        if not dag.trajectory_estimator:
            raise ConfigurationError("DAG-TR-003: GRAQLE_DAG_TRAJECTORY_ESTIMATOR is required")
        return cls(estimator=dag.trajectory_estimator)
