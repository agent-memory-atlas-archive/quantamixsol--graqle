"""Shared builders for the CR-015 PR-015a tests.

Map knots, exponents and the salt are TEST SUBSTITUTES, not deployed values.
"""

from __future__ import annotations

from graqle.assurance import causal_baselines as cb
from graqle.assurance.estimators import CausalBaselineEstimator, EstimatorDeps
from graqle.assurance.settings import DagSettings
from graqle.assurance.trajectory import (
    ToolErrorRecord,
    TrajectoryCheckpoint,
    TrajectoryHistory,
)
from graqle.assurance.trajectory_settings import TrajectorySettings

SALT = "test-substitute-salt-0123456789abcdef-XYZ"
DOWN = cb.MonotoneMap(knots_x=(0.0, 3.0, 9.0), knots_y=(1.0, 0.6, 0.2))
UP = cb.MonotoneMap(knots_x=(0.0, 1.0), knots_y=(0.3, 1.0))
FAIL_DOWN = cb.MonotoneMap(knots_x=(0.0, 1.0), knots_y=(1.0, 0.1))

PARAMS = cb.CausalBaselineParams(
    maps={"steps": DOWN, "retry": DOWN, "contra": DOWN, "fresh": UP, "tool": FAIL_DOWN},
    exponents={name: 1.0 for name in cb.BASELINE_NAMES},
)
DAG = DagSettings(config_salt=SALT)
DEPS = EstimatorDeps(dag_settings=DAG, baseline_params=PARAMS)
TS = TrajectorySettings(estimator="causal_baseline", history_window_steps=4)


def estimator() -> CausalBaselineEstimator:
    return CausalBaselineEstimator(TS, DEPS)


def cp(step: int, *, session: str = "s1", errors: int = 0, calls: int = 1, **kw) -> TrajectoryCheckpoint:  # type: ignore[no-untyped-def]
    errs = tuple(
        ToolErrorRecord(step=step, tool="t", error_class="E", retryable=False) for _ in range(errors)
    )
    return TrajectoryCheckpoint(
        checkpoint_id=f"cp{step}",
        session_id=session,
        turn_id="turn1",
        step_index=step,
        timestamp_unix=1000.0 + step,
        candidate_id="cand",
        tool_calls=calls,
        tool_errors=errs,
        evidence_freshness=kw.pop("evidence_freshness", 0.8),
        **kw,
    )


def history(n: int, **kw) -> TrajectoryHistory:  # type: ignore[no-untyped-def]
    h = TrajectoryHistory(session_id="s1")
    for i in range(n):
        h.append(cp(i, **kw))
    return h
