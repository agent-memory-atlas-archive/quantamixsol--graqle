"""CR-015 PR-015a — AC-5: registry resolve/validate/log; TrajectorySettings; AC-22 numerals."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from graqle.assurance.estimators import EstimatorDeps, EstimatorRegistry, TrajectoryEstimator
from graqle.assurance.reason_codes import REGISTRY, Severity, resolvable
from graqle.assurance.settings import ConfigurationError, DagSettings
from graqle.assurance.trajectory_settings import TrajectorySettings
from tests.test_assurance._traj_fakes import DAG, DEPS, SALT, TS, estimator

ROOT = Path(__file__).resolve().parents[2] / "graqle" / "assurance"


@pytest.fixture(autouse=True)
def _restore_registry():  # type: ignore[no-untyped-def]
    saved = dict(EstimatorRegistry._factories)
    yield
    EstimatorRegistry._factories.clear()
    EstimatorRegistry._factories.update(saved)


def test_resolve_known_estimator_logs_active_line(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="graqle.assurance.estimators"):
        est = EstimatorRegistry.resolve(TS, DEPS)
    assert isinstance(est, TrajectoryEstimator)
    assert "DAG trajectory estimator active: id=causal_baseline version=1" in caplog.text


def test_unknown_estimator_name_is_rejected_at_settings_construction() -> None:
    with pytest.raises(ConfigurationError, match="DAG-TR-003"):
        TrajectorySettings(estimator="nope")


def test_resolve_unknown_raises_and_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="graqle.assurance.estimators"):
        ts = TS.model_copy(update={"estimator": "ghost"})  # bypasses the validator on purpose
        with pytest.raises(ConfigurationError, match="DAG-TR-003"):
            EstimatorRegistry.resolve(ts, DEPS)
    assert "active" not in caplog.text


def test_register_rejects_duplicate_and_empty_names() -> None:
    with pytest.raises(ConfigurationError, match="already registered"):
        EstimatorRegistry.register("causal_baseline", lambda ts, deps: estimator())
    for bad in ("", "  "):
        with pytest.raises(ConfigurationError):
            EstimatorRegistry.register(bad, lambda ts, deps: estimator())
    assert EstimatorRegistry.names() == ("causal_baseline",)


def test_registered_non_baseline_estimator_needs_a_weights_path() -> None:
    EstimatorRegistry.register("custom", lambda ts, deps: estimator())
    assert EstimatorRegistry.names() == ("causal_baseline", "custom")
    with pytest.raises(ConfigurationError, match="weights path"):
        TrajectorySettings(estimator="custom")
    ok = TrajectorySettings(estimator="custom", estimator_weights_path=Path("w.json"))
    assert EstimatorRegistry.resolve(ok, DEPS).id == "causal_baseline"


def test_window_must_be_positive() -> None:
    for bad in (0, -1):
        with pytest.raises(ConfigurationError):
            TrajectorySettings(estimator="causal_baseline", history_window_steps=bad)


def test_from_dag_settings_fails_closed_without_estimator_name() -> None:
    with pytest.raises(ConfigurationError, match="required"):
        TrajectorySettings.from_dag_settings(DagSettings(config_salt=SALT))
    ts = TrajectorySettings.from_dag_settings(
        DagSettings(config_salt=SALT, trajectory_estimator="causal_baseline")
    )
    assert ts.estimator == "causal_baseline"
    assert ts.history_window_steps >= 1


def test_settings_reexported_lazily_without_loading_estimators() -> None:
    from graqle.assurance import settings

    assert settings.TrajectorySettings is TrajectorySettings


def test_trajectory_reason_codes_registered() -> None:
    est = REGISTRY["DAG-TR-003-ESTIMATOR_UNAVAILABLE"]
    assert est.severity is Severity.CRITICAL
    for code in ("DAG-TR-004-TRAJECTORY_RELIABILITY_BELOW_FLOOR", "DAG-TR-005-HISTORY_INCOMPLETE"):
        assert code in REGISTRY and resolvable(code)


def test_no_numeric_literal_for_private_symbols_in_new_modules() -> None:
    """AC-22 (PR-015a part): only the documented safe-default window may be a numeral."""
    for name in ("trajectory.py", "estimators.py", "trajectory_settings.py"):
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
        floats = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, float) and n.value not in (0.0, 1.0)
        ]
        assert floats == [], f"{name}: unexpected float literals {floats}"
        ints = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant)
            and isinstance(n.value, int)
            and not isinstance(n.value, bool)
            and n.value not in (0, 1)
        ]
        assert ints == ([8] if name == "trajectory_settings.py" else []), f"{name}: {ints}"
