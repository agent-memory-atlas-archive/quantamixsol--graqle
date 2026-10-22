"""CR-015 PR-015a — AC-4: causal baseline estimator is deterministic and monotone."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st

from graqle.assurance.estimators import CausalBaselineEstimator, EstimatorDeps, TrajectoryEstimate
from graqle.assurance.settings import ConfigurationError, DagSettings
from tests.test_assurance._traj_fakes import DAG, PARAMS, TS, cp, estimator, history


def test_deterministic_across_100_runs() -> None:
    view = history(4, errors=1, calls=2).view_until(3)
    first = estimator().estimate(view)
    runs = [estimator().estimate(view) for _ in range(100)]
    assert all(r.reliability == first.reliability and r.inputs_hash == first.inputs_hash for r in runs)
    assert all(r == first for r in runs)


@h_settings(max_examples=100, deadline=None)
@given(a=st.integers(0, 8), b=st.integers(0, 8))
def test_more_tool_errors_never_raise_reliability(a: int, b: int) -> None:
    lo, hi = sorted((a, b))
    est = estimator()
    r_lo = est.estimate(history(3, errors=lo, calls=8).view_until(2)).reliability
    r_hi = est.estimate(history(3, errors=hi, calls=8).view_until(2)).reliability
    assert r_hi <= r_lo


def test_estimate_shape_and_provenance() -> None:
    e = estimator().estimate(history(3).view_until(2))
    assert isinstance(e, TrajectoryEstimate)
    assert 0.0 <= e.reliability <= 1.0
    assert (e.probabilistic, e.variance) == (False, None)
    assert (e.estimator_id, e.estimator_version) == ("causal_baseline", "1")
    assert e.inputs_hash.startswith("sha256:")
    assert e.config_version.startswith("hmac-sha256:")
    assert e.decisive_conditions == ("freshness_na=False",)


def test_na_freshness_is_worst_case_not_a_default() -> None:
    est = estimator()
    na = est.estimate(history(2, evidence_freshness=None).view_until(1))
    fresh = est.estimate(history(2, evidence_freshness=1.0).view_until(1))
    zero = est.estimate(history(2, evidence_freshness=0.0).view_until(1))
    assert na.reliability == zero.reliability <= fresh.reliability
    assert na.decisive_conditions == ("freshness_na=True",)
    assert na.inputs_hash == zero.inputs_hash


def test_estimate_uses_only_the_viewed_prefix_window() -> None:
    h = history(6, errors=2, calls=2)
    h.append(cp(6, errors=0, calls=4))
    est = estimator()
    # window of 4 steps: steps 3..6 -> 6 errors of 10 calls vs steps 2..5 -> 8 of 8
    assert est.estimate(h.view_until(6)).reliability > est.estimate(h.view_until(5)).reliability


def test_missing_salt_or_params_fail_at_construction() -> None:
    with pytest.raises(ConfigurationError, match="SALT"):
        CausalBaselineEstimator(TS, EstimatorDeps(dag_settings=DagSettings(), baseline_params=PARAMS))
    with pytest.raises(ConfigurationError, match="parameters"):
        CausalBaselineEstimator(TS, EstimatorDeps(dag_settings=DAG, baseline_params=None))


def test_estimate_rejects_variance_on_deterministic_estimate() -> None:
    e = estimator().estimate(history(1).view_until(0))
    with pytest.raises(ValueError):
        TrajectoryEstimate(**{**e.model_dump(), "variance": 0.1})


def test_repr_hides_private_parameters() -> None:
    assert "private" in repr(EstimatorDeps(dag_settings=DAG, baseline_params=PARAMS))
