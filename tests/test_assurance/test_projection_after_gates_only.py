"""Projection is defined only after the hard gates pass; every degraded input fails closed."""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from graqle.assurance.confidence_vector import Availability, DimensionName, EntityClass
from graqle.assurance.projection import (
    HardGateSummary,
    LinearProjection,
    PenaltyInputs,
    ProjectionStrategyName,
    project,
)

from ._proj_fakes import FakeCap, dim, failed, no_penalty, passed, settings, vector

D = DimensionName


class SpyStrategy:
    name = ProjectionStrategyName.LINEAR

    def __init__(self, value: float = 0.9) -> None:
        self.calls = 0
        self._value = value

    def score(self, x, s, entity_class) -> float:
        self.calls += 1
        return self._value


@pytest.fixture
def s(tmp_path: Path):
    return settings(str(tmp_path))


class TestHardGatesFirst:
    def test_gate_failure_is_bottom_and_no_strategy_runs(self, s) -> None:
        spy = SpyStrategy()
        res = project(vector(), failed("HG-03", "HG-05"), FakeCap(), s, spy, no_penalty())
        assert res.decision_score is None
        assert res.admitted is False
        assert res.reason_codes == ("DAG-CV-004-PROJECTION_SKIPPED_HG_FAIL",)
        assert res.decisive_conditions == ("HG-03", "HG-05")
        assert spy.calls == 0

    def test_empty_gate_results_are_not_a_pass(self) -> None:
        summary = HardGateSummary.from_results([])
        assert summary.all_passed is False
        assert summary.failed_gate_ids

    def test_from_results_names_failed_gates(self) -> None:
        ok = types.SimpleNamespace(rule_id="HG-01", passed=True)
        bad = types.SimpleNamespace(rule_id="HG-02", passed=False)
        summary = HardGateSummary.from_results([ok, bad])
        assert summary.all_passed is False
        assert summary.failed_gate_ids == ("HG-02",)

    def test_inconsistent_summary_rejected(self) -> None:
        with pytest.raises(ValueError):
            HardGateSummary(all_passed=True, failed_gate_ids=("HG-01",))
        with pytest.raises(ValueError):
            HardGateSummary(all_passed=False)


class TestFailClosed:
    def test_mandatory_not_available_blocks_without_scoring(self, s) -> None:
        spy = SpyStrategy()
        cv = vector({D.CORROBORATION: dim(D.CORROBORATION, availability=Availability.NOT_AVAILABLE)})
        res = project(cv, passed(), FakeCap(), s, spy, no_penalty())
        assert res.decision_score is None and not res.admitted
        assert "DAG-CV-001-DIM_NOT_AVAILABLE" in res.reason_codes
        assert spy.calls == 0

    def test_compensatory_not_available_is_dropped(self, s) -> None:
        cv = vector({D.CONTEXT_FIT: dim(D.CONTEXT_FIT, availability=Availability.NOT_AVAILABLE)})
        res = project(cv, passed(), FakeCap(), s, LinearProjection(), no_penalty())
        assert res.decision_score is not None

    def test_provider_error_always_blocks(self, s) -> None:
        cv = vector({D.CONTEXT_FIT: dim(D.CONTEXT_FIT, availability=Availability.PROVIDER_ERROR)})
        res = project(cv, passed(), FakeCap(), s, SpyStrategy(), no_penalty())
        assert res.decision_score is None and not res.admitted
        assert "DAG-CV-007-PROVIDER_ERROR" in res.reason_codes

    def test_mandatory_divergence_blocks(self, s) -> None:
        cv = vector({D.CORROBORATION: dim(D.CORROBORATION, 0.9, diverged=True)})
        res = project(cv, passed(), FakeCap(), s, SpyStrategy(), no_penalty())
        assert res.decision_score is None and not res.admitted
        assert "DAG-CV-003-DIVERGENCE_EXCEEDED" in res.reason_codes

    def test_compensatory_divergence_uses_raw_with_warning(self, s) -> None:
        cv = vector({D.CONTEXT_FIT: dim(D.CONTEXT_FIT, 0.9, diverged=True)})
        res = project(cv, passed(), FakeCap(), s, LinearProjection(), no_penalty())
        assert res.decision_score is not None
        assert "DAG-CV-003-DIVERGENCE_EXCEEDED" in res.reason_codes
        assert "context_fit=0.9000" in res.decisive_conditions

    def test_strategy_exception_does_not_admit(self, s) -> None:
        class Boom(SpyStrategy):
            def score(self, x, s, entity_class) -> float:
                raise RuntimeError("boom")

        res = project(vector(default=1.0), passed(), FakeCap(), s, Boom(), no_penalty())
        assert res.decision_score is None and not res.admitted
        assert "DAG-CV-008-CONFIG_INVALID" in res.reason_codes

    @pytest.mark.parametrize("bad", [float("nan"), float("inf")])
    def test_non_finite_score_does_not_admit(self, s, bad: float) -> None:
        res = project(vector(), passed(), FakeCap(), s, SpyStrategy(bad), no_penalty())
        assert res.decision_score is None and not res.admitted

    def test_non_finite_cap_does_not_admit(self, s) -> None:
        cap = FakeCap(cap_applied=True, output_value=float("nan"))
        res = project(vector(default=1.0), passed(), cap, s, SpyStrategy(1.0), no_penalty())
        assert res.decision_score is None and not res.admitted

    def test_missing_monotone_knots_does_not_admit(self, s) -> None:
        from graqle.assurance.projection import MonotonicProjection

        res = project(vector(default=1.0), passed(), FakeCap(), s, MonotonicProjection(), no_penalty())
        assert res.decision_score is None and not res.admitted
        assert "DAG-CV-008-CONFIG_INVALID" in res.reason_codes


class TestScoring:
    def test_cap_lowers_score_and_is_reported(self, s) -> None:
        cap = FakeCap(cap_applied=True, output_value=0.1)
        res = project(vector(default=1.0), passed(), cap, s, SpyStrategy(1.0), no_penalty())
        assert res.decision_score == pytest.approx(0.1)
        assert res.capped_by_critical_cap is True
        assert "DAG-CV-010-CRITICAL_CAP_APPLIED" in res.reason_codes

    def test_cap_above_score_changes_nothing(self, s) -> None:
        cap = FakeCap(cap_applied=True, output_value=1.0)
        res = project(vector(default=1.0), passed(), cap, s, SpyStrategy(0.5), no_penalty())
        assert res.decision_score == pytest.approx(0.5)
        assert res.capped_by_critical_cap is False

    def test_penalties_subtract_and_clamp_at_zero(self, s) -> None:
        pen = PenaltyInputs(unresolved_contradictions=50, staleness=1.0, dependency_penalty=1.0)
        res = project(vector(), passed(), FakeCap(), s, SpyStrategy(0.5), pen)
        assert res.decision_score == 0.0
        assert res.penalty_total and res.penalty_total > 0.5
        assert res.admitted is False
        assert "DAG-CV-005-BELOW_POLICY_THRESHOLD" in res.reason_codes

    def test_stale_dimension_is_reported(self, s) -> None:
        cv = vector({D.CORROBORATION: dim(D.CORROBORATION, 0.5, stale=True)})
        res = project(cv, passed(), FakeCap(), s, LinearProjection(), no_penalty())
        assert "DAG-CV-002-CALIBRATION_STALE" in res.reason_codes

    def test_calibrated_value_preferred_over_raw(self, s) -> None:
        cv = vector({D.CORROBORATION: dim(D.CORROBORATION, 0.2, calibrated=0.7)})
        res = project(cv, passed(), FakeCap(), s, LinearProjection(), no_penalty())
        assert "corroboration=0.7000" in res.decisive_conditions

    def test_result_names_a_symbol_never_the_threshold(self, s) -> None:
        res = project(vector(), passed(), FakeCap(), s, LinearProjection(), no_penalty())
        assert res.policy_threshold_ref == "θ_POLICY[decision]"
        dumped = json.dumps(res.model_dump(mode="json")).lower()
        for banned in ("weights", "penalties", "half_life", "max_divergence", "ttl"):
            assert banned not in dumped

    def test_inputs_hash_is_deterministic_and_input_sensitive(self, s) -> None:
        a = project(vector(), passed(), FakeCap(), s, LinearProjection(), no_penalty())
        b = project(vector(), passed(), FakeCap(), s, LinearProjection(), no_penalty())
        c = project(vector(default=0.6), passed(), FakeCap(), s, LinearProjection(), no_penalty())
        assert a.inputs_hash == b.inputs_hash
        assert a.inputs_hash != c.inputs_hash

    @pytest.mark.parametrize("entity_class", list(EntityClass))
    def test_threshold_reference_follows_class(self, s, entity_class: EntityClass) -> None:
        res = project(
            vector(entity_class=entity_class), passed(), FakeCap(), s, LinearProjection(), no_penalty()
        )
        assert entity_class.value in res.policy_threshold_ref
