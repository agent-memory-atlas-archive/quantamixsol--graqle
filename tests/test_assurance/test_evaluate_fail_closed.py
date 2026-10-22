"""CR-015 AC-8: evaluate() is fail-closed per stage and never raises (PR-015b)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from graqle.assurance.gate import DagVerdict, ProjectionStageResult
from graqle.assurance.outcomes import GateOutcome

from ._gate_fakes import (
    CANDIDATE,
    FakeCap,
    FakeEstimator,
    good_projection,
    hg,
    make_components,
    make_ctx,
    make_gate,
)


def _boom(*_a: Any, **_k: Any) -> Any:
    raise RuntimeError("stage down")


class TestHappyPath:
    def test_all_stages_pass_executes(self) -> None:
        v = make_gate().evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.EXECUTE and v.decisive_rule == "DAG-RT-17"
        assert v.verdict.evaluation_errors == [] and v.verdict.trajectory_reliability is not None

    def test_estimator_sees_only_the_prefix_view(self) -> None:
        est = FakeEstimator()
        make_gate(make_components(estimator=est)).evaluate(CANDIDATE, make_ctx())
        assert len(est.seen_views) == 1 and est.seen_views[0].t == 0


class TestStageFaults:
    def test_hard_gate_exception_rejects_with_error_recorded(self) -> None:
        v = make_gate(make_components(hard_gates=_boom)).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.REJECT and v.decisive_rule == "DAG-RT-01"
        assert any(e.startswith("hard_gates:") for e in v.verdict.evaluation_errors)

    def test_empty_hard_gate_results_reject(self) -> None:
        v = make_gate(make_components(hard_gates=lambda _c, _x: ())).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.REJECT

    def test_cap_exception_rejects(self) -> None:
        v = make_gate(make_components(cap=_boom)).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.REJECT
        assert any(e.startswith("critical_cap:") for e in v.verdict.evaluation_errors)

    def test_projection_exception_escalates(self) -> None:
        v = make_gate(make_components(projection=_boom)).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.ESCALATE and v.decisive_rule == "DAG-RT-03"
        assert any(e.startswith("projection:") for e in v.verdict.evaluation_errors)

    def test_trajectory_exception_escalates(self) -> None:
        comps = make_components(estimator=FakeEstimator(boom=True))
        v = make_gate(comps).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.ESCALATE
        assert any(e.startswith("trajectory:") for e in v.verdict.evaluation_errors)

    def test_missing_checkpoint_view_escalates(self) -> None:
        ctx = make_ctx()
        ctx.checkpoint = type("CP", (), {"step_index": 99})()  # beyond the recorded history
        v = make_gate().evaluate(CANDIDATE, ctx)
        assert v.outcome is GateOutcome.ESCALATE

    def test_authority_exception_escalates(self) -> None:
        v = make_gate(make_components(may_automate=_boom)).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.ESCALATE

    def test_unauthorised_actor_escalates(self) -> None:
        v = make_gate(make_components(may_automate=lambda _a, _t: False)).evaluate(CANDIDATE, make_ctx())
        assert (v.outcome, v.decisive_rule) == (GateOutcome.ESCALATE, "DAG-RT-04")

    def test_unregistered_carried_code_fails_closed_not_raised(self) -> None:
        def proj(*_a: Any) -> ProjectionStageResult:
            return ProjectionStageResult(
                admitted=False, decision_score=None, calibration_stale=False, mandatory_na=False,
                reason_codes=("NOT-A-REGISTERED-CODE",),
            )

        v = make_gate(make_components(projection=proj)).evaluate(CANDIDATE, make_ctx())
        assert isinstance(v, DagVerdict) and v.outcome is GateOutcome.ESCALATE
        assert v.verdict.evaluation_errors

    def test_non_numeric_risk_level_is_critical_tier(self) -> None:
        cand = type(CANDIDATE)(id="c", risk_level="not-a-level")
        v = make_gate().evaluate(cand, make_ctx())
        assert v.impact_tier.value == "CRITICAL"


class TestSemantics:
    def test_failed_critical_gate_rejects_even_with_perfect_projection(self) -> None:
        comps = make_components(hard_gates=lambda _c, _x: (hg("HG-01", passed=False, severity="CRITICAL",
                                                             codes=("DAG-HG01-POLICY_MISSING",)),))
        v = make_gate(comps).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.REJECT and v.decisive_rule == "DAG-RT-02"

    def test_noncritical_unresolvable_failure_holds(self) -> None:
        comps = make_components(hard_gates=lambda _c, _x: (hg("HG-02", passed=False, severity="FAIL",
                                                             codes=("DAG-TR-010-EVALUATION_ERROR",)),))
        v = make_gate(comps).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is not GateOutcome.EXECUTE

    def test_replan_without_controller_is_escalate(self) -> None:
        def proj(*_a: Any) -> ProjectionStageResult:
            return ProjectionStageResult(
                admitted=False, decision_score=0.2, calibration_stale=False, mandatory_na=False,
                reason_codes=("DAG-CV-005-BELOW_POLICY_THRESHOLD",),
            )

        v = make_gate(make_components(projection=proj)).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.ESCALATE
        assert any("replan controller unavailable" in e for e in v.verdict.evaluation_errors)

    def test_replan_with_controller_keeps_replan(self) -> None:
        @dataclass
        class Controller:
            calls: list = field(default_factory=list)

            def on_replan(self, dv: DagVerdict, ctx: Any) -> DagVerdict:
                self.calls.append(dv.fingerprint)
                return dv

        def proj(*_a: Any) -> ProjectionStageResult:
            return ProjectionStageResult(
                admitted=False, decision_score=0.2, calibration_stale=False, mandatory_na=False,
                reason_codes=("DAG-CV-005-BELOW_POLICY_THRESHOLD",),
            )

        ctrl = Controller()
        v = make_gate(make_components(projection=proj, replan=ctrl)).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.REPLAN and ctrl.calls == [v.fingerprint]

    def test_replan_controller_exception_escalates(self) -> None:
        class Bad:
            def on_replan(self, *_a: Any) -> Any:
                raise RuntimeError("x")

        def proj(*_a: Any) -> ProjectionStageResult:
            return ProjectionStageResult(
                admitted=False, decision_score=0.2, calibration_stale=False, mandatory_na=False,
                reason_codes=("DAG-CV-005-BELOW_POLICY_THRESHOLD",),
            )

        v = make_gate(make_components(projection=proj, replan=Bad())).evaluate(CANDIDATE, make_ctx())
        assert v.outcome is GateOutcome.ESCALATE

    def test_repeated_fingerprint_escalates_with_unchanged_reason_code(self) -> None:
        def proj(*_a: Any) -> ProjectionStageResult:
            return ProjectionStageResult(
                admitted=False, decision_score=0.2, calibration_stale=False, mandatory_na=False,
                reason_codes=("DAG-CV-005-BELOW_POLICY_THRESHOLD",),
            )

        class Ctrl:
            def on_replan(self, dv: DagVerdict, ctx: Any) -> DagVerdict:
                return dv

        gate = make_gate(make_components(projection=proj, replan=Ctrl()))
        first = gate.evaluate(CANDIDATE, make_ctx())
        assert first.outcome is GateOutcome.REPLAN

        @dataclass(frozen=True)
        class State:
            attempts: int
            fingerprints: frozenset

        second = gate.evaluate(CANDIDATE, make_ctx(replan_state=State(1, frozenset({first.fingerprint}))))
        assert second.outcome is GateOutcome.ESCALATE and second.decisive_rule == "DAG-RT-07"
        assert "DAG-TR-002-UNCHANGED_REASON_DETECTED" in second.reason_codes
        assert second.fingerprint == first.fingerprint

    def test_budget_exhausted_without_mandatory_pass_escalates(self) -> None:
        @dataclass(frozen=True)
        class State:
            attempts: int = 2
            fingerprints: frozenset = frozenset()

        def proj(*_a: Any) -> ProjectionStageResult:
            return ProjectionStageResult(
                admitted=False, decision_score=0.2, calibration_stale=False, mandatory_na=False,
                reason_codes=("DAG-CV-005-BELOW_POLICY_THRESHOLD",),
            )

        v = make_gate(make_components(projection=proj), budget=2).evaluate(CANDIDATE, make_ctx(replan_state=State()))
        assert (v.outcome, v.decisive_rule) == (GateOutcome.ESCALATE, "DAG-RT-08")

    def test_article14_refusal_escalates_and_marks_placeholder(self) -> None:
        a14 = type("A14", (), {"allowed": False, "threshold_status": "placeholder"})()
        v = make_gate().evaluate(CANDIDATE, make_ctx(article14=a14))
        assert v.outcome is GateOutcome.ESCALATE
        assert "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD" in v.reason_codes


class TestEmission:
    def _tier_candidate(self, level: str) -> Any:
        return type(CANDIDATE)(id="c", risk_level=level)

    def test_emit_failure_at_low_tier_keeps_execute_with_marker(self) -> None:
        comps = make_components(audit=_boom)
        v = make_gate(comps).evaluate(self._tier_candidate("LOW"), make_ctx())
        assert v.outcome is GateOutcome.EXECUTE
        assert "DAG-TR-015-PROVENANCE_EMIT_FAILED" in v.reason_codes
        assert v.verdict.evaluation_errors == []

    def test_emit_failure_at_high_tier_downgrades_execute_to_hold(self) -> None:
        comps = make_components(audit=_boom)
        v = make_gate(comps).evaluate(self._tier_candidate("HIGH"), make_ctx())
        assert v.outcome is GateOutcome.HOLD and v.decisive_rule == "DAG-RT-EMIT"

    def test_emitter_receives_public_view_only(self) -> None:
        seen: list[dict] = []

        class Emitter:
            def append(self, *, kind: str, subject_id: str, payload: dict) -> None:
                seen.append({"kind": kind, "subject_id": subject_id, **payload})

        make_gate(make_components(emitter=Emitter())).evaluate(CANDIDATE, make_ctx())
        assert seen and seen[0]["kind"] == "GATE_VERDICT"
        assert "confidence_vector" not in seen[0]


class TestConstruction:
    @pytest.mark.parametrize("budget", [0, -1, True])
    def test_non_positive_budget_rejected(self, budget: Any) -> None:
        with pytest.raises(ValueError):
            make_gate(budget=budget)

    def test_private_combinator_without_secret_rejected(self) -> None:
        from datetime import datetime, timezone

        from graqle.assurance.gate import DecisionAssuranceGate

        from ._gate_fakes import FakeRouting

        with pytest.raises(ValueError):
            DecisionAssuranceGate(
                components=make_components(), routing=FakeRouting(), max_retry_budget=1,
                config_version="c", combinator="private", clock=lambda: datetime.now(timezone.utc),
            )


def test_unused_fakes_import_guard() -> None:
    # Keeps the shared fakes honest: they must stay importable and self-consistent.
    assert FakeCap().cap_applied is False and good_projection(None, None, None, None).admitted
