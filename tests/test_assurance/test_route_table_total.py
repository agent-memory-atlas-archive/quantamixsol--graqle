"""CR-015 AC-6 / AC-7: route() is total, deterministic and ordered (PR-015b)."""

from __future__ import annotations

import random

import pytest

from graqle.assurance.gate import ImpactTier, RoutingInputs, route
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.reason_codes import REGISTRY

from ._gate_fakes import FakeRouting

_RULES = {f"DAG-RT-{n:02d}" for n in range(1, 18)}
_STAGES = ((), ("hard_gates",), ("critical_cap",), ("projection",), ("trajectory",), ("routing",), ("hard_gates", "projection"))


def _inputs(**over: object) -> RoutingInputs:
    base: dict[str, object] = dict(
        error_stages=(), hg_all_passed=True, hg_critical_failed=False, hg_noncritical_failed=False,
        cap_applied=False, proj_admitted=True, proj_score=0.95, cv_calibration_stale=False,
        cv_mandatory_na=False, trj_available=True, trj_reliability=0.9, authority_ok=True,
        impact_tier=ImpactTier.LOW, retries_remaining=2, fingerprint_seen=False,
        article14_refused=False, article14_status=None, resolvable=True, residual_risk=0.05,
    )
    base.update(over)
    return RoutingInputs(**base)


def _random_inputs(rng: random.Random) -> RoutingInputs:
    return RoutingInputs(
        error_stages=rng.choice(_STAGES),
        hg_all_passed=rng.random() < 0.5,
        hg_critical_failed=rng.random() < 0.3,
        hg_noncritical_failed=rng.random() < 0.3,
        cap_applied=rng.random() < 0.3,
        proj_admitted=rng.choice((None, True, False)),
        proj_score=rng.choice((None, 0.1, 0.9)),
        cv_calibration_stale=rng.random() < 0.3,
        cv_mandatory_na=rng.random() < 0.3,
        trj_available=rng.random() < 0.8,
        trj_reliability=rng.choice((None, 0.05, 0.95)),
        authority_ok=rng.random() < 0.8,
        impact_tier=rng.choice(list(ImpactTier)),
        retries_remaining=rng.choice((0, 1, 3)),
        fingerprint_seen=rng.random() < 0.2,
        article14_refused=rng.random() < 0.2,
        article14_status=rng.choice((None, "placeholder", "calibrated")),
        resolvable=rng.random() < 0.6,
        residual_risk=rng.choice((None, 0.01, 0.99)),
    )


class TestAC6TotalAndDeterministic:
    def test_total_deterministic_and_registered_over_many_inputs(self) -> None:
        rng = random.Random(20260918)
        settings = FakeRouting(tier_automation_max=ImpactTier.HIGH)
        for _ in range(20000):
            i = _random_inputs(rng)
            first = route(i, settings)
            assert first == route(i, settings)
            outcome, rule, codes = first
            assert isinstance(outcome, GateOutcome) and rule in _RULES
            assert all(c in REGISTRY for c in codes), codes

    def test_execute_requires_every_mandatory_condition(self) -> None:
        rng = random.Random(7)
        settings = FakeRouting()
        executes = 0
        for _ in range(20000):
            i = _random_inputs(rng)
            outcome, rule, _ = route(i, settings)
            if outcome is GateOutcome.EXECUTE:
                executes += 1
                assert rule == "DAG-RT-17"
                assert i.hg_all_passed and not i.hg_critical_failed and not i.hg_noncritical_failed
                assert not i.error_stages and i.authority_ok and i.proj_admitted is True
                assert not i.cv_mandatory_na and i.trj_available
                assert not i.article14_refused and not i.fingerprint_seen
                assert i.residual_risk is not None
        assert executes > 0  # the property is not vacuous

    @pytest.mark.parametrize("tier", list(ImpactTier))
    def test_none_valued_numbers_never_raise(self, tier: ImpactTier) -> None:
        i = _inputs(impact_tier=tier, trj_reliability=None, residual_risk=None, proj_admitted=None, proj_score=None)
        outcome, _, _ = route(i, FakeRouting())
        assert outcome is not GateOutcome.EXECUTE


class TestAC7Ordering:
    def test_critical_hard_gate_failure_rejects_despite_perfect_projection(self) -> None:
        i = _inputs(hg_all_passed=False, hg_critical_failed=True, proj_score=1.0, residual_risk=0.0)
        assert route(i, FakeRouting())[:2] == (GateOutcome.REJECT, "DAG-RT-02")

    def test_cap_with_no_budget_escalates_despite_perfect_projection(self) -> None:
        i = _inputs(cap_applied=True, retries_remaining=0, proj_score=1.0, residual_risk=0.0)
        outcome, rule, _ = route(i, FakeRouting())
        assert (outcome, rule) == (GateOutcome.ESCALATE, "DAG-RT-05")

    @pytest.mark.parametrize(
        ("over", "rule", "outcome"),
        [
            (dict(error_stages=("hard_gates",)), "DAG-RT-01", GateOutcome.REJECT),
            (dict(error_stages=("critical_cap",)), "DAG-RT-01", GateOutcome.REJECT),
            (dict(error_stages=("projection",)), "DAG-RT-03", GateOutcome.ESCALATE),
            (dict(error_stages=("trajectory",)), "DAG-RT-03", GateOutcome.ESCALATE),
            (dict(authority_ok=False), "DAG-RT-04", GateOutcome.ESCALATE),
            (dict(article14_refused=True), "DAG-RT-06", GateOutcome.ESCALATE),
            (dict(fingerprint_seen=True), "DAG-RT-07", GateOutcome.ESCALATE),
            (dict(retries_remaining=0, proj_admitted=False), "DAG-RT-08", GateOutcome.ESCALATE),
            (dict(hg_all_passed=False, hg_noncritical_failed=True), "DAG-RT-09", GateOutcome.REPLAN),
            (dict(proj_admitted=False), "DAG-RT-10", GateOutcome.REPLAN),
            (dict(proj_admitted=False, resolvable=False), "DAG-RT-11", GateOutcome.HOLD),
            (dict(trj_available=False, trj_reliability=None), "DAG-RT-12", GateOutcome.HOLD),
            (dict(trj_reliability=0.01), "DAG-RT-13", GateOutcome.REPLAN),
            (dict(trj_reliability=0.01, resolvable=False), "DAG-RT-14", GateOutcome.HOLD),
            (dict(impact_tier=ImpactTier.HIGH, residual_risk=0.99), "DAG-RT-15", GateOutcome.ESCALATE),
            (dict(residual_risk=0.99), "DAG-RT-16", GateOutcome.HOLD),
            ({}, "DAG-RT-17", GateOutcome.EXECUTE),
        ],
    )
    def test_each_row_is_reachable_with_minimal_inputs(self, over: dict, rule: str, outcome: GateOutcome) -> None:
        assert route(_inputs(**over), FakeRouting())[:2] == (outcome, rule)

    def test_impact_at_or_above_automation_ceiling_escalates(self) -> None:
        settings = FakeRouting(tier_automation_max=ImpactTier.MEDIUM)
        assert route(_inputs(impact_tier=ImpactTier.HIGH), settings)[:2] == (GateOutcome.ESCALATE, "DAG-RT-05")

    def test_placeholder_status_adds_marker_code_only_on_article14_row(self) -> None:
        _, _, codes = route(_inputs(article14_refused=True, article14_status="placeholder"), FakeRouting())
        assert "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD" in codes
        _, _, codes = route(_inputs(article14_refused=True, article14_status="calibrated"), FakeRouting())
        assert "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD" not in codes

    def test_hg02_style_failure_never_executes(self) -> None:
        # HG-02 FAIL (recompute incomplete): REPLAN if resolvable and budget remains, else HOLD/ESCALATE.
        for resolvable_, retries in ((True, 2), (False, 2), (True, 0)):
            i = _inputs(hg_all_passed=False, hg_noncritical_failed=True, resolvable=resolvable_, retries_remaining=retries)
            assert route(i, FakeRouting())[0] is not GateOutcome.EXECUTE
