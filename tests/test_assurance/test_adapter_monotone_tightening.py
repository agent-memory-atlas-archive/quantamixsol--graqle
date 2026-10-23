"""CR-015 AC-11, AC-12 and the adapter's fail-closed paths (PR-015b)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from graqle.assurance import adapter
from graqle.assurance.adapter import VerdictStore, register_runtime, route_via_dag, to_gate_result
from graqle.assurance.gate import DagVerdict
from graqle.assurance.outcomes import GateOutcome
from graqle.core.governance import GateResult, GovernanceConfig, GovernanceMiddleware

from ._gate_fakes import make_components, make_ctx, make_gate

_GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "gate_result_golden_v0830.json"
_TIER = {"T1": 0, "T2": 1, "T3": 2, "TS-BLOCK": 3}


def _dag_verdict(outcome: GateOutcome) -> DagVerdict:
    base = DagVerdict.failed_closed("seed")
    return DagVerdict(
        base.verdict.model_copy(update={"outcome": outcome, "evaluation_errors": [], "decisive_rule": "DAG-RT-17"}),
        base.verdict_id, base.fingerprint, base.impact_tier, "summary",
    )


def _legacy_cases() -> list[GateResult]:
    cases = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    return [GateResult(**c["out"]) for c in cases]


@pytest.fixture(autouse=True)
def _clean() -> Any:
    register_runtime(None)
    VerdictStore.clear()
    GovernanceMiddleware._cumulative.clear()
    yield
    register_runtime(None)
    VerdictStore.clear()


class TestAC11MonotoneTightening:
    def test_final_is_never_less_restrictive_than_legacy(self) -> None:
        legacy_cases = _legacy_cases()
        assert len(legacy_cases) >= 40
        for legacy in legacy_cases:
            for outcome in GateOutcome:
                final = to_gate_result(legacy, _dag_verdict(outcome))
                assert _TIER[final.tier] >= _TIER[legacy.tier]
                assert final.blocked or not legacy.blocked
                assert final.requires_approval or not legacy.requires_approval
                assert legacy.bypass_allowed or not final.bypass_allowed
                assert final.gate_score == legacy.gate_score
                assert final.warnings[: len(legacy.warnings)] == legacy.warnings
                assert final.warnings[len(legacy.warnings)].startswith("[DAG]")

    def test_execute_leaves_the_legacy_decision_unchanged(self) -> None:
        for legacy in _legacy_cases():
            final = to_gate_result(legacy, _dag_verdict(GateOutcome.EXECUTE))
            assert (final.tier, final.blocked, final.requires_approval, final.bypass_allowed) == (
                legacy.tier, legacy.blocked, legacy.requires_approval, legacy.bypass_allowed)

    @pytest.mark.parametrize("outcome", [GateOutcome.HOLD, GateOutcome.REPLAN, GateOutcome.REJECT, GateOutcome.ESCALATE])
    def test_non_execute_outcomes_block_a_clean_legacy_pass(self, outcome: GateOutcome) -> None:
        legacy = GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="ok")
        final = to_gate_result(legacy, _dag_verdict(outcome))
        assert final.blocked and not final.bypass_allowed

    def test_legacy_reason_kept_when_legacy_tier_is_stricter(self) -> None:
        legacy = GateResult(tier="T3", blocked=True, requires_approval=True, gate_score=0.9, reason="legacy says no")
        assert to_gate_result(legacy, _dag_verdict(GateOutcome.HOLD)).reason == "legacy says no"


class TestAC12TsBlockUntouched:
    def test_ts_block_is_returned_as_is_and_dag_not_invoked(self) -> None:
        legacy = GateResult(tier="TS-BLOCK", blocked=True, requires_approval=False, gate_score=1.0, reason="TS")
        calls: list[str] = []
        register_runtime(lambda *a, **k: calls.append("built") or (_ for _ in ()).throw(AssertionError))
        out = route_via_dag(object(), lambda **kw: legacy, diff="x")  # type: ignore[arg-type]
        assert out is legacy and calls == []


class TestFailClosed:
    def test_no_runtime_registered_blocks_at_t3_requiring_approval(self) -> None:
        legacy = GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="ok")
        out = route_via_dag(object(), lambda **kw: legacy, diff="x")  # type: ignore[arg-type]
        assert out.blocked and out.tier == "T3" and out.requires_approval and not out.bypass_allowed
        assert any("outcome=ESCALATE" in w for w in out.warnings)

    def test_runtime_provider_exception_blocks(self) -> None:
        def provider(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("config missing")

        register_runtime(provider)
        legacy = GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="ok")
        out = route_via_dag(object(), lambda **kw: legacy)  # type: ignore[arg-type]
        assert out.blocked and out.tier == "T3"

    def test_verdict_store_failure_does_not_change_the_decision(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(VerdictStore, "put", classmethod(lambda cls, v: (_ for _ in ()).throw(RuntimeError)))
        legacy = GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="ok")
        out = route_via_dag(object(), lambda **kw: legacy)  # type: ignore[arg-type]
        assert out.blocked

    def test_dry_run_relaxes_hold_but_never_reject_or_escalate(self) -> None:
        policy = type("P", (), {"dry_run": True})()
        mw = type("MW", (), {"_policy": policy})()
        legacy = GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="ok")

        def provider_for(outcome: GateOutcome) -> Any:
            class G:
                def evaluate(self, cand: Any, ctx: Any) -> DagVerdict:
                    return _dag_verdict(outcome)

            return lambda *a, **k: (G(), make_ctx())

        for outcome, relaxed in ((GateOutcome.HOLD, True), (GateOutcome.REPLAN, True),
                                 (GateOutcome.REJECT, False), (GateOutcome.ESCALATE, False)):
            register_runtime(provider_for(outcome))
            out = route_via_dag(mw, lambda **kw: legacy)  # type: ignore[arg-type]
            assert out.blocked is (not relaxed), outcome


class TestVerdictStore:
    def test_lru_evicts_oldest_and_get_refreshes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GRAQLE_DAG_VERDICT_STORE_SIZE", "2")
        a, b, c = (DagVerdict.failed_closed(x) for x in "abc")
        VerdictStore.put(a)
        VerdictStore.put(b)
        assert VerdictStore.get(a.verdict_id) is a  # refresh a
        VerdictStore.put(c)
        assert VerdictStore.get(b.verdict_id) is None and VerdictStore.get(a.verdict_id) is a

    @pytest.mark.parametrize("raw", ["0", "-3", "abc"])
    def test_unusable_size_falls_back_to_safe_default(self, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
        monkeypatch.setenv("GRAQLE_DAG_VERDICT_STORE_SIZE", raw)
        assert adapter._store_capacity() > 0


class TestFlagOnEndToEnd:
    def test_check_routes_through_the_gate_and_stores_the_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
        gate = make_gate(make_components(may_automate=lambda _a, _t: False))
        register_runtime(lambda *a, **k: (gate, make_ctx()))
        GovernanceMiddleware._state_loaded = True
        mw = GovernanceMiddleware(config=GovernanceConfig())
        out = mw.check(diff="+ x = 1", file_path="src/mod.py", risk_level="LOW", actor="alice")
        assert out.blocked and out.tier == "T3" and out.requires_approval
        vid = next(w for w in out.warnings if w.startswith("[DAG] outcome=")).split("verdict_id=")[1].split()[0]
        stored = VerdictStore.get(vid)
        assert stored is not None and stored.outcome is GateOutcome.ESCALATE

    def test_execute_leaves_a_low_risk_pass_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
        register_runtime(lambda *a, **k: (make_gate(), make_ctx()))
        GovernanceMiddleware._state_loaded = True
        mw = GovernanceMiddleware(config=GovernanceConfig())
        out = mw.check(diff="+ x = 1", file_path="src/mod.py", risk_level="LOW", actor="alice")
        assert not out.blocked and out.tier == "T1"
