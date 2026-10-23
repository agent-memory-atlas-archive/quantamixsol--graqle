"""CR-015 AC-21 (+ AC-23 report): a non-execute outcome revokes the cached grant (PR-015b)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from graqle.assurance import adapter
from graqle.assurance.adapter import NON_EXECUTE_HOOKS, VerdictStore, register_runtime, route_via_dag
from graqle.assurance.gate import ImpactTier, RoutingInputs, route
from graqle.assurance.outcomes import GateOutcome
from graqle.chat.permission_manager import PermissionDecision, PermissionManager
from graqle.core.governance import GateResult

from ._gate_fakes import CANDIDATE, FakeRouting, make_components, make_ctx, make_gate

_TOOL, _SCOPE, _SESSION = "graq_edit", "src/mod.py", "s1"


async def _grant(pm: PermissionManager) -> None:
    decision, pending = await pm.check(session_id=_SESSION, tool_name=_TOOL, resource_scope=_SCOPE, tier="YELLOW")
    assert decision is PermissionDecision.PROMPT and pending
    await pm.resolve(pending, PermissionDecision.APPROVE)
    again, _ = await pm.check(session_id=_SESSION, tool_name=_TOOL, resource_scope=_SCOPE, tier="YELLOW")
    assert again is PermissionDecision.APPROVE


async def _decision(pm: PermissionManager) -> PermissionDecision:
    got, _ = await pm.check(session_id=_SESSION, tool_name=_TOOL, resource_scope=_SCOPE, tier="YELLOW")
    return got


def _legacy() -> GateResult:
    return GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="ok")


@pytest.fixture(autouse=True)
def _clean() -> Any:
    register_runtime(None)
    NON_EXECUTE_HOOKS.clear()
    VerdictStore.clear()
    yield
    register_runtime(None)
    NON_EXECUTE_HOOKS.clear()
    VerdictStore.clear()


def _run_with(pm: PermissionManager, gate: Any) -> GateResult:
    ctx = make_ctx(permission_manager=pm, permission_scope=(_TOOL, _SCOPE))
    register_runtime(lambda *a, **k: (gate, ctx))
    return route_via_dag(object(), lambda **kw: _legacy(), risk_level="LOW", file_path=_SCOPE)  # type: ignore[arg-type]


class TestAC21Revocation:
    @pytest.mark.parametrize(
        "comps",
        [
            dict(may_automate=lambda _a, _t: False),  # ESCALATE
            dict(hard_gates=lambda _c, _x: ()),  # REJECT
            dict(estimator=type("E", (), {"estimate": lambda self, v: (_ for _ in ()).throw(RuntimeError)})()),  # ESCALATE
        ],
    )
    def test_non_execute_outcome_forces_a_fresh_prompt(self, comps: dict) -> None:
        pm = PermissionManager()

        async def scenario() -> PermissionDecision:
            await _grant(pm)
            await asyncio.get_running_loop().run_in_executor(
                None, lambda: _run_with(pm, make_gate(make_components(**comps)))
            )
            return await _decision(pm)

        assert asyncio.run(scenario()) is PermissionDecision.PROMPT

    def test_execute_keeps_the_grant(self) -> None:
        pm = PermissionManager()

        async def scenario() -> PermissionDecision:
            await _grant(pm)
            out = await asyncio.get_running_loop().run_in_executor(None, lambda: _run_with(pm, make_gate()))
            assert not out.blocked
            return await _decision(pm)

        assert asyncio.run(scenario()) is PermissionDecision.APPROVE

    def test_revoke_works_from_plain_sync_code_too(self) -> None:
        pm = PermissionManager()
        asyncio.run(_grant(pm))
        out = _run_with(pm, make_gate(make_components(may_automate=lambda _a, _t: False)))
        assert out.blocked
        assert asyncio.run(_decision(pm)) is PermissionDecision.PROMPT

    def test_revoke_failure_is_visible_and_still_blocks(self) -> None:
        class BrokenPm:
            async def revoke(self, **_k: Any) -> bool:
                raise RuntimeError("down")

        out = _run_with(BrokenPm(), make_gate(make_components(may_automate=lambda _a, _t: False)))  # type: ignore[arg-type]
        assert out.blocked and any("permission revoke failed" in w for w in out.warnings)

    def test_failing_hook_never_converts_a_block_into_a_pass(self) -> None:
        def bad_hook(ctx: Any, verdict: Any) -> None:
            raise RuntimeError("hook down")

        seen: list[str] = []
        NON_EXECUTE_HOOKS.extend([bad_hook, lambda ctx, v: seen.append(v.outcome.value)])
        out = _run_with(PermissionManager(), make_gate(make_components(may_automate=lambda _a, _t: False)))
        assert out.blocked and seen == ["ESCALATE"]
        assert any("non-execute hook failed" in w for w in out.warnings)

    def test_hooks_do_not_run_for_execute(self) -> None:
        seen: list[str] = []
        NON_EXECUTE_HOOKS.append(lambda ctx, v: seen.append("ran"))
        _run_with(PermissionManager(), make_gate())
        assert seen == []


class TestAC23Performance:
    """Reported, not asserted against wall-clock: CI hardware varies. Prints the measured P95."""

    def _p95(self, fn: Any, n: int) -> float:
        samples = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - t0)
        samples.sort()
        return samples[int(len(samples) * 0.95) - 1]

    def test_report_evaluate_and_route_p95(self, record_property: Any) -> None:
        gate = make_gate()
        ctx = make_ctx()
        eval_p95 = self._p95(lambda: gate.evaluate(CANDIDATE, ctx), 300)
        inputs = RoutingInputs(
            error_stages=(), hg_all_passed=True, hg_critical_failed=False, hg_noncritical_failed=False,
            cap_applied=False, proj_admitted=True, proj_score=0.9, cv_calibration_stale=False,
            cv_mandatory_na=False, trj_available=True, trj_reliability=0.9, authority_ok=True,
            impact_tier=ImpactTier.LOW, retries_remaining=2, fingerprint_seen=False,
            article14_refused=False, article14_status=None, resolvable=True, residual_risk=0.05,
        )
        settings = FakeRouting()
        route_p95 = self._p95(lambda: route(inputs, settings), 5000)
        record_property("evaluate_p95_ms", round(eval_p95 * 1000, 3))
        record_property("route_p95_us", round(route_p95 * 1e6, 3))
        print(f"AC-23 evaluate_p95_ms={eval_p95 * 1000:.3f} route_p95_us={route_p95 * 1e6:.3f}")
        assert route(inputs, settings)[0] is GateOutcome.EXECUTE
        assert adapter.VerdictStore is VerdictStore
