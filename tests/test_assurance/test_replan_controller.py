"""CR-015 PR-015c: AC-14 (fingerprint), AC-15 (circuit breaker), AC-20 (provenance linearity)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from graqle.assurance.gate import ProjectionStageResult, fingerprint
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.replan import ReplanController, ReplanState

from ._gate_fakes import CANDIDATE, make_components, make_ctx, make_gate

_codes = st.lists(st.text(alphabet="ABCDEF-0123", min_size=1, max_size=8), max_size=6)


@given(codes=_codes, nodes=_codes)
def test_fingerprint_order_invariant(codes: list[str], nodes: list[str]) -> None:
    base = fingerprint("DAG-RT-10", codes, nodes)
    assert fingerprint("DAG-RT-10", list(reversed(codes)), list(reversed(nodes))) == base
    assert fingerprint("DAG-RT-10", codes + codes, nodes + nodes) == base


@given(codes=_codes, nodes=_codes)
def test_fingerprint_sensitive_to_decisive_rule(codes: list[str], nodes: list[str]) -> None:
    assert fingerprint("DAG-RT-10", codes, nodes) != fingerprint("DAG-RT-13", codes, nodes)


class ChainEmitter:
    """CR-018 emitter stub: assigns sequence and previous-event hash like the real chain."""

    def __init__(self, fail: bool = False) -> None:
        self.events: list[dict[str, Any]] = []
        self.fail = fail

    def append(self, *, kind: str, subject_id: str, payload: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("emitter down")
        prev = self.events[-1]["hash"] if self.events else "0" * 64
        seq = len(self.events)
        body = json.dumps(
            {"kind": kind, "subject": subject_id, "payload": payload, "seq": seq, "prev": prev}, sort_keys=True
        )
        self.events.append(
            {"kind": kind, "subject": subject_id, "seq": seq, "prev": prev,
             "hash": hashlib.sha256(body.encode()).hexdigest(), "payload": payload}
        )


class StubPlanner:
    """Re-submits the candidate; ``vary`` changes the implicated nodes on every attempt."""

    def __init__(self, vary: bool) -> None:
        self.vary, self.calls = vary, 0

    def projection(self, _c: Any, _x: Any, _r: Any, _cap: Any) -> ProjectionStageResult:
        self.calls += 1
        nodes = (f"node-{self.calls}",) if self.vary else ("node-0",)
        return ProjectionStageResult(
            admitted=False, decision_score=0.2, calibration_stale=False, mandatory_na=False,
            reason_codes=("DAG-CV-005-BELOW_POLICY_THRESHOLD",), implicated_nodes=nodes,
        )


def _run(planner: StubPlanner, budget: int, emitter: ChainEmitter | None = None):
    replan = ReplanController(max_retry_budget=budget, emitter=emitter)
    gate = make_gate(make_components(projection=planner.projection, replan=replan), budget=budget)
    ctx = make_ctx(replan_state=ReplanState(root_candidate_id="root-1"))
    verdicts = []
    while True:
        v = gate.evaluate(CANDIDATE, ctx)
        verdicts.append(v)
        if v.outcome is not GateOutcome.REPLAN:
            return verdicts, ctx
        assert len(verdicts) <= budget + 1, "loop exceeded B_MAX + 1 evaluations"


def test_unchanged_reason_escalates_on_second_replan() -> None:
    verdicts, _ = _run(StubPlanner(vary=False), budget=5)
    assert [v.outcome for v in verdicts] == [GateOutcome.REPLAN, GateOutcome.ESCALATE]
    assert "DAG-TR-002-UNCHANGED_REASON_DETECTED" in verdicts[-1].reason_codes


def test_budget_exhaustion_escalates_with_tr001() -> None:
    budget = 2
    planner = StubPlanner(vary=True)
    verdicts, ctx = _run(planner, budget=budget)
    assert len(verdicts) <= budget + 1
    assert verdicts[-1].outcome is GateOutcome.ESCALATE
    assert "DAG-TR-001-RETRY_BUDGET_EXHAUSTED" in verdicts[-1].reason_codes
    assert ctx.replan_state.attempts == budget


def test_replan_context_reaches_the_planner() -> None:
    verdicts, _ = _run(StubPlanner(vary=True), budget=3)
    rc = verdicts[0].replan_context
    assert rc.attempt == 1 and rc.budget_remaining == 2
    assert rc.root_candidate_id == "root-1" and rc.fingerprint == verdicts[0].fingerprint
    assert rc.prior_fingerprints == ()
    assert verdicts[1].replan_context.prior_fingerprints == (verdicts[0].fingerprint,)


def test_provenance_chain_is_linear() -> None:
    emitter = ChainEmitter()
    verdicts, _ = _run(StubPlanner(vary=True), budget=3, emitter=emitter)
    replans = [e for e in emitter.events if e["kind"] == "REPLAN"]
    assert len(replans) == sum(1 for v in verdicts if v.outcome is GateOutcome.REPLAN) == 3
    assert [e["seq"] for e in emitter.events] == list(range(len(emitter.events)))
    for prev, cur in zip(emitter.events, emitter.events[1:]):
        assert cur["prev"] == prev["hash"]
    assert len({e["prev"] for e in emitter.events}) == len(emitter.events)  # no shared predecessor


def test_emitter_failure_escalates_and_does_not_spend_budget() -> None:
    planner = StubPlanner(vary=True)
    replan = ReplanController(max_retry_budget=3, emitter=ChainEmitter(fail=True))
    gate = make_gate(make_components(projection=planner.projection, replan=replan), budget=3)
    ctx = make_ctx(replan_state=ReplanState(root_candidate_id="root-1"))
    v = gate.evaluate(CANDIDATE, ctx)
    assert v.outcome is GateOutcome.ESCALATE
    assert ctx.replan_state.attempts == 0


def test_missing_root_candidate_fails_closed() -> None:
    planner = StubPlanner(vary=True)
    gate = make_gate(make_components(projection=planner.projection, replan=ReplanController(3)), budget=3)
    v = gate.evaluate(CANDIDATE, make_ctx())  # default state has no root id
    assert v.outcome is GateOutcome.ESCALATE


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_budget_must_be_positive_int(bad: Any) -> None:
    with pytest.raises(ValueError):
        ReplanController(max_retry_budget=bad)


def test_non_replan_verdict_never_passes_through() -> None:
    planner = StubPlanner(vary=True)
    gate = make_gate(make_components(projection=planner.projection, replan=ReplanController(3)), budget=3)
    first = gate.evaluate(CANDIDATE, make_ctx(replan_state=ReplanState(root_candidate_id="r")))
    out = ReplanController(3).on_replan(first.downgraded(GateOutcome.HOLD, rule="DAG-RT-11"), make_ctx())
    assert out.outcome is GateOutcome.ESCALATE
