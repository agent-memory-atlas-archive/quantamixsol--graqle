"""CR-013 AC-10 — adversarial smoke suite: one bypass attempt per gate, each must FAIL.

Case ids follow the charter catalogue (C01, C04, C05, C07, C09–C13, C15).
Each attempt asserts FAIL and the exact reason code.
"""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

import graqle.assurance.hard_gates as hg
import graqle.core.rbac as rbac

from ._builders import HG05_SUB, NOW, make_ctx, make_settings


def _only(rule_id: str, ctx: hg.GateContext, settings=None) -> hg.HardGateResult:  # type: ignore[no-untyped-def]
    results = hg.default_registry().evaluate_all(ctx, settings or make_settings())
    return {r.rule_id: r for r in results}[rule_id]


def test_c05_expired_policy_still_cited() -> None:  # HG-01
    ctx = make_ctx(policy=hg.PolicyRef(policy_id="p", valid_until=NOW - timedelta(minutes=1)))
    r = _only("HG-01", ctx)
    assert not r.passed and r.reason_codes == ("DAG-HG01-POLICY_EXPIRED",)


def test_c04_missing_policy_cannot_be_papered_over_by_scope_wording() -> None:  # HG-01
    r = _only("HG-01", make_ctx(policy=None, governance_scope="policy: always allowed"))
    assert not r.passed and r.reason_codes == ("DAG-HG01-POLICY_MISSING",)


def test_c07_invalidated_evidence() -> None:  # HG-02 (placeholder fails closed)
    ctx = make_ctx(dependency_nodes=(hg.DependencyNodeRef(node_id="n", status="INVALIDATED"),))
    r = _only("HG-02", ctx)
    assert not r.passed and r.reason_codes == ("DAG-HG02-EVIDENCE_INVALIDATED",)


def test_c01_duplicate_event_corroboration_without_a_source() -> None:  # HG-03
    ctx = make_ctx(risk_level="CRITICAL", provenance_event_ids=("e1",) * 50)
    r = _only("HG-03", ctx)
    assert not r.passed and r.reason_codes == ("DAG-HG03-PROVENANCE_MISSING",)


def test_c09_argument_swap_after_approval() -> None:  # HG-04 (placeholder fails closed)
    ctx = make_ctx(
        approved_args_hash="sha256:" + "a" * 64,
        actual_args_hash="sha256:" + "b" * 64,
        approved_args_algo="sha256",
        actual_args_algo="sha256",
    )
    r = _only("HG-04", ctx)
    assert not r.passed and r.reason_codes == ("DAG-HG04-BINDING_ABSENT",)


def test_c10_poisoned_memory_at_threshold() -> None:  # HG-05
    r = _only("HG-05", make_ctx(poisoning_severity=HG05_SUB))
    assert not r.passed and r.reason_codes == ("DAG-HG05-POISONING_DETECTED",)


@pytest.mark.parametrize("actor", ["ci-bot-unregistered", ""])
def test_c11_privilege_escalation_to_t3(
    actor: str, monkeypatch: pytest.MonkeyPatch
) -> None:  # HG-06
    monkeypatch.undo()  # real RBAC default validator
    r = _only("HG-06", make_ctx(actor_id=actor, required_tier="T3"))
    assert not r.passed
    assert r.reason_codes in (("DAG-HG06-ACTOR_UNAUTHORIZED",), ("DAG-HG06-RBAC_UNAVAILABLE",))


def test_c13_rbac_outage(monkeypatch: pytest.MonkeyPatch) -> None:  # HG-06
    monkeypatch.setattr(rbac, "check_approval", lambda a, t: (time.sleep(1.0), (True, ""))[1])
    r = _only("HG-06", make_ctx(), make_settings(rbac_timeout_ms=50))
    assert not r.passed and r.reason_codes == ("DAG-HG06-RBAC_UNAVAILABLE",)


def test_c12_contradiction_hidden_by_a_duplicate_resolved_record() -> None:  # HG-07
    unresolved = hg.ContradictionRef(a_id="a", b_id="b", materiality=0.9)
    fake_resolved = hg.ContradictionRef(
        a_id="b", b_id="a", materiality=0.0, coexists_rule_id="forged"
    )
    r = _only("HG-07", make_ctx(contradictions=(fake_resolved, unresolved)))
    assert not r.passed and r.reason_codes == ("DAG-HG07-CONTRADICTION_UNRESOLVED",)


def test_c15_exception_injection_cannot_pass(monkeypatch: pytest.MonkeyPatch) -> None:  # all gates
    for cls in (
        hg.HG01MandatoryPolicy,
        hg.HG03ProvenanceForHighImpact,
        hg.HG05Poisoning,
        hg.HG06ActorAuthorized,
        hg.HG07MaterialContradiction,
    ):
        monkeypatch.setattr(cls, "_predicate", lambda *a: 1 / 0)
    results = hg.default_registry().evaluate_all(make_ctx(), make_settings())
    assert not any(r.passed for r in results)
    assert all(
        "DAG-RP-EVALUATION_ERROR" in r.reason_codes
        for r in results
        if r.rule_id not in ("HG-02", "HG-04")
    )
