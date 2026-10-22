"""CR-015 PR-015c: AC-16 (RBAC), AC-17 (degraded), AC-18 (Article 14), AC-19 (queue + SLA)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from graqle.assurance.escalation import (
    EscalationRouter,
    JsonlEscalationQueue,
    MemoryEscalationQueue,
    ReviewPackage,
)
from graqle.assurance.escalation_settings import EscalationSettings
from graqle.assurance.gate import ImpactTier
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.settings import ConfigurationError
from graqle.compliance.article_14_gate import THRESHOLD_STATUS_PLACEHOLDER, Article14GateResult
from graqle.core.rbac import DAG_ESCALATE_TIER, ROLE_PERMISSIONS, Actor

from ._gate_fakes import CANDIDATE, make_components, make_ctx, make_gate

# Symbolic test deadlines; not deployment values.
SLA = {ImpactTier.LOW: 11, ImpactTier.MEDIUM: 12, ImpactTier.HIGH: 13, ImpactTier.CRITICAL: 14}
ROLES = {ImpactTier.LOW: "senior", ImpactTier.MEDIUM: "senior", ImpactTier.HIGH: "lead", ImpactTier.CRITICAL: "lead"}


def _settings(tmp_path: Path) -> EscalationSettings:
    return EscalationSettings(sla_seconds=SLA, role=ROLES, queue_path=tmp_path)


class Registry:
    def __init__(self, behaviour: str = "ok") -> None:
        self.behaviour = behaviour

    def list_actors(self) -> list[dict]:
        if self.behaviour == "raise":
            raise RuntimeError("registry down")
        if self.behaviour == "hang":
            time.sleep(5)
        return [
            Actor("sam", "senior").to_dict(),
            Actor("lee", "lead").to_dict(),
            {**Actor("off", "lead").to_dict(), "disabled": True},
            Actor("dev", "developer").to_dict(),
        ]


class BrokenQueue(MemoryEscalationQueue):
    def enqueue(self, pkg: ReviewPackage) -> None:
        raise OSError("queue down")


def _refused(status: str = THRESHOLD_STATUS_PLACEHOLDER) -> Article14GateResult:
    return Article14GateResult(allowed=False, confidence=0.1, threshold=0.5, threshold_status=status, reason="needs review")


def _escalate(router: EscalationRouter, article14: Any = None):
    gate = make_gate(make_components(escalation=router))
    ctx = make_ctx(article14=article14 or _refused())
    return gate.evaluate(CANDIDATE, ctx)


def _router(tmp_path: Path, queue: Any = None, registry: Any = None, **kw: Any) -> EscalationRouter:
    return EscalationRouter(
        _settings(tmp_path), queue if queue is not None else MemoryEscalationQueue(),
        registry or Registry(), rbac_timeout_ms=200, **kw,
    )


# ── AC-16 ────────────────────────────────────────────────────────────────────
def test_role_permissions_extension_is_additive() -> None:
    legacy = {
        "readonly": frozenset(), "developer": frozenset({"T1"}), "ci_pipeline": frozenset({"T1"}),
        "senior": frozenset({"T1", "T2"}), "lead": frozenset({"T1", "T2", "T3"}),
        "admin": frozenset({"T1", "T2", "T3"}),
    }
    assert set(ROLE_PERMISSIONS) == set(legacy)
    for role, tiers in legacy.items():
        assert ROLE_PERMISSIONS[role] - {DAG_ESCALATE_TIER} == tiers
        for tier in ("T1", "T2", "T3"):
            assert Actor("x", role).can_approve(tier) == (tier in tiers)
    holders = {r for r, p in ROLE_PERMISSIONS.items() if DAG_ESCALATE_TIER in p}
    assert holders == {"senior", "lead", "admin"}


# ── routing ──────────────────────────────────────────────────────────────────
def test_escalation_creates_package_for_eligible_role(tmp_path: Path) -> None:
    queue = MemoryEscalationQueue()
    v = _escalate(_router(tmp_path, queue))
    assert v.outcome is GateOutcome.ESCALATE
    [pkg] = queue.list_open()
    assert v.escalation.package_id == pkg.package_id
    assert pkg.route_to_role == ROLES[v.impact_tier] == v.escalation.route_to_role
    assert pkg.eligible_actor_ids and "dev" not in pkg.eligible_actor_ids and "off" not in pkg.eligible_actor_ids
    assert pkg.deadline_unix - pkg.created_unix == SLA[v.impact_tier] == pkg.sla_seconds
    assert pkg.verdict_id == v.verdict_id and pkg.rbac_degraded is False


# ── AC-17 ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("behaviour", ["raise", "hang"])
def test_rbac_failure_routes_to_admin_and_stays_escalate(tmp_path: Path, behaviour: str) -> None:
    queue = MemoryEscalationQueue()
    v = _escalate(_router(tmp_path, queue, Registry(behaviour)))
    [pkg] = queue.list_open()
    assert v.outcome is GateOutcome.ESCALATE
    assert pkg.rbac_degraded is True and pkg.route_to_role == "admin" and pkg.eligible_actor_ids == ()
    assert "DAG-TR-011-RBAC_UNAVAILABLE" in v.reason_codes
    assert v.escalation.route_to_role == "admin"


# ── AC-18 ────────────────────────────────────────────────────────────────────
def test_article14_envelope_and_status_propagate_verbatim(tmp_path: Path) -> None:
    queue = MemoryEscalationQueue()
    a14 = _refused()
    v = _escalate(_router(tmp_path, queue), a14)
    [pkg] = queue.list_open()
    assert pkg.article14_envelope == a14.to_refusal_envelope()
    assert pkg.threshold_status == THRESHOLD_STATUS_PLACEHOLDER
    assert "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD" in pkg.reason_codes
    assert "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD" in v.reason_codes


def test_non_placeholder_status_is_not_rewritten(tmp_path: Path) -> None:
    queue = MemoryEscalationQueue()
    _escalate(_router(tmp_path, queue), _refused("other-status"))
    [pkg] = queue.list_open()
    assert pkg.threshold_status == "other-status"
    assert "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD" not in pkg.reason_codes


def test_escalation_module_never_writes_the_calibrated_status() -> None:
    import graqle.assurance.escalation as mod

    assert "calibrated" not in Path(mod.__file__).read_text(encoding="utf-8").lower()


# ── AC-19 ────────────────────────────────────────────────────────────────────
def test_queue_failure_falls_back_to_jsonl_and_expires_after_sla(tmp_path: Path) -> None:
    now = [1_000.0]
    router = _router(tmp_path, BrokenQueue(), clock=lambda: now[0])
    v = _escalate(router)
    assert v.outcome is GateOutcome.ESCALATE
    assert "DAG-TR-009-ESCALATION_QUEUE_UNAVAILABLE" in v.reason_codes
    fallback = JsonlEscalationQueue(tmp_path)
    [pkg] = fallback.list_open(v.escalation.route_to_role)
    assert pkg.package_id == v.escalation.package_id
    assert "DAG-TR-009-ESCALATION_QUEUE_UNAVAILABLE" in pkg.reason_codes
    assert fallback.expire_overdue(pkg.deadline_unix - 1) == []
    assert fallback.expire_overdue(pkg.deadline_unix) == [pkg.package_id]
    assert fallback.list_open() == []
    assert JsonlEscalationQueue(tmp_path).list_open() == []  # replayed from disk


def test_fallback_failure_keeps_escalate_with_an_error(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    settings = EscalationSettings(sla_seconds=SLA, role=ROLES, queue_path=blocker)  # not a directory
    router = EscalationRouter(settings, BrokenQueue(), Registry(), rbac_timeout_ms=200)
    v = _escalate(router)
    assert v.outcome is GateOutcome.ESCALATE
    assert v.verdict.evaluation_errors


# ── queue state machine ──────────────────────────────────────────────────────
@pytest.mark.parametrize("factory", [lambda p: MemoryEscalationQueue(), lambda p: JsonlEscalationQueue(p)])
def test_ack_and_resolve_require_an_eligible_actor(tmp_path: Path, factory: Any) -> None:
    queue = factory(tmp_path)
    v = _escalate(_router(tmp_path, queue))
    pid = v.escalation.package_id
    role = v.escalation.route_to_role
    eligible = queue.list_open(role)[0].eligible_actor_ids[0]
    assert queue.ack(pid, "dev") is False
    assert queue.resolve(pid, "dev", "approve_execute", "why") is False
    assert queue.resolve(pid, eligible, "not-a-decision", "why") is False
    assert queue.resolve(pid, eligible, "defer", "  ") is False
    assert queue.ack(pid, eligible) is True and queue.ack(pid, eligible) is False
    assert queue.list_open(role)[0].status == "ACKED"
    assert queue.resolve(pid, eligible, "reject", "unsafe") is True
    assert queue.list_open() == [] and queue.resolve(pid, eligible, "reject", "again") is False
    assert queue.ack("missing", eligible) is False


def test_jsonl_skips_a_malformed_line(tmp_path: Path) -> None:
    queue = JsonlEscalationQueue(tmp_path)
    _escalate(_router(tmp_path, queue))
    with (tmp_path / "escalations.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    assert len(JsonlEscalationQueue(tmp_path).list_open()) == 1


def test_evidence_provider_failure_still_routes(tmp_path: Path) -> None:
    def boom(*_a: Any) -> Any:
        raise RuntimeError("graph down")

    queue = MemoryEscalationQueue()
    v = _escalate(_router(tmp_path, queue, evidence_provider=boom))
    [pkg] = queue.list_open()
    assert pkg.evidence == () and "DAG-TR-010-EVALUATION_ERROR" in pkg.reason_codes
    assert v.outcome is GateOutcome.ESCALATE


def test_router_rejects_non_positive_rbac_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        EscalationRouter(_settings(tmp_path), MemoryEscalationQueue(), Registry(), rbac_timeout_ms=0)


# ── settings ─────────────────────────────────────────────────────────────────
def _env() -> dict[str, str]:
    return {f"GRAQLE_DAG_ESCALATION_SLA_{t.value}_SECONDS": str(s) for t, s in SLA.items()}


def test_settings_from_env_defaults_roles_and_queue() -> None:
    s = EscalationSettings.from_env(_env())
    assert s.role == ROLES and s.queue == "jsonl" and s.sla_seconds == SLA


def test_settings_missing_or_zero_sla_fails_closed() -> None:
    env = _env()
    del env["GRAQLE_DAG_ESCALATION_SLA_HIGH_SECONDS"]
    with pytest.raises(ConfigurationError):
        EscalationSettings.from_env(env)
    for bad in ("0", "-5", "abc"):
        env["GRAQLE_DAG_ESCALATION_SLA_HIGH_SECONDS"] = bad
        with pytest.raises(ConfigurationError):
            EscalationSettings.from_env(env)


def test_settings_role_must_hold_dag_escalate() -> None:
    env = {**_env(), "GRAQLE_DAG_ESCALATION_ROLE_LOW": "developer"}
    with pytest.raises(ConfigurationError):
        EscalationSettings.from_env(env)
    with pytest.raises(ConfigurationError):
        EscalationSettings.from_env({**_env(), "GRAQLE_DAG_ESCALATION_QUEUE": "carrier-pigeon"})
