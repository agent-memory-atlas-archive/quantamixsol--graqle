"""Escalation routing: review package, RBAC-bound routing, SLA queue (CR-015 PR-015c).

An ESCALATE verdict becomes a :class:`ReviewPackage` routed to a role that holds the
DAG-ESCALATE permission, enqueued with a per-tier deadline.

Fail closed throughout:

* if reviewer eligibility cannot be resolved within the RBAC bound (timeout or any
  error) the package goes to ``admin`` with ``rbac_degraded=True`` (DAG-TR-011);
* if the configured queue rejects the package it is written to the local JSONL
  fallback (DAG-TR-009); if that also fails the error propagates and the gate keeps
  the ESCALATE verdict with an evaluation error;
* the verdict stays ESCALATE in every case -- this module never produces EXECUTE.

The Article 14 refusal envelope and ``threshold_status`` are propagated verbatim and
never rewritten.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.escalation
# risk: MEDIUM (impact radius: 0 existing callers -- consumed by the gate via GateComponents.escalation)
# dependencies: dataclasses, json, threading, time, uuid, pydantic, graqle.assurance.gate, graqle.assurance.reason_codes
# constraints: never imported by graqle.governance.*; threshold status is propagated, never set here
# -- /graqle:intelligence --
import dataclasses
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from graqle.assurance.escalation_settings import EscalationSettings
from graqle.assurance.gate import DagVerdict, EvaluationContext, GateCandidate, ImpactTier
from graqle.assurance.reason_codes import REGISTRY, Severity

logger = logging.getLogger(__name__)

__all__ = [
    "EscalationQueue",
    "EscalationRef",
    "EscalationRouter",
    "JsonlEscalationQueue",
    "MemoryEscalationQueue",
    "ReviewPackage",
    "run_with_timeout",
]

_CODE_QUEUE = "DAG-TR-009-ESCALATION_QUEUE_UNAVAILABLE"
_CODE_RBAC = "DAG-TR-011-RBAC_UNAVAILABLE"
_CODE_PLACEHOLDER = "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD"
_CODE_ERROR = "DAG-TR-010-EVALUATION_ERROR"
_DEGRADED_ROLE = "admin"
_DECISIONS = frozenset({"approve_execute", "approve_replan", "reject", "defer"})
_JSONL_NAME = "escalations.jsonl"


class ReviewPackage(BaseModel):
    """Everything a human reviewer needs to decide an escalated candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package_id: str
    verdict_id: str
    candidate_id: str
    session_id: str
    created_unix: float
    deadline_unix: float
    sla_seconds: int
    impact_tier: ImpactTier
    route_to_role: str
    eligible_actor_ids: tuple[str, ...]
    evidence: tuple[dict, ...]  # public views only
    alternatives: tuple[str, ...]
    risks: tuple[dict, ...]  # {code, severity, remediation_hint}
    requested_decision: Literal["approve_execute", "approve_replan", "reject", "defer"]
    reason_codes: tuple[str, ...]
    article14_envelope: dict | None = None  # Article14GateResult.to_refusal_envelope() verbatim
    threshold_status: str | None = None  # propagated, never rewritten
    rbac_degraded: bool = False  # DAG-TR-011
    status: Literal["OPEN", "ACKED", "RESOLVED", "EXPIRED"] = "OPEN"


@dataclasses.dataclass(frozen=True)
class EscalationRef:
    """What the adapter reads from ``DagVerdict.escalation``."""

    package_id: str
    route_to_role: str
    deadline_unix: float


class EscalationQueue(Protocol):
    def enqueue(self, pkg: ReviewPackage) -> None: ...
    def ack(self, package_id: str, actor_id: str) -> bool: ...
    def resolve(self, package_id: str, actor_id: str, decision: str, justification: str) -> bool: ...
    def list_open(self, role: str | None = None) -> list[ReviewPackage]: ...
    def expire_overdue(self, now_unix: float) -> list[str]: ...


class _EventQueue:
    """Shared state machine over an ordered event log; subclasses persist the events."""

    def __init__(self) -> None:
        self._lock = threading.RLock()

    # -- persistence hooks --------------------------------------------------
    def _append(self, event: dict[str, Any]) -> None:
        raise NotImplementedError

    def _events(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    # -- state --------------------------------------------------------------
    def _state(self) -> dict[str, ReviewPackage]:
        out: dict[str, ReviewPackage] = {}
        for ev in self._events():
            kind = ev.get("event")
            if kind == "enqueue":
                pkg = ReviewPackage.model_validate(ev["package"])
                out[pkg.package_id] = pkg
                continue
            pkg = out.get(ev.get("package_id", ""))
            if pkg is None:
                continue
            status = {"ack": "ACKED", "resolve": "RESOLVED", "expire": "EXPIRED"}.get(kind or "")
            if status is not None:
                out[pkg.package_id] = pkg.model_copy(update={"status": status})
        return out

    # -- queue API ----------------------------------------------------------
    def enqueue(self, pkg: ReviewPackage) -> None:
        with self._lock:
            if pkg.package_id in self._state():
                raise ValueError("duplicate package_id")
            self._append({"event": "enqueue", "package": pkg.model_dump(mode="json")})

    def ack(self, package_id: str, actor_id: str) -> bool:
        with self._lock:
            pkg = self._state().get(package_id)
            if pkg is None or pkg.status != "OPEN" or actor_id not in pkg.eligible_actor_ids:
                return False
            self._append({"event": "ack", "package_id": package_id, "actor_id": actor_id, "ts": time.time()})
            return True

    def resolve(self, package_id: str, actor_id: str, decision: str, justification: str) -> bool:
        if decision not in _DECISIONS or not justification.strip():
            return False
        with self._lock:
            pkg = self._state().get(package_id)
            if pkg is None or pkg.status not in ("OPEN", "ACKED") or actor_id not in pkg.eligible_actor_ids:
                return False
            self._append({
                "event": "resolve", "package_id": package_id, "actor_id": actor_id,
                "decision": decision, "justification": justification, "ts": time.time(),
            })
            return True

    def list_open(self, role: str | None = None) -> list[ReviewPackage]:
        with self._lock:
            return [
                p for p in self._state().values()
                if p.status in ("OPEN", "ACKED") and (role is None or p.route_to_role == role)
            ]

    def expire_overdue(self, now_unix: float) -> list[str]:
        with self._lock:
            expired = [
                p.package_id for p in self._state().values()
                if p.status in ("OPEN", "ACKED") and p.deadline_unix <= now_unix
            ]
            for package_id in expired:
                self._append({"event": "expire", "package_id": package_id, "ts": now_unix})
            return expired


class MemoryEscalationQueue(_EventQueue):
    """In-process queue (tests, single-process deployments)."""

    def __init__(self) -> None:
        super().__init__()
        self._log: list[dict[str, Any]] = []

    def _append(self, event: dict[str, Any]) -> None:
        self._log.append(event)

    def _events(self) -> list[dict[str, Any]]:
        return list(self._log)


class JsonlEscalationQueue(_EventQueue):
    """Append-only JSONL event log under ``directory``; state is replayed on read.

    Single-process safe (a lock serialises read-modify-append); a malformed line is
    skipped with a warning rather than hiding every other package.
    """

    def __init__(self, directory: Path | str) -> None:
        super().__init__()
        self._path = Path(directory) / _JSONL_NAME

    def _append(self, event: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    def _events(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    logger.warning("escalation log %s: skipping malformed line %d", self._path.name, number)
                    continue
                if isinstance(ev, dict):
                    events.append(ev)
        return events


def run_with_timeout(timeout_ms: int, fn: Callable[[], Any]) -> Any:
    """Run ``fn`` on a daemon thread bounded by ``timeout_ms``.

    Raises ``TimeoutError`` on expiry and re-raises whatever ``fn`` raised. A hung
    callee can neither block past the deadline nor block interpreter shutdown.
    """
    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # surfaced to the caller below
            box["error"] = exc

    thread = threading.Thread(target=_call, name="dag-escalation-rbac", daemon=True)
    thread.start()
    thread.join(timeout_ms / 1000.0)
    if thread.is_alive():
        raise TimeoutError("operation exceeded its deadline")
    if "error" in box:
        raise box["error"]
    return box.get("result")


def _risk_view(code: str) -> dict[str, str]:
    rc = REGISTRY.get(code)
    if rc is None:
        return {"code": code, "severity": "UNREGISTERED", "remediation_hint": ""}
    return {"code": code, "severity": rc.severity.value, "remediation_hint": rc.remediation_hint}


class EscalationRouter:
    """Implements ``GateComponents.escalation`` (``route(verdict, candidate, ctx) -> verdict``)."""

    def __init__(
        self,
        settings: EscalationSettings,
        queue: EscalationQueue,
        actor_registry: Any,
        rbac_timeout_ms: int,
        *,
        evidence_provider: Callable[[GateCandidate, EvaluationContext], Iterable[dict]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if isinstance(rbac_timeout_ms, bool) or rbac_timeout_ms <= 0:
            raise ValueError("rbac_timeout_ms must be a positive integer")
        self._settings = settings
        self._queue = queue
        self._actors = actor_registry
        self._rbac_timeout_ms = rbac_timeout_ms
        self._evidence = evidence_provider
        self._clock = clock

    def route(self, verdict: DagVerdict, candidate: GateCandidate, ctx: EvaluationContext) -> DagVerdict:
        from graqle.core.rbac import DAG_ESCALATE_TIER, ROLE_PERMISSIONS  # lazy: stdlib leaf

        tier = verdict.impact_tier
        codes = list(verdict.reason_codes)
        role = self._settings.role[tier]
        degraded = False
        try:
            eligible = tuple(
                run_with_timeout(
                    self._rbac_timeout_ms,
                    lambda: [
                        a["actor_id"] for a in self._actors.list_actors()
                        if a["role"] == role
                        and DAG_ESCALATE_TIER in ROLE_PERMISSIONS.get(a["role"], frozenset())
                        and not a["disabled"]
                    ],
                )
            )
        except Exception:  # timeout or registry failure: fail-closed routing
            eligible, degraded, role = (), True, _DEGRADED_ROLE
            codes.append(_CODE_RBAC)

        a14 = ctx.article14
        envelope = a14.to_refusal_envelope() if (a14 is not None and not a14.allowed) else None
        status = a14.threshold_status if a14 is not None else None  # propagated verbatim
        if status is not None and _CODE_PLACEHOLDER in REGISTRY and _is_placeholder(status):
            if _CODE_PLACEHOLDER not in codes:
                codes.append(_CODE_PLACEHOLDER)

        evidence: tuple[dict, ...] = ()
        if self._evidence is not None:
            try:
                evidence = tuple(self._evidence(candidate, ctx))
            except Exception:
                codes.append(_CODE_ERROR)  # the package still reaches a human, without evidence

        codes = list(dict.fromkeys(codes))
        now = self._clock()
        sla = self._settings.sla_seconds[tier]
        pkg = ReviewPackage(
            package_id="pkg_" + uuid.uuid4().hex,
            verdict_id=verdict.verdict_id,
            candidate_id=candidate.id,
            session_id=ctx.session_id,
            created_unix=now,
            deadline_unix=now + sla,
            sla_seconds=sla,
            impact_tier=tier,
            route_to_role=role,
            eligible_actor_ids=eligible,
            evidence=evidence,
            alternatives=tuple(ctx.alternatives),
            risks=tuple(_risk_view(c) for c in codes),
            requested_decision=_requested_decision(codes),
            reason_codes=tuple(codes),
            article14_envelope=envelope,
            threshold_status=status,
            rbac_degraded=degraded,
        )
        try:
            self._queue.enqueue(pkg)
        except Exception as exc:
            # Local fallback; if it also fails the error propagates and the gate keeps
            # ESCALATE with an evaluation error.
            logger.warning("escalation queue enqueue failed (%s); using local JSONL fallback", type(exc).__name__)
            codes.append(_CODE_QUEUE)
            pkg = pkg.model_copy(update={
                "reason_codes": tuple(codes),
                "risks": tuple(_risk_view(c) for c in codes),
            })
            JsonlEscalationQueue(self._settings.queue_path).enqueue(pkg)
        out = verdict
        for code in dict.fromkeys(codes):
            out = out.with_reason_code(code)
        return dataclasses.replace(
            out,
            escalation=EscalationRef(package_id=pkg.package_id, route_to_role=role, deadline_unix=pkg.deadline_unix),
        )


def _is_placeholder(status: str) -> bool:
    from graqle.compliance.article_14_gate import THRESHOLD_STATUS_PLACEHOLDER  # lazy

    return status == THRESHOLD_STATUS_PLACEHOLDER


def _requested_decision(codes: Iterable[str]) -> Literal["approve_execute", "reject"]:
    """``approve_execute`` unless a critical failure code is present (REJECT-derived)."""
    if any(c in REGISTRY and REGISTRY[c].severity is Severity.CRITICAL for c in codes):
        return "reject"
    return "approve_execute"
