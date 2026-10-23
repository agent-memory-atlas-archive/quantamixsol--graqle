"""Flag-guarded adapter: ``GateVerdict`` -> legacy ``GateResult`` (CR-015 §5.7-5.8, PR-015b).

Only ``GovernanceMiddleware.check`` reaches this module, and only when
``GRAQLE_DAG_ENABLED`` is on; with the flag off it is never imported.

Mapping is monotone tightening only (I-TR-2): the final result is never less
restrictive than the legacy one in tier, ``blocked``, ``requires_approval`` or
``bypass_allowed``. A TS-BLOCK legacy result is returned untouched and the DAG is
not invoked. Any failure while building or running the gate is fail-closed: it
becomes an ESCALATE verdict, which maps to a blocked T3 requiring approval.

``GovernanceMiddleware`` carries no graph slices, so the gate and its context come
from a runtime provider registered with :func:`register_runtime`. With the flag on
and no provider registered the adapter fails closed (it never guesses inputs).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.adapter
# risk: HIGH (sits on the governance check path when the flag is on)
# dependencies: graqle.assurance.gate, graqle.core.governance (type only), asyncio, threading
# constraints: never imported by graqle.governance.*; imported lazily by core.governance only when flag on
# -- /graqle:intelligence --
import asyncio
import logging
import os
import threading
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from graqle.assurance.gate import (
    DagVerdict,
    DecisionAssuranceGate,
    EvaluationContext,
    GateCandidate,
)
from graqle.assurance.outcomes import GateOutcome

if TYPE_CHECKING:
    from graqle.core.governance import GateResult, GovernanceMiddleware

logger = logging.getLogger(__name__)

__all__ = [
    "NON_EXECUTE_HOOKS",
    "VerdictStore",
    "register_runtime",
    "route_via_dag",
    "to_gate_result",
]

_TIER_ORDER = {"T1": 0, "T2": 1, "T3": 2, "TS-BLOCK": 3}

_MAPPING: dict[GateOutcome, dict[str, Any]] = {
    GateOutcome.EXECUTE: dict(tier="T1", blocked=False, requires_approval=False, bypass_allowed=True),
    GateOutcome.HOLD: dict(tier="T2", blocked=True, requires_approval=True, bypass_allowed=False),
    GateOutcome.REPLAN: dict(tier="T2", blocked=True, requires_approval=False, bypass_allowed=False),
    # Unoverridable and dry-run immune; tier string per CR-015 OQ-2 (open at review).
    GateOutcome.REJECT: dict(tier="T3", blocked=True, requires_approval=False, bypass_allowed=False),
    GateOutcome.ESCALATE: dict(tier="T3", blocked=True, requires_approval=True, bypass_allowed=False),
}

_STORE_SIZE_ENV = "GRAQLE_DAG_VERDICT_STORE_SIZE"
_SAFE_DEFAULT_STORE_SIZE = 256  # operational default, not tuned

_PLACEHOLDER_CODE = "DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD"
_REVOKE_TIMEOUT_S = 5.0  # operational bound on the permission revoke, not a policy value

#: Hooks run after a non-execute outcome (CR-018 registers approved_args_hash invalidation).
NON_EXECUTE_HOOKS: list[Callable[[Any, DagVerdict], None]] = []

RuntimeProvider = Callable[..., "tuple[DecisionAssuranceGate, EvaluationContext]"]
_runtime_provider: RuntimeProvider | None = None


def register_runtime(provider: RuntimeProvider | None) -> None:
    """Install (or clear, with ``None``) the provider that builds the gate and context."""
    global _runtime_provider
    _runtime_provider = provider


def _store_capacity() -> int:
    raw = os.environ.get(_STORE_SIZE_ENV, "").strip()
    try:
        value = int(raw) if raw else _SAFE_DEFAULT_STORE_SIZE
    except ValueError:
        logger.warning("%s is not an integer; using the safe default", _STORE_SIZE_ENV)
        return _SAFE_DEFAULT_STORE_SIZE
    if value <= 0:
        logger.warning("%s must be positive; using the safe default", _STORE_SIZE_ENV)
        return _SAFE_DEFAULT_STORE_SIZE
    return value


class VerdictStore:
    """In-process LRU of full verdicts, keyed by ``verdict_id``."""

    _lock = threading.Lock()
    _items: OrderedDict[str, DagVerdict] = OrderedDict()

    @classmethod
    def put(cls, verdict: DagVerdict) -> None:
        with cls._lock:
            cls._items[verdict.verdict_id] = verdict
            cls._items.move_to_end(verdict.verdict_id)
            capacity = _store_capacity()
            while len(cls._items) > capacity:
                cls._items.popitem(last=False)

    @classmethod
    def get(cls, verdict_id: str) -> DagVerdict | None:
        with cls._lock:
            item = cls._items.get(verdict_id)
            if item is not None:
                cls._items.move_to_end(verdict_id)
            return item

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._items.clear()


def _build_gate_and_context(
    mw: GovernanceMiddleware, legacy: GateResult, **kwargs: Any
) -> tuple[DecisionAssuranceGate, EvaluationContext]:
    if _runtime_provider is None:
        raise RuntimeError("DAG runtime provider is not registered")
    return _runtime_provider(mw, legacy, **kwargs)


def route_via_dag(mw: GovernanceMiddleware, legacy_fn: Callable[..., GateResult], **kwargs: Any) -> GateResult:
    legacy = legacy_fn(**kwargs)  # legacy audit and dry-run already applied exactly once
    if legacy.tier == "TS-BLOCK":
        return legacy  # unconditional; the DAG never re-evaluates IP-pattern blocks
    ctx: EvaluationContext | None = None
    try:
        gate, ctx = _build_gate_and_context(mw, legacy, **kwargs)
        verdict = gate.evaluate(GateCandidate.from_check_kwargs(**kwargs), ctx)
    except Exception as exc:  # adapter-level failure is fail-closed
        logger.warning("DAG adapter failed closed: %s", type(exc).__name__)
        verdict = DagVerdict.failed_closed(type(exc).__name__, now=datetime.now(timezone.utc))
    try:
        VerdictStore.put(verdict)
    except Exception:  # the store is a convenience; it never changes the decision
        logger.warning("DAG verdict store write failed")
    result = to_gate_result(legacy, verdict)
    if verdict.outcome is not GateOutcome.EXECUTE:
        failures = _on_non_execute(ctx, verdict)
        result.warnings.extend(failures)
    policy = getattr(mw, "_policy", None)
    if (
        policy is not None
        and policy.dry_run
        and verdict.outcome in (GateOutcome.HOLD, GateOutcome.REPLAN)
        and not legacy.blocked
    ):
        # REJECT and ESCALATE are never dry-run relaxed. Relaxing only undoes the DAG's own
        # block: a legacy block was already converted (or not) by the legacy dry-run.
        result.blocked = False
        result.warnings.append(f"[DRY_RUN][DAG] would {verdict.outcome.value}")
    return result


def _iso(unix: float) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).isoformat()


def to_gate_result(legacy: GateResult, v: DagVerdict) -> GateResult:
    from graqle.core.governance import GateResult  # deferred: governance imports us lazily

    m = _MAPPING[v.outcome]
    warnings = list(legacy.warnings)
    warnings.append(
        f"[DAG] outcome={v.outcome.value} rule={v.decisive_rule} "
        f"verdict_id={v.verdict_id} codes={','.join(v.reason_codes)}"
    )
    if v.outcome is GateOutcome.REPLAN:
        attempt = getattr(v.replan_context, "attempt", 0)
        warnings.append(
            f"[DAG] REPLAN implicated_nodes={','.join(v.implicated_nodes)} attempt={attempt}"
        )
    if v.outcome is GateOutcome.ESCALATE:
        esc = v.escalation
        if esc is not None:
            warnings.append(
                f"[DAG] ESCALATE human_review_required package={esc.package_id} "
                f"role={esc.route_to_role} deadline={_iso(esc.deadline_unix)}"
            )
        else:
            warnings.append("[DAG] ESCALATE human_review_required")
        if _PLACEHOLDER_CODE in v.reason_codes:
            warnings.append("[DAG] ARTICLE_14 threshold_status=placeholder")
    tier = max((legacy.tier, m["tier"]), key=lambda t: _TIER_ORDER.get(t, _TIER_ORDER["TS-BLOCK"]))
    legacy_rank = _TIER_ORDER.get(legacy.tier, _TIER_ORDER["TS-BLOCK"])
    return GateResult(
        tier=tier,
        blocked=legacy.blocked or m["blocked"],
        requires_approval=legacy.requires_approval or m["requires_approval"],
        gate_score=legacy.gate_score,
        reason=(
            legacy.reason
            if legacy_rank > _TIER_ORDER[m["tier"]]
            else f"{v.outcome.value}: {v.decisive_rule} - {v.summary}"
        ),
        warnings=warnings,
        bypass_allowed=legacy.bypass_allowed and m["bypass_allowed"],
        risk_level=legacy.risk_level,
        impact_radius=legacy.impact_radius,
        file_path=legacy.file_path,
        threshold_at_time=legacy.threshold_at_time,
    )


def _run_sync(coro: Any) -> Any:
    """Run a coroutine to completion from sync code, inside or outside a running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: dict[str, Any] = {}

    def _worker() -> None:
        try:
            box["result"] = asyncio.run(coro)
        except BaseException as exc:  # surfaced to the caller below
            box["error"] = exc

    thread = threading.Thread(target=_worker, name="dag-revoke", daemon=True)
    thread.start()
    thread.join(_REVOKE_TIMEOUT_S)
    if thread.is_alive():
        raise TimeoutError("revoke timed out")
    if "error" in box:
        raise box["error"]
    return box.get("result")


def _on_non_execute(ctx: EvaluationContext | None, verdict: DagVerdict) -> list[str]:
    """Revoke the cached grant and run registered hooks; return warnings for any failure.

    A failure never converts a block into a pass: the result is already blocked and the
    failure is added to its warnings so the operator can see the grant may have survived.
    """
    failures: list[str] = []
    if ctx is not None and ctx.permission_manager is not None and ctx.permission_scope is not None:
        tool_name, scope = ctx.permission_scope
        try:
            _run_sync(
                ctx.permission_manager.revoke(
                    session_id=ctx.session_id, tool_name=tool_name, resource_scope=scope
                )
            )
        except Exception as exc:
            logger.exception("permission revoke failed")
            failures.append(f"[DAG] permission revoke failed: {type(exc).__name__}")
    for hook in list(NON_EXECUTE_HOOKS):
        try:
            hook(ctx, verdict)
        except Exception as exc:
            logger.exception("non-execute hook failed")
            failures.append(f"[DAG] non-execute hook failed: {type(exc).__name__}")
    return failures
