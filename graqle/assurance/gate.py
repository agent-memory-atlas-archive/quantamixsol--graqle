"""DAG-2026 Decision Assurance Gate: ordered pipeline + routing table (CR-015 §5.3-5.4, PR-015b).

``DecisionAssuranceGate.evaluate`` runs hard gates -> critical cap -> confidence
projection -> trajectory reliability -> authority, then asks :func:`route` for the
outcome. ``route`` is a pure, total, first-match decision table (rows R01..R17).

Fail-closed rules:
* every stage runs under ``guarded``; a stage exception becomes an evaluation error
  and a conservative fallback, never a propagated exception;
* an error in the hard-gate or cap stage routes REJECT; in any later stage, ESCALATE;
* EXECUTE is impossible with a failed hard gate or any evaluation error (the
  :class:`GateVerdict` validator and a final defensive check both enforce it);
* a REPLAN with no replan controller wired, or whose controller raises, is ESCALATE.

Configuration rule: floors, budgets and the residual-risk combinator arrive through
:class:`~graqle.assurance.routing_settings.RoutingSettings`; no value lives here.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.gate
# risk: MEDIUM (consumed by graqle.assurance.adapter; flag-off never imports it)
# dependencies: pydantic, graqle.assurance.{outcomes,reason_codes,verdict,hard_gates,_hashing}
# constraints: never imported by graqle.governance.*; no numeric literal for any private symbol
# -- /graqle:intelligence --
import hashlib
import logging
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from graqle.assurance._hashing import inputs_hash as _inputs_hash
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.reason_codes import REGISTRY, resolvable
from graqle.assurance.verdict import DeterminismRecord, GateVerdict, HardGateResultRef

logger = logging.getLogger(__name__)

__all__ = [
    "DecisionAssuranceGate",
    "DagVerdict",
    "EvaluationContext",
    "GateCandidate",
    "GateComponents",
    "ImpactTier",
    "ProjectionStageResult",
    "RULE_VERSION_ROUTE",
    "RoutingInputs",
    "fingerprint",
    "impact_tier_of",
    "rbac_may_automate",
    "residual_risk",
    "route",
    "tier_ge",
]

RULE_VERSION_ROUTE = "1"
_PLACEHOLDER = "placeholder"  # mirrors compliance.article_14_gate.THRESHOLD_STATUS_PLACEHOLDER
_EMIT_RULE = "DAG-RT-EMIT"
_UNREGISTERED_FALLBACK = ("DAG-TR-010-EVALUATION_ERROR",)


class ImpactTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_TIER_RANK = {ImpactTier.LOW: 0, ImpactTier.MEDIUM: 1, ImpactTier.HIGH: 2, ImpactTier.CRITICAL: 3}
# Same vocabulary as GovernanceConfig._RISK_ORDER; an unknown level is CRITICAL.
_TIER_NAMES = {t.value: t for t in ImpactTier}
# The legacy RBAC tiers an actor must hold to automate each impact tier (OQ-3: derived,
# no second role table). CRITICAL has no automating tier: nobody may automate it.
_RBAC_TIER = {ImpactTier.LOW: "T1", ImpactTier.MEDIUM: "T2", ImpactTier.HIGH: "T3"}


def tier_ge(a: ImpactTier, b: ImpactTier) -> bool:
    return _TIER_RANK[a] >= _TIER_RANK[b]


def impact_tier_of(risk_level: object) -> ImpactTier:
    """Map a legacy ``risk_level`` onto an impact tier; anything unknown is CRITICAL."""
    if isinstance(risk_level, str):
        return _TIER_NAMES.get(risk_level.strip().upper(), ImpactTier.CRITICAL)
    return ImpactTier.CRITICAL


def rbac_may_automate(actor_id: str, tier: ImpactTier, timeout_ms: int) -> bool:
    """May ``actor_id`` automate ``tier``? Timeout, error or empty actor => False."""
    legacy_tier = _RBAC_TIER.get(tier)
    if not actor_id or legacy_tier is None:
        return False
    from graqle.assurance.hard_gates import _rbac_with_deadline  # same-package helper

    return _rbac_with_deadline(actor_id, legacy_tier, timeout_ms) == "ok"


# ── routing inputs and decision table (§2.4, §5.4) ───────────────────────────


class RoutingInputs(BaseModel):
    """Every field is a plain value so :func:`route` is a pure function."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    error_stages: tuple[str, ...] = ()
    hg_all_passed: bool
    hg_critical_failed: bool
    hg_noncritical_failed: bool
    cap_applied: bool
    proj_admitted: bool | None
    proj_score: float | None
    cv_calibration_stale: bool
    cv_mandatory_na: bool
    trj_available: bool
    trj_reliability: float | None
    authority_ok: bool
    impact_tier: ImpactTier
    retries_remaining: int = Field(ge=0)
    fingerprint_seen: bool
    article14_refused: bool
    article14_status: str | None
    resolvable: bool
    residual_risk: float | None


class _RoutingLimits(Protocol):
    trajectory_floor: dict[ImpactTier, float]
    residual_risk_budget: dict[ImpactTier, float]
    tier_automation_max: ImpactTier


def _all_mandatory_pass(i: RoutingInputs) -> bool:
    return (
        i.hg_all_passed
        and i.proj_admitted is True
        and not i.cv_mandatory_na
        and i.trj_available
    )


def _below_floor(i: RoutingInputs, s: _RoutingLimits) -> bool:
    # An absent reliability is below every floor (fail closed).
    return i.trj_reliability is None or i.trj_reliability < s.trajectory_floor[i.impact_tier]


def _over_budget(i: RoutingInputs, s: _RoutingLimits) -> bool:
    return i.residual_risk is None or i.residual_risk > s.residual_risk_budget[i.impact_tier]


_Pred = Callable[[RoutingInputs, _RoutingLimits], bool]

_TABLE: tuple[tuple[str, _Pred, GateOutcome, tuple[str, ...]], ...] = (
    ("DAG-RT-01", lambda i, s: any(st in ("hard_gates", "critical_cap") for st in i.error_stages),
     GateOutcome.REJECT, ("DAG-TR-010-EVALUATION_ERROR",)),
    # A "not all passed" input that names no failure kind is inconsistent; it is treated as
    # critical (fail closed) so it can never fall through to EXECUTE.
    ("DAG-RT-02",
     lambda i, s: i.hg_critical_failed or (not i.hg_all_passed and not i.hg_noncritical_failed),
     GateOutcome.REJECT, ()),
    ("DAG-RT-03", lambda i, s: any(st in ("projection", "trajectory", "routing") for st in i.error_stages),
     GateOutcome.ESCALATE, ("DAG-TR-010-EVALUATION_ERROR",)),
    ("DAG-RT-04", lambda i, s: not i.authority_ok, GateOutcome.ESCALATE, ("DAG-TR-006-AUTHORITY_EXCEEDED",)),
    ("DAG-RT-05",
     lambda i, s: tier_ge(i.impact_tier, s.tier_automation_max) or (i.cap_applied and i.retries_remaining == 0),
     GateOutcome.ESCALATE, ("DAG-TR-007-IMPACT_EXCEEDED",)),
    ("DAG-RT-06", lambda i, s: i.article14_refused, GateOutcome.ESCALATE, ("DAG-TR-016-ARTICLE14_REVIEW_REQUIRED",)),
    ("DAG-RT-07", lambda i, s: i.fingerprint_seen, GateOutcome.ESCALATE, ("DAG-TR-002-UNCHANGED_REASON_DETECTED",)),
    ("DAG-RT-08", lambda i, s: i.retries_remaining == 0 and not _all_mandatory_pass(i),
     GateOutcome.ESCALATE, ("DAG-TR-001-RETRY_BUDGET_EXHAUSTED",)),
    ("DAG-RT-09", lambda i, s: i.hg_noncritical_failed and i.resolvable and i.retries_remaining > 0,
     GateOutcome.REPLAN, ("DAG-TR-014-REPLAN_RESOLVABLE",)),
    ("DAG-RT-10", lambda i, s: i.proj_admitted is False and i.resolvable and i.retries_remaining > 0,
     GateOutcome.REPLAN, ("DAG-TR-014-REPLAN_RESOLVABLE", "DAG-CV-005-BELOW_POLICY_THRESHOLD")),
    ("DAG-RT-11",
     lambda i, s: i.proj_admitted is not True
     or i.cv_mandatory_na
     or (i.cv_calibration_stale and tier_ge(i.impact_tier, ImpactTier.HIGH))
     or i.hg_noncritical_failed,
     GateOutcome.HOLD, ("DAG-TR-012-HOLD_EVIDENCE_INCOMPLETE",)),
    ("DAG-RT-12", lambda i, s: not i.trj_available, GateOutcome.HOLD, ("DAG-TR-005-HISTORY_INCOMPLETE",)),
    ("DAG-RT-13", lambda i, s: _below_floor(i, s) and i.resolvable and i.retries_remaining > 0,
     GateOutcome.REPLAN,
     ("DAG-TR-004-TRAJECTORY_RELIABILITY_BELOW_FLOOR", "DAG-TR-014-REPLAN_RESOLVABLE")),
    ("DAG-RT-14", _below_floor, GateOutcome.HOLD, ("DAG-TR-004-TRAJECTORY_RELIABILITY_BELOW_FLOOR",)),
    ("DAG-RT-15",
     lambda i, s: i.residual_risk is None or (_over_budget(i, s) and tier_ge(i.impact_tier, ImpactTier.HIGH)),
     GateOutcome.ESCALATE, ("DAG-TR-013-RESIDUAL_RISK_EXCEEDS_BUDGET",)),
    ("DAG-RT-16", _over_budget, GateOutcome.HOLD, ("DAG-TR-013-RESIDUAL_RISK_EXCEEDS_BUDGET",)),
    ("DAG-RT-17", lambda i, s: True, GateOutcome.EXECUTE, ()),
)


def route(i: RoutingInputs, s: _RoutingLimits) -> tuple[GateOutcome, str, tuple[str, ...]]:
    """First matching row wins. Total: DAG-RT-17 matches everything."""
    for rule_id, pred, outcome, codes in _TABLE:
        if pred(i, s):
            extra: tuple[str, ...] = ()
            if rule_id == "DAG-RT-06" and i.article14_status == _PLACEHOLDER:
                extra = ("DAG-TR-008-ARTICLE14_PLACEHOLDER_THRESHOLD",)
            return outcome, rule_id, codes + extra
    raise AssertionError("routing table is total; unreachable")  # pragma: no cover


def residual_risk(
    decision_score: float,
    reliability: float,
    combinator: str,
    private_combinator: Callable[[float, float], float] | None = None,
) -> float:
    """R(1 - decision_score, 1 - reliability), clamped to [0, 1]; ``max`` by default."""
    a, b = 1.0 - decision_score, 1.0 - reliability
    if combinator == "max":
        value = max(a, b)
    elif combinator == "private" and private_combinator is not None:
        value = private_combinator(a, b)
    else:
        raise ValueError("residual-risk combinator is not available")
    if not 0.0 <= value <= 1.0:
        raise ValueError("residual risk out of range")
    return value


def fingerprint(decisive_rule: str, reason_codes: Sequence[str], implicated_nodes: Sequence[str]) -> str:
    """sha256 over the RFC 8785 canonical bytes of the order-free reason triple (§2.5)."""
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    payload = {
        "decisive_rule": decisive_rule,
        "reason_codes": sorted(set(reason_codes)),
        "implicated_nodes": sorted(set(implicated_nodes)),
    }
    return hashlib.sha256(canon(payload)).hexdigest()


# ── stage contracts and evaluation context ───────────────────────────────────


@dataclass(frozen=True)
class GateCandidate:
    id: str
    risk_level: str = "CRITICAL"
    file_path: str = ""
    action: str = "edit"

    @classmethod
    def from_check_kwargs(cls, **kwargs: Any) -> GateCandidate:
        """Stable id from the request, so replans of one request share a root."""
        basis = f"{kwargs.get('file_path', '')}|{kwargs.get('action', '')}|{kwargs.get('actor', '')}"
        return cls(
            id="cand-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16],
            risk_level=str(kwargs.get("risk_level", "CRITICAL")),
            file_path=str(kwargs.get("file_path", "")),
            action=str(kwargs.get("action", "edit")),
        )


@dataclass(frozen=True)
class ProjectionStageResult:
    """What the projection stage hands the router (CR-014 ``ProjectionResult`` + vector flags)."""

    admitted: bool
    decision_score: float | None
    calibration_stale: bool
    mandatory_na: bool
    reason_codes: tuple[str, ...] = ()
    implicated_nodes: tuple[str, ...] = ()
    confidence_vector: dict[str, float] | None = None


@dataclass(frozen=True)
class _NoReplan:
    attempts: int = 0
    fingerprints: frozenset[str] = frozenset()


@dataclass
class EvaluationContext:
    session_id: str
    actor_id: str
    history: Any
    checkpoint: Any
    turn_id: str = ""
    approved_by: str = ""
    replan_state: Any = field(default_factory=_NoReplan)  # .attempts, .fingerprints
    article14: Any = None  # Article14GateResult | None
    legacy_result: Any = None
    permission_manager: Any = None
    permission_scope: tuple[str, str] | None = None
    alternatives: tuple[str, ...] = ()
    extras: dict[str, Any] = field(default_factory=dict)  # opaque, passed to stages


class _Estimator(Protocol):
    def estimate(self, view: Any) -> Any: ...


@dataclass(frozen=True)
class GateComponents:
    """The pluggable stages. Each takes plain inputs and may raise (guarded)."""

    hard_gates: Callable[[GateCandidate, EvaluationContext], Sequence[Any]]
    cap: Callable[[Sequence[Any], EvaluationContext], Any]  # -> .cap_applied, .reason_codes
    projection: Callable[[GateCandidate, EvaluationContext, Sequence[Any], Any], ProjectionStageResult]
    estimator: _Estimator
    may_automate: Callable[[str, ImpactTier], bool]
    replan: Any = None  # .on_replan(DagVerdict, ctx) -> DagVerdict   (PR-015c)
    escalation: Any = None  # .route(DagVerdict, candidate, ctx) -> DagVerdict   (PR-015c)
    audit: Callable[[dict[str, Any]], None] | None = None
    emitter: Any = None  # .append(kind=, subject_id=, payload=)


@dataclass(frozen=True)
class DagVerdict:
    """A CR-012 :class:`GateVerdict` plus the routing artefacts the adapter needs."""

    verdict: GateVerdict
    verdict_id: str
    fingerprint: str
    impact_tier: ImpactTier
    summary: str = ""
    replan_context: Any = None
    escalation: Any = None

    @property
    def outcome(self) -> GateOutcome:
        return self.verdict.outcome

    @property
    def decisive_rule(self) -> str:
        return self.verdict.decisive_rule or ""

    @property
    def reason_codes(self) -> list[str]:
        return self.verdict.reason_codes

    @property
    def implicated_nodes(self) -> list[str]:
        return self.verdict.implicated_nodes

    def public_view(self) -> dict[str, Any]:
        v = self.verdict
        return {
            "verdict_id": self.verdict_id,
            "outcome": v.outcome.value,
            "decisive_rule": self.decisive_rule,
            "reason_codes": list(v.reason_codes),
            "implicated_nodes": list(v.implicated_nodes),
            "fingerprint": self.fingerprint,
            "impact_tier": self.impact_tier.value,
            "evaluation_errors": list(v.evaluation_errors),
            "rule_version": v.determinism_record.rule_version,
            "config_version": v.determinism_record.config_version,
            "inputs_hash": v.determinism_record.inputs_hash,
        }

    def downgraded(
        self, outcome: GateOutcome, *, rule: str, codes: Sequence[str] = (), errors: Sequence[str] = ()
    ) -> DagVerdict:
        merged = list(dict.fromkeys([*self.verdict.reason_codes, *codes]))
        v = self.verdict.model_copy(
            update={
                "outcome": outcome,
                "decisive_rule": rule,
                "reason_codes": merged,
                "evaluation_errors": [*self.verdict.evaluation_errors, *errors],
            }
        )
        return DagVerdict(v, self.verdict_id, self.fingerprint, self.impact_tier, self.summary)

    def with_reason_code(self, code: str) -> DagVerdict:
        codes = list(dict.fromkeys([*self.verdict.reason_codes, code]))
        v = self.verdict.model_copy(update={"reason_codes": codes})
        return DagVerdict(
            v, self.verdict_id, self.fingerprint, self.impact_tier, self.summary,
            self.replan_context, self.escalation,
        )

    @classmethod
    def failed_closed(cls, reason: str, *, now: datetime | None = None) -> DagVerdict:
        """The verdict used when evaluation itself cannot complete: ESCALATE, never EXECUTE."""
        when = now or datetime.now(timezone.utc)
        detail = f"evaluate: {reason}"[:240]
        record = DeterminismRecord(
            inputs_hash=_inputs_hash({"failed_closed": True}),
            rule_id="DAG-RT-03",
            rule_version=RULE_VERSION_ROUTE,
            config_version="unavailable",
            decisive_conditions=["evaluation_failed"],
        )
        verdict = GateVerdict(
            outcome=GateOutcome.ESCALATE,
            reason_codes=list(_UNREGISTERED_FALLBACK),
            decisive_rule="DAG-RT-03",
            evaluation_errors=[detail],
            determinism_record=record,
            evaluated_at=when,
        )
        return cls(
            verdict, "v_" + uuid.uuid4().hex, fingerprint("DAG-RT-03", verdict.reason_codes, ()),
            ImpactTier.CRITICAL, "evaluation failed closed",
        )


# ── the gate ─────────────────────────────────────────────────────────────────


class DecisionAssuranceGate:
    def __init__(
        self,
        *,
        components: GateComponents,
        routing: _RoutingLimits,
        max_retry_budget: int,
        config_version: str,
        combinator: str = "max",
        private_combinator: Callable[[float, float], float] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if isinstance(max_retry_budget, bool) or max_retry_budget < 1:
            raise ValueError("max_retry_budget must be a positive integer")
        if combinator == "private" and private_combinator is None:
            raise ValueError("residual-risk combinator 'private' requires a private combinator")
        self._c = components
        self._routing = routing
        self._budget = max_retry_budget
        self._config_version = config_version
        self._combinator = combinator
        self._private = private_combinator
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def evaluate(self, candidate: GateCandidate, ctx: EvaluationContext) -> DagVerdict:
        """Never raises: any failure here returns an ESCALATE verdict."""
        try:
            return self._evaluate(candidate, ctx)
        except Exception as exc:  # fail closed; never propagate
            logger.warning("DAG evaluate failed closed: %s", type(exc).__name__)
            return DagVerdict.failed_closed(type(exc).__name__)

    # -- internals -----------------------------------------------------------

    def _evaluate(self, candidate: GateCandidate, ctx: EvaluationContext) -> DagVerdict:
        errors: list[tuple[str, str]] = []

        def guarded(stage: str, fn: Callable[[], Any], fallback: Any) -> Any:
            try:
                return fn()
            except Exception as exc:
                errors.append((stage, type(exc).__name__))
                return fallback

        tier = impact_tier_of(candidate.risk_level)
        results: tuple[Any, ...] = tuple(
            guarded("hard_gates", lambda: self._c.hard_gates(candidate, ctx), ())
        )
        failed = [r for r in results if not r.passed]
        hg_all = bool(results) and not failed
        # No results at all (stage error or empty suite) is treated as a critical failure.
        hg_critical = (not results) or any(r.severity == "CRITICAL" for r in failed)
        hg_noncritical = any(r.severity == "FAIL" for r in failed)

        cap = guarded("critical_cap", lambda: self._c.cap(results, ctx), None)
        cap_applied = True if cap is None else bool(cap.cap_applied)

        proj: ProjectionStageResult | None = guarded(
            "projection", lambda: self._c.projection(candidate, ctx, results, cap), None
        )
        est = guarded("trajectory", lambda: self._estimate(ctx), None)
        authority_ok = bool(
            guarded("routing", lambda: self._c.may_automate(ctx.actor_id, tier), False)
        )

        # Failure reasons (failed gates, projection) decide RES; the cap's informational
        # code is carried on the verdict but never makes a failure look resolvable.
        failure_codes: list[str] = []
        for r in failed:
            failure_codes.extend(getattr(r, "reason_codes", ()))
        implicated: list[str] = []
        if proj is not None:
            failure_codes.extend(proj.reason_codes)
            implicated.extend(proj.implicated_nodes)
        carried: list[str] = list(failure_codes)
        if cap is not None:
            carried.extend(cap.reason_codes)

        a14 = ctx.article14
        risk: float | None = None
        if proj is not None and est is not None and proj.decision_score is not None:
            risk = guarded(
                "routing",
                lambda: residual_risk(
                    proj.decision_score, est.reliability, self._combinator, self._private
                ),
                None,
            )

        def inputs_for(seen: bool) -> RoutingInputs:
            return RoutingInputs(
                error_stages=tuple(stage for stage, _ in errors),
                hg_all_passed=hg_all,
                hg_critical_failed=hg_critical,
                hg_noncritical_failed=hg_noncritical,
                cap_applied=cap_applied,
                proj_admitted=proj.admitted if proj is not None else None,
                proj_score=proj.decision_score if proj is not None else None,
                cv_calibration_stale=proj.calibration_stale if proj is not None else True,
                cv_mandatory_na=proj.mandatory_na if proj is not None else True,
                trj_available=est is not None,
                trj_reliability=est.reliability if est is not None else None,
                authority_ok=authority_ok,
                impact_tier=tier,
                retries_remaining=max(self._budget - int(ctx.replan_state.attempts), 0),
                fingerprint_seen=seen,
                article14_refused=bool(a14 is not None and not a14.allowed),
                article14_status=a14.threshold_status if a14 is not None else None,
                resolvable=_has_resolvable(failure_codes),
                residual_risk=risk,
            )

        # Fingerprint the provisional (not-yet-seen) routing, then re-route once with
        # the repeat flag so a repeated reason escalates (C12, DAG-RT-07).
        first = inputs_for(False)
        outcome, rule_id, codes = route(first, self._routing)
        fp = fingerprint(rule_id, [*codes, *carried], implicated)
        seen_before = fp in ctx.replan_state.fingerprints
        inputs = first
        if seen_before:
            inputs = inputs_for(True)
            outcome, rule_id, codes = route(inputs, self._routing)

        all_codes = list(dict.fromkeys([*codes, *carried]))
        error_text = [f"{stage}: {detail}" for stage, detail in errors]
        if outcome is GateOutcome.EXECUTE and (error_text or not hg_all):
            # Defence in depth: the table cannot produce this, the verdict must not either.
            outcome, rule_id = GateOutcome.ESCALATE, "DAG-RT-03"
            all_codes = list(dict.fromkeys([*all_codes, "DAG-TR-010-EVALUATION_ERROR"]))

        now = self._clock()
        record = DeterminismRecord(
            inputs_hash=_inputs_hash(_hashable(inputs)),
            rule_id=rule_id,
            rule_version=RULE_VERSION_ROUTE,
            config_version=self._config_version,
            decisive_conditions=[rule_id],
            probabilistic=bool(est is not None and est.probabilistic),
            variance=est.variance if est is not None and est.probabilistic else None,
        )
        verdict = GateVerdict(
            outcome=outcome,
            reason_codes=all_codes,
            hard_gate_results=[HardGateResultRef.from_result(r) for r in results],
            confidence_vector=proj.confidence_vector if proj is not None else None,
            trajectory_reliability=est.reliability if est is not None else None,
            residual_risk=risk,
            implicated_nodes=sorted(set(implicated)),
            decisive_rule=rule_id,
            evaluation_errors=error_text,
            determinism_record=record,
            cap_applied=cap_applied,
            evaluated_at=now,
        )
        dv = DagVerdict(verdict, "v_" + uuid.uuid4().hex, fp, tier, f"{rule_id}: {outcome.value}")

        if dv.outcome is GateOutcome.REPLAN:
            dv = self._replan(dv, ctx)
        if dv.outcome is GateOutcome.ESCALATE:
            dv = self._escalate(dv, candidate, ctx)
        return self._emit(dv, candidate)

    def _estimate(self, ctx: EvaluationContext) -> Any:
        view = ctx.history.view_until(ctx.checkpoint.step_index)
        return self._c.estimator.estimate(view)

    def _replan(self, dv: DagVerdict, ctx: EvaluationContext) -> DagVerdict:
        hook = self._c.replan
        if hook is None:
            return dv.downgraded(
                GateOutcome.ESCALATE, rule="DAG-RT-03",
                codes=("DAG-TR-010-EVALUATION_ERROR",), errors=("routing: replan controller unavailable",),
            )
        try:
            out = hook.on_replan(dv, ctx)
        except Exception as exc:
            return dv.downgraded(
                GateOutcome.ESCALATE, rule="DAG-RT-03",
                codes=("DAG-TR-010-EVALUATION_ERROR",), errors=(f"routing: {type(exc).__name__}",),
            )
        if not isinstance(out, DagVerdict) or out.outcome is GateOutcome.EXECUTE:
            return dv.downgraded(
                GateOutcome.ESCALATE, rule="DAG-RT-03",
                codes=("DAG-TR-010-EVALUATION_ERROR",), errors=("routing: replan hook returned an invalid verdict",),
            )
        return out

    def _escalate(self, dv: DagVerdict, candidate: GateCandidate, ctx: EvaluationContext) -> DagVerdict:
        hook = self._c.escalation
        if hook is None:
            return dv
        try:
            out = hook.route(dv, candidate, ctx)
        except Exception as exc:
            # The verdict stays ESCALATE; the failed routing is recorded on it.
            return dv.downgraded(
                GateOutcome.ESCALATE, rule=dv.decisive_rule,
                codes=("DAG-TR-010-EVALUATION_ERROR",), errors=(f"routing: {type(exc).__name__}",),
            )
        if not isinstance(out, DagVerdict) or out.outcome is not GateOutcome.ESCALATE:
            return dv
        return out

    def _emit(self, dv: DagVerdict, candidate: GateCandidate) -> DagVerdict:
        if self._c.audit is None and self._c.emitter is None:
            return dv
        try:
            view = dv.public_view()
            if self._c.audit is not None:
                self._c.audit(view)
            if self._c.emitter is not None:
                self._c.emitter.append(kind="GATE_VERDICT", subject_id=candidate.id, payload=view)
        except Exception:
            # A reason code (WARN), deliberately not an evaluation error: EXECUTE forbids
            # evaluation_errors, and a LOW/MEDIUM EXECUTE with a failed audit write may proceed.
            dv = dv.with_reason_code("DAG-TR-015-PROVENANCE_EMIT_FAILED")
            if dv.outcome is GateOutcome.EXECUTE and tier_ge(dv.impact_tier, ImpactTier.HIGH):
                dv = dv.downgraded(GateOutcome.HOLD, rule=_EMIT_RULE)
        return dv


def _has_resolvable(codes: Sequence[str]) -> bool:
    """RES: at least one carried failure reason is resolvable per the registry (ruling R2)."""
    return any(resolvable(c) for c in dict.fromkeys(codes) if c in REGISTRY)


def _hashable(inputs: RoutingInputs) -> dict[str, Any]:
    data = inputs.model_dump(mode="json")
    data["error_stages"] = list(data["error_stages"])
    return data
