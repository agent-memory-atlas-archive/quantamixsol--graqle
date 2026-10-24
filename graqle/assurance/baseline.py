"""Baseline admission gate: rule DAG-RT-BASELINE-ADMIT (CR-DAG-087-1 PR-B).

Used by the default runtime provider, where ``GovernanceMiddleware`` supplies no graph slices.
The decision is made from declared structural facts about the call, never inferred at runtime:
policy default/PUBLIC, the call's own risk tier, lowest actor tier, no injected contradictions
or dependency nodes, freshness CURRENT. ``contradictions`` empty means "none injected, graph
not consulted", NOT "graph checked and clean".

* EXECUTE only when risk is within the baseline ceiling (LOW), impact is zero and all of
  HG-01..HG-07 pass independently.
* A failed critical hard gate is REJECT; a failed non-critical gate, or any other case, is
  HOLD with ``DAG-RT-NO-EVIDENCE``.
* No projection score, trajectory reliability or residual risk is computed or recorded.
* Every outcome (EXECUTE included) is written as a signed, hash-chained provenance event. If
  the event cannot be recorded, EXECUTE becomes HOLD and the failure is carried on the verdict.

This is a distinct code path: ``gate.py`` (rows DAG-RT-01..17) is not edited or consulted.
Baseline EXECUTE is a policy-scoped authorisation at evidence tier BASELINE; it is not
graph-informed and not a safety verification.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.baseline
# risk: MEDIUM (decides EXECUTE on the flag-on path; flag-off never imports it)
# dependencies: graqle.assurance.{gate,hard_gates,provenance_recorder,provenance_event,routing_settings,settings}
# constraints: no numeric score/reliability/residual field; routing settings scope-locked to this rule
# -- /graqle:intelligence --
import hashlib
import logging
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from graqle.assurance._hashing import inputs_hash as _inputs_hash
from graqle.assurance._ids import new_id, rfc3339
from graqle.assurance.gate import (
    RULE_VERSION_ROUTE,
    DagVerdict,
    EvaluationContext,
    GateCandidate,
    ImpactTier,
    fingerprint,
    impact_tier_of,
    tier_ge,
)
from graqle.assurance.hard_gates import (
    GateContext,
    HardGateRegistry,
    HardGateResult,
    PolicyRef,
)
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.provenance_event import (
    Activity,
    Actor,
    ActorType,
    Assessment,
    EventType,
    IdentityAssurance,
    Inputs,
)
from graqle.assurance.provenance_event import HardGateResult as EventGateResult
from graqle.assurance.routing_settings import BaselineRoutingSettings
from graqle.assurance.settings import DagSettings, config_version
from graqle.assurance.verdict import DeterminismRecord, GateVerdict, HardGateResultRef

logger = logging.getLogger(__name__)

__all__ = [
    "BASELINE_RULE_ID",
    "BASELINE_TRAJECTORY",
    "BaselineAdmissionGate",
    "NO_EVIDENCE_CODE",
]

BASELINE_RULE_ID = "DAG-RT-BASELINE-ADMIT"
NO_EVIDENCE_CODE = "DAG-RT-NO-EVIDENCE"
_EMIT_FAILED_CODE = "DAG-TR-015-PROVENANCE_EMIT_FAILED"
_EVAL_ERROR_CODE = "DAG-TR-010-EVALUATION_ERROR"

#: Fixed trajectory for baseline events, so all of them share one hash chain.
BASELINE_TRAJECTORY = "trj_" + "0" * 25 + "1"

_BASELINE_POLICY_ID = "default-public"
_BASELINE_SCOPE = "baseline"
_ARGS_ALGO = "sha256"
_EVIDENCE_TIER = "BASELINE"
_VECTOR_SOURCE = "BASELINE"
_DECISION_PATH = "BASELINE_ADMISSION"
_PASSED = "BASELINE_GATES_PASSED"
_FAILED = "BASELINE_GATES_FAILED"
_RBAC_TIER = {ImpactTier.LOW: "T1", ImpactTier.MEDIUM: "T2", ImpactTier.HIGH: "T3"}
_EVENT_CODE = re.compile(r"^DAG-(HG0[1-7]|CV|TR|PV)-[A-Z0-9_-]+$")
_AGENT_FALLBACK = "unauthenticated"


def _args_hash(candidate: GateCandidate) -> str:
    """Hash of the call as the gate saw it; binds the evaluated call to the recorded call."""
    basis = "|".join((candidate.id, candidate.risk_level, candidate.file_path, candidate.action))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _impact_is_zero(ctx: EvaluationContext) -> bool:
    radius = getattr(ctx.legacy_result, "impact_radius", None)
    return isinstance(radius, int) and not isinstance(radius, bool) and radius == 0


def _event_gate_result(r: HardGateResult) -> EventGateResult:
    code = next((c for c in r.reason_codes if _EVENT_CODE.match(c)), None)
    return EventGateResult(
        gate_id=r.rule_id,
        passed=r.passed,
        reason_code=code,
        rule_version=r.rule_version,
        inputs_hash=r.inputs_hash.removeprefix("sha256:"),
    )


class BaselineAdmissionGate:
    """Duck-typed stand-in for ``DecisionAssuranceGate`` (``evaluate`` never raises)."""

    def __init__(
        self,
        *,
        registry: HardGateRegistry,
        settings: DagSettings,
        recorder: Any,
        routing: BaselineRoutingSettings,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._settings = settings
        self._recorder = recorder
        self._routing = routing
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._config_version = config_version(settings)  # fails at construction if unusable

    def evaluate(self, candidate: GateCandidate, ctx: EvaluationContext) -> DagVerdict:
        try:
            return self._evaluate(candidate, ctx)
        except Exception as exc:  # fail closed; never propagate
            logger.warning("DAG baseline gate failed closed: %s", type(exc).__name__)
            return DagVerdict.failed_closed(type(exc).__name__)

    # -- internals -----------------------------------------------------------

    def _gate_results(
        self, candidate: GateCandidate, ctx: EvaluationContext, tier: ImpactTier, now: datetime
    ) -> tuple[HardGateResult, ...]:
        digest = _args_hash(candidate)
        gctx = GateContext(
            now=now,
            governance_scope=_BASELINE_SCOPE,
            policy=PolicyRef(policy_id=_BASELINE_POLICY_ID),
            risk_level=tier.value,
            approved_args_hash=digest,
            approved_args_algo=_ARGS_ALGO,
            actual_args_hash=digest,
            actual_args_algo=_ARGS_ALGO,
            poisoning_severity=0.0,  # declared: no poisoning signal injected, none scanned
            actor_id=ctx.actor_id or None,
            required_tier=_RBAC_TIER.get(tier),
        )
        return self._registry.evaluate_all(gctx, self._settings)

    def _evaluate(self, candidate: GateCandidate, ctx: EvaluationContext) -> DagVerdict:
        now = self._clock()
        tier = impact_tier_of(candidate.risk_level)
        results = self._gate_results(candidate, ctx, tier, now)
        failed = [r for r in results if not r.passed]
        impact_zero = _impact_is_zero(ctx)
        within_ceiling = tier_ge(self._routing.tier_automation_max, tier)

        failure_codes: list[str] = [c for r in failed for c in r.reason_codes]
        if not results or any(r.severity == "CRITICAL" for r in failed):
            outcome, codes = GateOutcome.REJECT, failure_codes or [_EVAL_ERROR_CODE]
        elif failed:
            outcome, codes = GateOutcome.HOLD, [*failure_codes, NO_EVIDENCE_CODE]
        elif within_ceiling and impact_zero:
            outcome, codes = GateOutcome.EXECUTE, []
        else:
            outcome, codes = GateOutcome.HOLD, [NO_EVIDENCE_CODE]

        errors: list[str] = []
        codes = list(dict.fromkeys(codes))
        passed_all = bool(results) and not failed
        try:
            self._record(candidate, ctx, tier, now, results, outcome, codes, impact_zero, passed_all)
        except Exception as exc:  # the event is the audit trail: no event, no EXECUTE
            reason = getattr(exc, "reason_code", type(exc).__name__)
            logger.error("DAG baseline provenance write failed: %s", reason)
            errors.append(f"provenance: {reason}")
            codes = list(dict.fromkeys([*codes, _EMIT_FAILED_CODE]))
            if outcome is GateOutcome.EXECUTE:
                outcome, codes = GateOutcome.HOLD, list(dict.fromkeys([*codes, NO_EVIDENCE_CODE]))

        record = DeterminismRecord(
            inputs_hash=_inputs_hash(
                {
                    "risk": tier.value,
                    "impact_zero": impact_zero,
                    "within_ceiling": within_ceiling,
                    "hard_gates": {r.rule_id: r.passed for r in results},
                }
            ),
            rule_id=BASELINE_RULE_ID,
            rule_version=RULE_VERSION_ROUTE,
            config_version=self._config_version,
            decisive_conditions=[BASELINE_RULE_ID],
        )
        verdict = GateVerdict(
            outcome=outcome,
            reason_codes=codes,
            hard_gate_results=[HardGateResultRef.from_result(r) for r in results],
            decisive_rule=BASELINE_RULE_ID,
            evaluation_errors=errors,
            determinism_record=record,
            evaluated_at=now,
        )
        return DagVerdict(
            verdict,
            "v_" + uuid.uuid4().hex,
            fingerprint(BASELINE_RULE_ID, codes, ()),
            tier,
            f"{BASELINE_RULE_ID}: {outcome.value}",
        )

    def _record(
        self,
        candidate: GateCandidate,
        ctx: EvaluationContext,
        tier: ImpactTier,
        now: datetime,
        results: tuple[HardGateResult, ...],
        outcome: GateOutcome,
        codes: list[str],
        impact_zero: bool,
        passed_all: bool,
    ) -> None:
        hold_code = NO_EVIDENCE_CODE if NO_EVIDENCE_CODE in codes else "NONE"
        refs = [
            f"policy:{_BASELINE_POLICY_ID}",
            "classification:PUBLIC",
            f"rule:{BASELINE_RULE_ID}",
            f"vector_source:{_VECTOR_SOURCE}",
            f"evidence_tier:{_EVIDENCE_TIER}",
            f"decision_path:{_DECISION_PATH}",
            f"validation_status:{_PASSED if passed_all else _FAILED}",
            f"hold_code:{hold_code}",
            f"risk:{tier.value}",
            f"impact:{'ZERO' if impact_zero else 'NONZERO_OR_UNKNOWN'}",
            "actor_tier:LOWEST",
            "contradictions:NONE_INJECTED_GRAPH_NOT_CONSULTED",
            "dependency_nodes:NONE",
            "freshness:CURRENT",
        ]
        self._recorder.record(
            event_type=EventType.DECISION_GATE_EVALUATED,
            actor=Actor(
                agent_id=ctx.actor_id or _AGENT_FALLBACK,
                type=ActorType.SOFTWARE_AGENT,
                identity_assurance=IdentityAssurance.IAL1,
            ),
            activity=Activity(
                decision_id=new_id("dec"),
                trajectory_id=BASELINE_TRAJECTORY,
                checkpoint=0,
                model_version="n/a",
                rule_set_version=RULE_VERSION_ROUTE,
                policy_bundle_version=_BASELINE_POLICY_ID,
                config_version=self._config_version.removeprefix("sha256:"),
            ),
            inputs=Inputs(
                policy_refs=refs,
                candidate_action_hash=_args_hash(candidate),
                candidate_action_hash_algo=_ARGS_ALGO,
            ),
            assessment=Assessment(
                hard_gate_results=[_event_gate_result(r) for r in results],
                outcome=outcome.value,
                reason_codes=codes,
            ),
            occurred_at=rfc3339(now),
        )
