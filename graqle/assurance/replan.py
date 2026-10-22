"""REPLAN controller: retry budget and unchanged-reason circuit breaker (CR-015 PR-015c).

The gate never loops. A REPLAN verdict is handed to :class:`ReplanController`, which

* ESCALATEs when the same fingerprint was seen before for this root candidate
  (any repeat, not only a consecutive one: DAG-TR-002), or when the retry budget
  is spent (DAG-TR-001) -- the circuit breaker (C12);
* otherwise records the attempt in a new immutable :class:`ReplanState`, emits a
  REPLAN provenance event as the *linear* successor of the chain head (never a
  fork), and attaches a :class:`ReplanContext` for the planner.

At most ``max_retry_budget`` REPLAN verdicts are issued per root candidate, hence
at most ``max_retry_budget + 1`` gate evaluations before a terminal outcome.

The budget is a private, required value: this module takes it as a constructor
argument and carries no default.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.replan
# risk: LOW (impact radius: 0 existing callers -- consumed by the gate via GateComponents.replan)
# dependencies: dataclasses, pydantic, graqle.assurance.gate, graqle.assurance.reason_codes
# constraints: no numeric budget or threshold in this file; fail closed on every error path
# -- /graqle:intelligence --
import dataclasses
from typing import Any

from pydantic import BaseModel, ConfigDict

from graqle.assurance.gate import DagVerdict, EvaluationContext
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.reason_codes import REGISTRY, resolvable

__all__ = ["ReasonCodeRef", "ReplanContext", "ReplanController", "ReplanState"]

_RULE_UNCHANGED = "DAG-RT-07"
_RULE_EXHAUSTED = "DAG-RT-08"
_CODE_UNCHANGED = "DAG-TR-002-UNCHANGED_REASON_DETECTED"
_CODE_EXHAUSTED = "DAG-TR-001-RETRY_BUDGET_EXHAUSTED"


class ReasonCodeRef(BaseModel):
    """A registered reason code with its public remediation hint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    remediation_hint: str


class ReplanState(BaseModel):
    """Per-root-candidate replan bookkeeping. Immutable: each attempt yields a new state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root_candidate_id: str
    attempts: int = 0
    fingerprints: frozenset[str] = frozenset()

    def with_attempt(self, fp: str) -> ReplanState:
        return ReplanState(
            root_candidate_id=self.root_candidate_id,
            attempts=self.attempts + 1,
            fingerprints=self.fingerprints | {fp},
        )


class ReplanContext(BaseModel):
    """What the planner receives with a REPLAN verdict (charter section 4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict_id: str
    root_candidate_id: str
    attempt: int
    budget_remaining: int
    failure_reasons: tuple[ReasonCodeRef, ...]
    implicated_nodes: tuple[str, ...]
    decisive_rule: str
    fingerprint: str
    prior_fingerprints: tuple[str, ...]


def _ref(code: str) -> ReasonCodeRef:
    return ReasonCodeRef(code=code, remediation_hint=REGISTRY[code].remediation_hint)


class ReplanController:
    """Implements ``GateComponents.replan`` (``on_replan(verdict, ctx) -> verdict``)."""

    def __init__(self, max_retry_budget: int, emitter: Any = None) -> None:
        if isinstance(max_retry_budget, bool) or not isinstance(max_retry_budget, int) or max_retry_budget < 1:
            raise ValueError("max_retry_budget must be a positive integer")
        self._budget = max_retry_budget
        self._emitter = emitter

    def on_replan(self, verdict: DagVerdict, ctx: EvaluationContext) -> DagVerdict:
        """Return the verdict with a :class:`ReplanContext`, or an ESCALATE verdict.

        Never returns EXECUTE. Raises only if the provenance emitter fails; the gate
        turns any raise from this hook into ESCALATE.
        """
        if verdict.outcome is not GateOutcome.REPLAN:
            return verdict.downgraded(
                GateOutcome.ESCALATE, rule=_RULE_EXHAUSTED, codes=(_CODE_EXHAUSTED,),
                errors=("replan: called with a non-REPLAN verdict",),
            )
        state = ctx.replan_state
        fp = verdict.fingerprint
        if fp in state.fingerprints:  # circuit breaker (C12): unchanged reason
            return verdict.downgraded(GateOutcome.ESCALATE, rule=_RULE_UNCHANGED, codes=(_CODE_UNCHANGED,))
        if state.attempts >= self._budget:
            return verdict.downgraded(GateOutcome.ESCALATE, rule=_RULE_EXHAUSTED, codes=(_CODE_EXHAUSTED,))

        root = getattr(state, "root_candidate_id", "") or ""
        if not root:
            raise ValueError("replan_state carries no root_candidate_id")  # gate escalates
        new_state = ReplanState(
            root_candidate_id=root,
            attempts=int(state.attempts),
            fingerprints=frozenset(state.fingerprints),
        ).with_attempt(fp)
        replan_ctx = ReplanContext(
            verdict_id=verdict.verdict_id,
            root_candidate_id=root,
            attempt=new_state.attempts,
            budget_remaining=self._budget - new_state.attempts,
            failure_reasons=tuple(_ref(c) for c in verdict.reason_codes if c in REGISTRY and resolvable(c)),
            implicated_nodes=tuple(verdict.implicated_nodes),
            decisive_rule=verdict.decisive_rule,
            fingerprint=fp,
            prior_fingerprints=tuple(sorted(state.fingerprints)),
        )
        if self._emitter is not None:
            # A linear successor of the chain head; the emitter assigns sequence and
            # previous-event hash. A failure here raises and the gate escalates.
            self._emitter.append(
                kind="REPLAN",
                subject_id=root,
                payload={
                    "verdict_id": verdict.verdict_id,
                    "attempt": new_state.attempts,
                    "fingerprint": fp,
                    "reason_codes": list(verdict.reason_codes),
                    "implicated_nodes": list(verdict.implicated_nodes),
                },
            )
        ctx.replan_state = new_state
        return dataclasses.replace(verdict, replan_context=replan_ctx)
