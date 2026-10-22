"""DAG-2026 trajectory checkpoints and the frozen history view (CR-015 §2.1, §4, PR-015a).

A trajectory is a sequence of per-step checkpoints ``cp_0 .. cp_n``. An estimator
may only ever see the prefix ``cp_0 .. cp_t`` (the no-post-outcome rule, charter
§6). That is enforced by construction:

* :meth:`TrajectoryHistory.view_until` copies ``cp_0 .. cp_t`` into a frozen tuple;
* :class:`HistoryView` keeps no reference to the parent history;
* :class:`TrajectoryMonitor` evaluates ``V_t`` BEFORE ``cp_{t+1}`` exists.

``HistoryView`` must never gain an accessor that can reach beyond ``t``; any
change to it is a Research-Team review item (the AC-3 test is the guard).

Trade-secret rule (CR-015 §12): this module holds no threshold, weight or
window value. The history window is an argument.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.trajectory
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015b/c)
# dependencies: hashlib, pydantic, graqle.assurance.outcomes,
#   graqle.governance.tamper_evidence.canonicalize (lazy)
# constraints: never imported by graqle.governance.*; HistoryView exposes
#   nothing beyond step t; no numeric literal for any trade-secret symbol
# -- /graqle:intelligence --
import hashlib
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from graqle.assurance.outcomes import GateOutcome

if TYPE_CHECKING:  # estimators imports this module; avoid the runtime cycle
    from graqle.assurance.estimators import TrajectoryEstimate, TrajectoryEstimator

__all__ = [
    "HistoryView",
    "PolicyCheckRecord",
    "PriorGateOutcome",
    "ToolErrorRecord",
    "TrajectoryCheckpoint",
    "TrajectoryHistory",
    "TrajectoryMonitor",
]


class ToolErrorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step: int = Field(ge=0)
    tool: str
    error_class: str
    retryable: bool


class PolicyCheckRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step: int = Field(ge=0)
    policy_id: str
    passed: bool
    rule_version: str


class PriorGateOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step: int = Field(ge=0)
    outcome: GateOutcome
    fingerprint: str
    verdict_id: str


class TrajectoryCheckpoint(BaseModel):
    """State of the trajectory at absolute step ``step_index`` (never normalised)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoint_id: str
    session_id: str
    turn_id: str  # chat/permission_manager.TurnCheckpoint.turn_id
    step_index: int = Field(ge=0)
    timestamp_unix: float = Field(allow_inf_nan=False)
    candidate_id: str
    is_retry: bool = False
    accepted_evidence_ids: tuple[str, ...] = ()
    rejected_evidence_ids: tuple[str, ...] = ()
    tool_calls: int = Field(default=0, ge=0)
    tool_errors: tuple[ToolErrorRecord, ...] = ()
    unresolved_conflict_ids: tuple[str, ...] = ()
    policy_checks: tuple[PolicyCheckRecord, ...] = ()
    path_depth: int = Field(default=0, ge=0)
    #: outcome of the evaluation at THIS step; filled after evaluate (record_outcome)
    prior_gate_outcome: PriorGateOutcome | None = None
    #: CR-014 raw temporal validity over the evidence accepted at this step
    evidence_freshness: float | None = Field(default=None, ge=0.0, le=1.0, allow_inf_nan=False)
    prev_checkpoint_hash: str | None = None
    checkpoint_hash: str = ""  # computed on append

    def public_dict(self) -> dict[str, Any]:
        """JSON-safe content that the hash chain commits to (no own hash)."""
        return self.model_dump(mode="json", exclude={"checkpoint_hash"})


def _canon(record: dict[str, Any]) -> bytes:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return canon(record)


def checkpoint_hash(cp: TrajectoryCheckpoint) -> str:
    """``sha256(canon(public_dict))``; ``prev_checkpoint_hash`` is part of the dict."""
    return "sha256:" + hashlib.sha256(_canon(cp.public_dict())).hexdigest()


class HistoryView(BaseModel):
    """Frozen prefix ``cp_0 .. cp_t``. Holds NO reference to the parent history."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    t: int = Field(ge=0)
    checkpoints: tuple[TrajectoryCheckpoint, ...]

    @model_validator(mode="after")
    def _prefix(self) -> HistoryView:
        if len(self.checkpoints) != self.t + 1 or any(
            cp.step_index != i for i, cp in enumerate(self.checkpoints)
        ):
            raise ValueError("HistoryView must be the exact prefix cp_0..cp_t")
        if any(cp.session_id != self.session_id for cp in self.checkpoints):
            raise ValueError("HistoryView checkpoints must share the view's session_id")
        return self

    # -- feature accessors: every one is a pure function of the prefix ----------

    def elapsed_steps(self) -> int:
        return self.t

    def retry_count(self) -> int:
        return sum(1 for cp in self.checkpoints if cp.is_retry)

    def unresolved_contradictions(self) -> int:
        return len(self.checkpoints[-1].unresolved_conflict_ids)

    def evidence_freshness(self) -> float | None:
        """Freshness of the evidence accepted at step t, or ``None`` (NA)."""
        return self.checkpoints[-1].evidence_freshness

    def tool_failure_history(self, window: int) -> float:
        """Tool errors over tool calls in the last ``window`` steps, clamped to [0, 1].

        No calls in the window means no recorded failures (0.0); errors are counted
        even when calls are under-reported, and the ratio is clamped (fail-closed
        towards the worst value rather than exceeding the unit interval).
        """
        if window < 1:
            raise ValueError("window must be a positive number of steps")
        recent = self.checkpoints[-window:]
        errors = sum(len(cp.tool_errors) for cp in recent)
        calls = sum(cp.tool_calls for cp in recent)
        return min(1.0, errors / max(calls, 1))

    def prior_gate_outcomes(self) -> tuple[PriorGateOutcome, ...]:
        """Outcomes of evaluations at steps strictly before t (t's own is not yet known)."""
        return tuple(
            cp.prior_gate_outcome
            for cp in self.checkpoints[:-1]
            if cp.prior_gate_outcome is not None
        )

    def fingerprints_seen(self) -> frozenset[str]:
        return frozenset(o.fingerprint for o in self.prior_gate_outcomes())


class TrajectoryHistory(BaseModel):
    """Append-only, hash-chained list of checkpoints for one session."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    checkpoints: list[TrajectoryCheckpoint] = Field(default_factory=list)

    def append(self, cp: TrajectoryCheckpoint) -> None:
        """Validate ordering and session, chain the hash, and store a hashed copy."""
        if cp.session_id != self.session_id:
            raise ValueError("checkpoint session_id does not match the history")
        if cp.step_index != len(self.checkpoints):
            raise ValueError(
                f"out-of-order step_index {cp.step_index}; expected {len(self.checkpoints)}"
            )
        prev = self.checkpoints[-1].checkpoint_hash if self.checkpoints else None
        if cp.prev_checkpoint_hash not in (None, prev):
            raise ValueError("prev_checkpoint_hash does not match the chain head")
        chained = cp.model_copy(update={"prev_checkpoint_hash": prev, "checkpoint_hash": ""})
        self.checkpoints.append(chained.model_copy(update={"checkpoint_hash": checkpoint_hash(chained)}))

    def view_until(self, t: int) -> HistoryView:
        if not self.checkpoints or not 0 <= t < len(self.checkpoints):
            raise ValueError(f"step {t} is outside the recorded history")
        return HistoryView(
            session_id=self.session_id, t=t, checkpoints=tuple(self.checkpoints[: t + 1])
        )

    def verify_chain(self) -> bool:
        """True iff every stored hash matches its content and links to its predecessor."""
        prev: str | None = None
        for cp in self.checkpoints:
            if cp.prev_checkpoint_hash != prev or cp.checkpoint_hash != checkpoint_hash(cp):
                return False
            prev = cp.checkpoint_hash
        return True


class TrajectoryMonitor:
    """Append/evaluate discipline: evaluate ``V_t`` before ``cp_{t+1}`` exists.

    Single-writer: one monitor owns one history; concurrent callers must serialise
    ``checkpoint`` / ``record_outcome`` themselves.
    """

    def __init__(self, history: TrajectoryHistory, estimator: TrajectoryEstimator, window: int) -> None:
        if window < 1:
            raise ValueError("window must be a positive number of steps")
        self.history = history
        self.estimator = estimator
        self.window = window

    def checkpoint(self, cp: TrajectoryCheckpoint) -> HistoryView:
        self.history.append(cp)
        return self.history.view_until(cp.step_index)

    def evaluate(self, view: HistoryView) -> TrajectoryEstimate:
        """Estimate reliability from ``view`` only."""
        return self.estimator.estimate(view)

    def record_outcome(self, t: int, outcome: PriorGateOutcome) -> None:
        """Attach the gate outcome to the LAST checkpoint, once, and re-hash it."""
        if not self.history.checkpoints or t != self.history.checkpoints[-1].step_index:
            raise ValueError("an outcome can only be recorded on the last checkpoint")
        if outcome.step != t:
            raise ValueError("outcome.step must equal the checkpoint step")
        last = self.history.checkpoints[-1]
        if last.prior_gate_outcome is not None:
            raise ValueError("an outcome is already recorded for this checkpoint")
        updated = last.model_copy(update={"prior_gate_outcome": outcome, "checkpoint_hash": ""})
        self.history.checkpoints[-1] = updated.model_copy(
            update={"checkpoint_hash": checkpoint_hash(updated)}
        )
