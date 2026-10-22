"""Stub CR-013/014 stages and settings for the CR-015 PR-015b gate tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from graqle.assurance.gate import (
    DecisionAssuranceGate,
    EvaluationContext,
    GateCandidate,
    GateComponents,
    ImpactTier,
    ProjectionStageResult,
)
from graqle.assurance.hard_gates import HardGateResult
from graqle.assurance.trajectory import TrajectoryCheckpoint, TrajectoryHistory

# Symbolic test values only; none is a deployment value.
FLOORS = {ImpactTier.LOW: 0.2, ImpactTier.MEDIUM: 0.3, ImpactTier.HIGH: 0.4, ImpactTier.CRITICAL: 0.5}
BUDGETS = {ImpactTier.LOW: 0.6, ImpactTier.MEDIUM: 0.5, ImpactTier.HIGH: 0.4, ImpactTier.CRITICAL: 0.3}
_HASH = "sha256:" + "0" * 64


@dataclass(frozen=True)
class FakeRouting:
    trajectory_floor: dict = field(default_factory=lambda: dict(FLOORS))
    residual_risk_budget: dict = field(default_factory=lambda: dict(BUDGETS))
    tier_automation_max: ImpactTier = ImpactTier.CRITICAL


def hg(rule_id: str, *, passed: bool = True, severity: str = "CRITICAL", codes: tuple[str, ...] = ()) -> HardGateResult:
    return HardGateResult(
        rule_id=rule_id,
        rule_version="1",
        severity=severity,
        passed=passed,
        reason_codes=codes,
        inputs_hash=_HASH,
        config_version="cfg-test",
        evaluated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_ms=0.0,
    )


@dataclass
class FakeCap:
    cap_applied: bool = False
    reason_codes: tuple[str, ...] = ()


@dataclass
class FakeEstimate:
    reliability: float = 0.9
    probabilistic: bool = False
    variance: float | None = None


class FakeEstimator:
    def __init__(self, reliability: float = 0.9, boom: bool = False) -> None:
        self.reliability, self.boom, self.seen_views = reliability, boom, []

    def estimate(self, view: Any) -> FakeEstimate:
        self.seen_views.append(view)
        if self.boom:
            raise RuntimeError("estimator down")
        return FakeEstimate(self.reliability)


def passing_gates(_c: Any, _x: Any) -> tuple[HardGateResult, ...]:
    return (hg("HG-01"), hg("HG-02"))


def good_projection(_c: Any, _x: Any, _r: Any, _cap: Any) -> ProjectionStageResult:
    return ProjectionStageResult(
        admitted=True, decision_score=0.95, calibration_stale=False, mandatory_na=False,
        confidence_vector={"correctness": 0.9},
    )


def make_components(**over: Any) -> GateComponents:
    base: dict[str, Any] = dict(
        hard_gates=passing_gates,
        cap=lambda _r, _x: FakeCap(),
        projection=good_projection,
        estimator=FakeEstimator(),
        may_automate=lambda _a, _t: True,
    )
    base.update(over)
    return GateComponents(**base)


def make_gate(components: GateComponents | None = None, *, budget: int = 2, routing: Any = None) -> DecisionAssuranceGate:
    return DecisionAssuranceGate(
        components=components or make_components(),
        routing=routing or FakeRouting(),
        max_retry_budget=budget,
        config_version="cfg-test",
        clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def make_ctx(**over: Any) -> EvaluationContext:
    history = TrajectoryHistory(session_id="s1")
    cp = TrajectoryCheckpoint(
        checkpoint_id="cp0", session_id="s1", turn_id="t0", step_index=0,
        timestamp_unix=1.0, candidate_id="cand",
    )
    history.append(cp)
    base: dict[str, Any] = dict(session_id="s1", actor_id="alice", history=history, checkpoint=cp)
    base.update(over)
    return EvaluationContext(**base)


CANDIDATE = GateCandidate(id="cand", risk_level="LOW", file_path="src/mod.py")
