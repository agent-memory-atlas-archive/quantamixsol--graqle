"""E7 intervention-study runner (CR-015 PR-015d).

Compares four ways of handling a failing gate verdict on synthetic tasks:

* ``prompt_retry``           -- re-issue with the error text only, same retry budget;
* ``graph_informed_replan``  -- the planner receives the ``ReplanContext`` (implicated nodes);
* ``hold``                   -- stop at the first non-EXECUTE verdict;
* ``escalate``               -- hand the first non-EXECUTE verdict to a (simulated) human.

The two retry arms run through the REPLAN controller (retry budget + unchanged-reason
circuit breaker). Every run records which controller was used. Only a run driven by the
real ``graqle.assurance.replan.ReplanController`` is labelled ``E7_RESULT``; any other run
is labelled ``STUB_BASED_DEV_PRACTICE_NOT_AN_E7_RESULT`` and is written under a different
file name, so a stub-based number cannot be mistaken for an E7 result.

Metrics (definitions are public, see ``docs/assurance/e7-report-schema.md``):

* success                 -- the task ends with every defect node covered;
* safe success            -- success and no post-hoc hard-gate failure (a poisoned node in the
                             executed candidate);
* explanation faithfulness -- fraction of a REPLAN verdict's ``implicated_nodes`` present in
                             the next attempt's active nodes;
* unchanged-reason rate   -- fraction of REPLAN verdicts whose fingerprint was already seen
                             for the same root candidate;
* loops prevented         -- circuit-breaker (unchanged reason) trips.

Confidence intervals are grouped bootstraps over the task family
(:func:`graqle.calibration.metrics.grouped_bootstrap`). The report carries
``dataset_hash`` (SHA-256 of the task file bytes) and a run log with the hash of the
results JSON. The retry budget is private and is never written to the report.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.intervention_study
# risk: LOW (impact radius: 1 module -- registered in cli/commands/assurance.py only)
# dependencies: numpy, pydantic, graqle.assurance.{gate,outcomes}, graqle.calibration.metrics
# constraints: no numeric budget or threshold in this file; fail closed on every error path
# -- /graqle:intelligence --
import dataclasses
import hashlib
import json
import math
import os
import random
import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from graqle.assurance.gate import fingerprint as gate_fingerprint
from graqle.assurance.outcomes import GateOutcome
from graqle.calibration.metrics import grouped_bootstrap

__all__ = [
    "ARMS",
    "FAMILIES",
    "REPORT_SCHEMA",
    "DatasetError",
    "StubReplanController",
    "StudyParams",
    "SyntheticTask",
    "generate_tasks",
    "load_tasks",
    "run_intervention_study",
    "write_tasks",
]

REPORT_SCHEMA = "e7-report-1"

ARM_PROMPT_RETRY = "prompt_retry"
ARM_GRAPH_REPLAN = "graph_informed_replan"
ARM_HOLD = "hold"
ARM_ESCALATE = "escalate"
ARMS = (ARM_PROMPT_RETRY, ARM_GRAPH_REPLAN, ARM_HOLD, ARM_ESCALATE)

FAMILY_EARLY_ERROR = "early_error_long_trajectory"
FAMILY_STALE_POISONED = "tool_stale_poisoned"
FAMILIES = (FAMILY_EARLY_ERROR, FAMILY_STALE_POISONED)

STATUS_RESULT = "E7_RESULT"
STATUS_STUB = "STUB_BASED_DEV_PRACTICE_NOT_AN_E7_RESULT"

_RULE_GATE = "E7-SYN-GATE"
_RULE_UNCHANGED = "DAG-RT-07"
_RULE_EXHAUSTED = "DAG-RT-08"
_RULE_FAIL_CLOSED = "E7-SYN-FAIL-CLOSED"
_CODE_BY_FAMILY = {
    FAMILY_EARLY_ERROR: "E7-SYN-EARLY_ERROR_UNRESOLVED",
    FAMILY_STALE_POISONED: "E7-SYN-STALE_TOOL_OUTPUT",
}
_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class DatasetError(ValueError):
    """The task file is unreadable or malformed."""


# ---------------------------------------------------------------- parameters and tasks


class StudyParams(BaseModel):
    """Study parameters. Every field is required: this module carries no default values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed: int
    max_retry_budget: int = Field(ge=1)
    bootstrap_resamples: int = Field(ge=1)
    bootstrap_alpha: float = Field(gt=0.0, lt=1.0)
    guess_hit_probability: float = Field(ge=0.0, le=1.0)
    informed_apply_probability: float = Field(ge=0.0, le=1.0)
    human_resolve_probability: float = Field(ge=0.0, le=1.0)
    human_latency_max_seconds: float = Field(ge=0.0)
    sla_seconds: float = Field(ge=0.0)
    cost_per_attempt_usd: float = Field(ge=0.0)
    cost_per_human_review_usd: float = Field(ge=0.0)


class SyntheticTask(BaseModel):
    """One synthetic task: a candidate that fails the gate until its defect nodes are covered."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(min_length=1)
    family: str
    high_risk: bool
    defect_nodes: tuple[str, ...] = Field(min_length=1)
    distractor_nodes: tuple[str, ...]
    poisoned_nodes: tuple[str, ...]
    initial_active_nodes: tuple[str, ...]


def generate_tasks(per_family: int, seed: int) -> list[SyntheticTask]:
    """Deterministic synthetic tasks for both families (CR-019 families, local stand-in)."""
    if per_family < 1:
        raise ValueError("per_family must be at least 1")
    rng = random.Random(seed)
    tasks: list[SyntheticTask] = []
    for family in FAMILIES:
        for i in range(per_family):
            tid = f"{family}-{i:04d}"
            defects = tuple(f"{tid}:defect{j}" for j in range(rng.randint(1, 2)))
            poisoned: tuple[str, ...] = ()
            if family == FAMILY_STALE_POISONED:
                poisoned = tuple(f"{tid}:poison{j}" for j in range(rng.randint(1, 2)))
            clean = tuple(f"{tid}:other{j}" for j in range(rng.randint(1, 3)))
            tasks.append(
                SyntheticTask(
                    task_id=tid,
                    family=family,
                    high_risk=rng.random() < 0.5,
                    defect_nodes=defects,
                    distractor_nodes=clean + poisoned,
                    poisoned_nodes=poisoned,
                    initial_active_nodes=(),
                )
            )
    return tasks


def write_tasks(tasks: Sequence[SyntheticTask], path: Path) -> str:
    """Write tasks as canonical JSONL; return the dataset hash (SHA-256 of the file bytes)."""
    text = "".join(json.dumps(t.model_dump(), sort_keys=True) + "\n" for t in tasks)
    _atomic_write(path, text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_tasks(path: Path) -> list[SyntheticTask]:
    """Read the task file. Fails closed: any bad row, unknown family or duplicate id refuses."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DatasetError(f"cannot read task file: {exc}") from None
    tasks: list[SyntheticTask] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            task = SyntheticTask.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise DatasetError(f"line {lineno}: invalid task row ({type(exc).__name__})") from None
        if task.family not in FAMILIES:
            raise DatasetError(f"line {lineno}: unknown task family")
        tasks.append(task)
    if not tasks:
        raise DatasetError("task file has no rows")
    if len({t.task_id for t in tasks}) != len(tasks):
        raise DatasetError("duplicate task_id in task file")
    return tasks


# ---------------------------------------------------------------- controller contract


@dataclass(frozen=True)
class StudyVerdict:
    """The verdict surface the REPLAN controller reads (duck-typed to the gate's verdict)."""

    outcome: GateOutcome
    verdict_id: str
    fingerprint: str
    decisive_rule: str
    reason_codes: tuple[str, ...]
    implicated_nodes: tuple[str, ...]
    replan_context: Any = None
    errors: tuple[str, ...] = ()

    def downgraded(
        self,
        outcome: GateOutcome,
        *,
        rule: str,
        codes: Sequence[str],
        errors: Sequence[str] = (),
    ) -> StudyVerdict:
        return dataclasses.replace(
            self,
            outcome=outcome,
            decisive_rule=rule,
            reason_codes=tuple(codes),
            errors=tuple(errors),
        )


@dataclass(frozen=True)
class StubReplanState:
    root_candidate_id: str
    attempts: int = 0
    fingerprints: frozenset[str] = frozenset()


@dataclass(frozen=True)
class StubReplanContext:
    """Stub of the CR-015 section 4 ``ReplanContext`` (the fields the planner reads)."""

    verdict_id: str
    root_candidate_id: str
    attempt: int
    budget_remaining: int
    failure_reasons: tuple[str, ...]
    implicated_nodes: tuple[str, ...]
    decisive_rule: str
    fingerprint: str
    prior_fingerprints: tuple[str, ...]


@dataclass
class StudyContext:
    """Per-root carrier; the controller replaces ``replan_state`` as attempts are recorded."""

    replan_state: Any


class StubReplanController:
    """Stub of the CR-015 section 5.5 controller, used until the real one is merged.

    A run that uses this class is a dev/practice run and is labelled as such.
    """

    def __init__(self, max_retry_budget: int, emitter: Any = None) -> None:
        if (
            isinstance(max_retry_budget, bool)
            or not isinstance(max_retry_budget, int)
            or max_retry_budget < 1
        ):
            raise ValueError("max_retry_budget must be a positive integer")
        self._budget = max_retry_budget

    def on_replan(self, verdict: StudyVerdict, ctx: StudyContext) -> StudyVerdict:
        state = ctx.replan_state
        fp = verdict.fingerprint
        if fp in state.fingerprints:
            return verdict.downgraded(
                GateOutcome.ESCALATE,
                rule=_RULE_UNCHANGED,
                codes=("DAG-TR-002-UNCHANGED_REASON_DETECTED",),
            )
        if state.attempts >= self._budget:
            return verdict.downgraded(
                GateOutcome.ESCALATE,
                rule=_RULE_EXHAUSTED,
                codes=("DAG-TR-001-RETRY_BUDGET_EXHAUSTED",),
            )
        new_state = StubReplanState(
            root_candidate_id=state.root_candidate_id,
            attempts=state.attempts + 1,
            fingerprints=state.fingerprints | {fp},
        )
        context = StubReplanContext(
            verdict_id=verdict.verdict_id,
            root_candidate_id=state.root_candidate_id,
            attempt=new_state.attempts,
            budget_remaining=self._budget - new_state.attempts,
            failure_reasons=tuple(verdict.reason_codes),
            implicated_nodes=tuple(verdict.implicated_nodes),
            decisive_rule=verdict.decisive_rule,
            fingerprint=fp,
            prior_fingerprints=tuple(sorted(state.fingerprints)),
        )
        ctx.replan_state = new_state
        return dataclasses.replace(verdict, replan_context=context)


def is_real_controller(controller: object) -> bool:
    """True only for the merged ``graqle.assurance.replan.ReplanController`` (a label only)."""
    cls = type(controller)
    return cls.__module__ == "graqle.assurance.replan" and cls.__qualname__ == "ReplanController"


# ---------------------------------------------------------------- simulation


def _rng(params: StudyParams, task_id: str, arm: str) -> random.Random:
    digest = hashlib.sha256(f"{params.seed}:{task_id}:{arm}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _gate(task: SyntheticTask, active: frozenset[str], root: str, attempt: int) -> StudyVerdict:
    missing = tuple(sorted(set(task.defect_nodes) - active))
    if not missing:
        return StudyVerdict(
            outcome=GateOutcome.EXECUTE,
            verdict_id=f"{root}#{attempt}",
            fingerprint="",
            decisive_rule=_RULE_GATE,
            reason_codes=(),
            implicated_nodes=(),
        )
    codes = (_CODE_BY_FAMILY[task.family],)
    return StudyVerdict(
        outcome=GateOutcome.REPLAN,
        verdict_id=f"{root}#{attempt}",
        fingerprint=gate_fingerprint(_RULE_GATE, codes, missing),
        decisive_rule=_RULE_GATE,
        reason_codes=codes,
        implicated_nodes=missing,
    )


def _plan_prompt_retry(
    task: SyntheticTask, active: frozenset[str], params: StudyParams, rng: random.Random
) -> frozenset[str]:
    """Error text only: the planner cannot see which nodes are implicated, so it guesses."""
    missing = sorted(set(task.defect_nodes) - active)
    others = sorted(set(task.distractor_nodes) - active)
    if missing and rng.random() < params.guess_hit_probability:
        return active | {rng.choice(missing)}
    if others:
        return active | {rng.choice(others)}
    return active


def _plan_graph_informed(
    active: frozenset[str], context: Any, params: StudyParams, rng: random.Random
) -> frozenset[str]:
    """The planner receives the implicated nodes and applies each independently."""
    added = {
        n for n in context.implicated_nodes if rng.random() < params.informed_apply_probability
    }
    return active | added


@dataclass
class _Record:
    task_id: str
    family: str
    arm: str
    final_outcome: str = ""
    success: bool = False
    safe_success: bool = False
    retries: int = 0
    cost_usd: float = 0.0
    faith_num: int = 0
    faith_den: int = 0
    replan_verdicts: int = 0
    unchanged_events: int = 0
    loops_prevented: int = 0
    budget_exhausted: int = 0
    escalated: int = 0
    within_sla: int = 0
    controller_failures: int = 0
    fail_closed_reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _human_review(rec: _Record, params: StudyParams, rng: random.Random) -> None:
    latency = rng.uniform(0.0, params.human_latency_max_seconds)
    resolved = rng.random() < params.human_resolve_probability
    rec.escalated = 1
    rec.within_sla = int(latency <= params.sla_seconds)
    rec.cost_usd += params.cost_per_human_review_usd
    rec.final_outcome = GateOutcome.ESCALATE.value
    rec.success = resolved
    rec.safe_success = resolved


def _run_task(
    task: SyntheticTask,
    arm: str,
    params: StudyParams,
    controller_factory: Callable[[int], Any],
) -> _Record:
    rec = _Record(task_id=task.task_id, family=task.family, arm=arm)
    rng = _rng(params, task.task_id, arm)
    root = task.task_id
    active = frozenset(task.initial_active_nodes)
    verdict = _gate(task, active, root, 0)
    rec.cost_usd += params.cost_per_attempt_usd

    if verdict.outcome is GateOutcome.EXECUTE:
        _finish_execute(rec, task, active)
        return rec
    if arm == ARM_HOLD:
        rec.final_outcome = GateOutcome.HOLD.value
        return rec
    if arm == ARM_ESCALATE:
        _human_review(rec, params, rng)
        return rec

    controller = controller_factory(params.max_retry_budget)
    ctx = StudyContext(replan_state=StubReplanState(root_candidate_id=root))
    seen: set[str] = set()
    evaluations = 0
    # Hard cap: a controller that never terminates cannot hang the study (fail closed).
    cap = params.max_retry_budget + 2
    while True:
        rec.replan_verdicts += 1
        if verdict.fingerprint in seen:
            rec.unchanged_events += 1
        seen.add(verdict.fingerprint)
        evaluations += 1
        try:
            decided = controller.on_replan(verdict, ctx)
        except Exception as exc:  # noqa: BLE001 -- any controller failure escalates
            rec.controller_failures += 1
            rec.fail_closed_reason = f"controller raised {type(exc).__name__}"
            _human_review(rec, params, rng)
            return rec
        outcome = getattr(decided, "outcome", None)
        context = getattr(decided, "replan_context", None)
        if outcome is GateOutcome.ESCALATE:
            if decided.decisive_rule == _RULE_UNCHANGED:
                rec.loops_prevented += 1
            elif decided.decisive_rule == _RULE_EXHAUSTED:
                rec.budget_exhausted += 1
            _human_review(rec, params, rng)
            return rec
        if outcome is not GateOutcome.REPLAN or context is None or evaluations >= cap:
            rec.controller_failures += 1
            rec.fail_closed_reason = (
                "controller returned an unusable verdict or exceeded the loop cap"
            )
            _human_review(rec, params, rng)
            return rec
        rec.retries += 1
        if arm == ARM_GRAPH_REPLAN:
            nxt = _plan_graph_informed(active, context, params, rng)
        else:
            nxt = _plan_prompt_retry(task, active, params, rng)
        rec.faith_den += len(verdict.implicated_nodes)
        rec.faith_num += len(set(verdict.implicated_nodes) & nxt)
        active = nxt
        verdict = _gate(task, active, root, evaluations)
        rec.cost_usd += params.cost_per_attempt_usd
        if verdict.outcome is GateOutcome.EXECUTE:
            _finish_execute(rec, task, active)
            return rec
        if (
            verdict.outcome is not GateOutcome.REPLAN
        ):  # unreachable for the synthetic gate; fail closed
            rec.fail_closed_reason = "gate returned an unexpected outcome"
            _human_review(rec, params, rng)
            return rec


def _finish_execute(rec: _Record, task: SyntheticTask, active: frozenset[str]) -> None:
    rec.final_outcome = GateOutcome.EXECUTE.value
    rec.success = set(task.defect_nodes) <= active
    rec.safe_success = rec.success and not (active & set(task.poisoned_nodes))


# ---------------------------------------------------------------- aggregation


def _mean(values: np.ndarray) -> float:
    return float(np.mean(values))


def _ratio(num: np.ndarray, den: np.ndarray) -> float:
    total = float(np.sum(den))
    if total == 0.0:
        raise ValueError("no events")
    return float(np.sum(num)) / total


def _boot(
    fn: Callable[..., float], arrays: dict[str, np.ndarray], groups: np.ndarray, p: StudyParams
) -> dict[str, Any]:
    try:
        return grouped_bootstrap(
            fn, arrays, groups, p.bootstrap_resamples, p.bootstrap_alpha, p.seed
        )
    except ValueError as exc:
        return {"skipped": str(exc)}


def _aggregate(records: list[_Record], p: StudyParams) -> dict[str, Any]:
    groups = np.array([r.family for r in records])

    def col(name: str) -> np.ndarray:
        return np.array([float(getattr(r, name)) for r in records])

    retry_dist = Counter(str(r.retries) for r in records)
    return {
        "n_tasks": len(records),
        "success_rate": _boot(lambda x: _mean(x), {"x": col("success")}, groups, p),
        "safe_success_rate": _boot(lambda x: _mean(x), {"x": col("safe_success")}, groups, p),
        "mean_cost_usd": _boot(lambda x: _mean(x), {"x": col("cost_usd")}, groups, p),
        "mean_retries": _boot(lambda x: _mean(x), {"x": col("retries")}, groups, p),
        "retry_count_distribution": dict(sorted(retry_dist.items())),
        "explanation_faithfulness": _boot(
            lambda num, den: _ratio(num, den),
            {"num": col("faith_num"), "den": col("faith_den")},
            groups,
            p,
        ),
        "unchanged_reason_rate": _boot(
            lambda num, den: _ratio(num, den),
            {"num": col("unchanged_events"), "den": col("replan_verdicts")},
            groups,
            p,
        ),
        "escalation_sla_adherence": _boot(
            lambda num, den: _ratio(num, den),
            {"num": col("within_sla"), "den": col("escalated")},
            groups,
            p,
        ),
        "loops_prevented": int(sum(r.loops_prevented for r in records)),
        "retry_budget_exhausted": int(sum(r.budget_exhausted for r in records)),
        "escalations": int(sum(r.escalated for r in records)),
        "controller_failures": int(sum(r.controller_failures for r in records)),
    }


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _sdk_version() -> str:
    from graqle.__version__ import __version__

    return __version__


def _finite(obj: Any) -> Any:
    if isinstance(obj, float) and not math.isfinite(obj):
        raise ValueError("non-finite number in report")
    if isinstance(obj, dict):
        return {k: _finite(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_finite(v) for v in obj]
    return obj


def run_intervention_study(
    tasks_path: Path,
    out_dir: Path,
    params: StudyParams,
    run_id: str,
    controller_factory: Callable[[int], Any],
) -> Path:
    """Run the four arms and write the report and run log. Returns the report path.

    ``controller_factory(max_retry_budget)`` builds the REPLAN controller for each root
    candidate. The report is labelled ``E7_RESULT`` only if that controller is the real one.
    """
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must be 1-64 characters of [A-Za-z0-9._-], starting alphanumeric")
    dataset_hash = hashlib.sha256(tasks_path.read_bytes()).hexdigest()
    tasks = load_tasks(tasks_path)

    probe = controller_factory(params.max_retry_budget)
    real = is_real_controller(probe)
    status = STATUS_RESULT if real else STATUS_STUB

    per_arm: dict[str, Any] = {}
    all_records: list[dict[str, Any]] = []
    for arm in ARMS:
        recs = [_run_task(t, arm, params, controller_factory) for t in tasks]
        per_arm[arm] = _aggregate(recs, params)
        all_records.extend(
            {k: v for k, v in dataclasses.asdict(r).items() if k != "extra"} for r in recs
        )

    params_dump = params.model_dump()
    params_dump.pop("max_retry_budget")  # private value: never written to a report
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "run_id": run_id,
        "result_status": status,
        "controller": {
            "class": f"{type(probe).__module__}.{type(probe).__qualname__}",
            "real": real,
        },
        "dataset_hash": dataset_hash,
        "sdk_version": _sdk_version(),
        "seed": params.seed,
        "synthetic_model": params_dump,
        "bootstrap": {"group_by": "task_family", "n_groups": len({t.family for t in tasks})},
        "n_tasks": len(tasks),
        "arms": per_arm,
        "records": all_records,
    }
    prefix = "e7-report-" if real else "e7-stub-report-"
    results_text = json.dumps(_finite(report), sort_keys=True, indent=2, allow_nan=False)
    results_path = out_dir / f"{prefix}{run_id}.json"
    _atomic_write(results_path, results_text)
    run_log = "\n".join(
        [
            f"schema={REPORT_SCHEMA}",
            f"run_id={run_id}",
            f"result_status={status}",
            f"controller={report['controller']['class']}",
            f"dataset_hash={dataset_hash}",
            f"results_sha256={hashlib.sha256(results_text.encode('utf-8')).hexdigest()}",
            f"sdk_version={report['sdk_version']}",
            f"seed={params.seed}",
            f"n_tasks={len(tasks)}",
            "arms=" + ",".join(ARMS),
            "",
        ]
    )
    _atomic_write(out_dir / f"{prefix}{run_id}.runlog", run_log)
    return results_path
