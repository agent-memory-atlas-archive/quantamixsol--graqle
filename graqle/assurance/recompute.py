"""Recompute queue and loop (CR-017 PR-017b, spec sections 2.5 and 5.7).

Every dirty node has a :class:`~graqle.assurance.conflicts.RecomputeTask`. The loop claims
tasks, re-derives each node from its current support, and writes the outcome as one
mutation. Rules:

* **Never ACTIVE by default.** A node returns to ACTIVE only after its recomputer ran
  without error. Any exception counts an attempt; when attempts reach the configured
  maximum the node is INVALIDATED with ``DAG-PV-RECOMPUTE-EXHAUSTED``.
* A node that is not ``PENDING_RECOMPUTE`` (already INVALIDATED, SUPERSEDED, ...) is never
  resurrected: its task is closed without a status write.
* A ``DEPTH_CAP`` task continues the propagation from its node, so the dependents beyond
  the depth cap are marked in the same mutation.
* A node with no recomputer registered for its class fails the attempt (fail closed).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.recompute
# risk: LOW (new module; writes only through the injected persister)
# dependencies: dataclasses, graqle.assurance.conflicts, graqle.assurance.propagation,
#   graqle.ontology.assurance
# constraints: attempt and batch limits are injected, never defaulted
# -- /graqle:intelligence --
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from graqle.assurance.conflicts import (
    AssuranceMutation,
    ConflictConfig,
    ConflictError,
    ConflictPersister,
    ConflictReader,
    NodeWrite,
    Propagator,
    PropValue,
    RecomputeTask,
    _now_iso,
    recompute_tasks,
    system_event,
)
from graqle.assurance.propagation import invalidate
from graqle.ontology.assurance import LifecycleStatus

__all__ = [
    "RECOMPUTE_ACTOR",
    "RecomputeConfig",
    "RecomputeQueue",
    "Neo4jRecomputeQueue",
    "Recomputer",
    "RecomputeReader",
    "LoopReport",
    "recompute_loop",
]

logger = logging.getLogger(__name__)

RECOMPUTE_ACTOR = "agent_recompute_worker"
_DEPTH_CAP = "DEPTH_CAP"
_CHECKED_CLASSES = frozenset({"Claim", "Abstraction"})
#: Properties a recomputer may not set: they belong to the loop and the persister.
_RESERVED = frozenset(
    {
        "id",
        "assurance_seq",
        "assurance_type",
        "lifecycle_status",
        "dirty",
        "dirty_since",
        "dirty_reason",
        "prov_event_id",
        "recomputed_at",
        "recompute_attempts",
        "superseded_by",
        "tombstone",
        "scope_key",
        "canonical_hash",
    }
)
_ERROR_CHARS = 200


@dataclass(frozen=True)
class RecomputeConfig:
    """Both limits have no default: they are protected values from private configuration."""

    max_attempts: int
    batch_size: int

    def __post_init__(self) -> None:
        for name in ("max_attempts", "batch_size"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ConflictError(f"{name} must be an integer of at least 1")


class RecomputeReader(ConflictReader, Protocol):
    def invalidated_upstream_count(self, node_id: str) -> int:
        """Number of DERIVED_FROM targets of ``node_id`` that are INVALIDATED."""


class Recomputer(Protocol):
    """Per-class recomputation (CR-014 vector recompute plugs in here). Raises on failure."""

    def recompute(self, node: Mapping[str, Any], reader: ConflictReader) -> Mapping[str, PropValue]: ...


class RecomputeQueue(Protocol):
    def claim(self, batch: int) -> Sequence[RecomputeTask]:
        """Move up to ``batch`` QUEUED tasks to RUNNING and return them."""

    def set_state(
        self, task: RecomputeTask, state: Literal["QUEUED", "RUNNING", "DONE", "EXHAUSTED"], attempts: int, error: str | None = None
    ) -> None: ...


class Neo4jRecomputeQueue:
    """Queue over ``:RecomputeTask`` nodes (no new label on CogniNode)."""

    def __init__(self, connector: Any) -> None:
        self._connector = connector

    def claim(self, batch: int) -> list[RecomputeTask]:
        fields = set(RecomputeTask.model_fields)
        return [
            RecomputeTask(**{k: v for k, v in props.items() if k in fields})
            for props in self._connector.claim_recompute_tasks(batch)
        ]

    def set_state(
        self, task: RecomputeTask, state: Literal["QUEUED", "RUNNING", "DONE", "EXHAUSTED"], attempts: int, error: str | None = None
    ) -> None:
        self._connector.set_recompute_task_state(task.task_id, state, attempts, error)


@dataclass
class LoopReport:
    recomputed: list[str] = field(default_factory=list)
    invalidated: list[str] = field(default_factory=list)
    exhausted: list[str] = field(default_factory=list)
    retried: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def _enum_value(raw: Any) -> str:
    return str(getattr(raw, "value", raw))


def _independent_support(node: Mapping[str, Any], reader: ConflictReader) -> int:
    """Distinct source roots among ACTIVE evidence in the node's own scope (C02)."""
    active = LifecycleStatus.ACTIVE.value
    roots = {
        str(e["canonical_hash"])
        for e in reader.supporting_evidence(str(node["id"]))
        if _enum_value(e.get("lifecycle_status")) == active and e.get("scope_key") == node.get("scope_key")
    }
    return len(roots)


def _recomputed_props(
    task: RecomputeTask,
    node: Mapping[str, Any],
    reader: RecomputeReader,
    recomputers: Mapping[str, Recomputer],
) -> tuple[dict[str, PropValue], list[str], str]:
    """Decide the new state of a PENDING_RECOMPUTE node. Returns ``(props, decisive, code)``."""
    cls = _enum_value(node.get("assurance_type"))
    supp = _independent_support(node, reader)
    bad_up = reader.invalidated_upstream_count(str(node["id"]))
    if isinstance(bad_up, bool) or not isinstance(bad_up, int):
        raise ConflictError("invalidated_upstream_count must return an integer")
    decisive = [f"supp={supp}", f"bad_upstream={bad_up}"]
    if bad_up > 0 or (cls in _CHECKED_CLASSES and supp == 0):
        return {"lifecycle_status": LifecycleStatus.INVALIDATED.value}, decisive, "DAG-PV-INVALIDATED"
    recomputer = recomputers.get(cls)
    if recomputer is None:
        raise ConflictError(f"no recomputer registered for class {cls!r}")
    extra = dict(recomputer.recompute(node, reader))
    clash = sorted(set(extra) & _RESERVED)
    if clash:
        raise ConflictError(f"recomputer set reserved properties {clash}")
    return {**extra, "lifecycle_status": LifecycleStatus.ACTIVE.value}, decisive, "DAG-PV-RECOMPUTED"


def _run_task(
    task: RecomputeTask,
    *,
    reader: RecomputeReader,
    recomputers: Mapping[str, Recomputer],
    persister: ConflictPersister,
    propagator: Propagator,
    conflict_cfg: ConflictConfig,
    now: str | None,
) -> bool:
    """Process one task; returns True when a status was written, False when it was skipped."""
    node = reader.load_node(task.node_id)
    if node is None:
        raise ConflictError(f"node {task.node_id!r} not found")
    pending = _enum_value(node.get("lifecycle_status")) == LifecycleStatus.PENDING_RECOMPUTE.value
    continues = task.reason == _DEPTH_CAP
    if not pending and not continues:
        return False
    props: dict[str, PropValue] = {}
    decisive: list[str] = []
    code = "DAG-PV-RECOMPUTED"
    if pending:
        props, decisive, code = _recomputed_props(task, node, reader, recomputers)
    if continues:
        decisive = [*decisive, "depth-cap continuation"]
    ev = system_event(
        "RECOMPUTATION",
        node,
        actor=RECOMPUTE_ACTOR,
        code=code,
        text="",
        decisive=decisive or ["no status change"],
        cfg=conflict_cfg,
        rule_id="CR017.recompute",
        extra={"task": task.task_id},
        now=now,
    )
    marks, frontier = propagator(task.node_id, ev, "HARD") if continues else ([], [])
    marks = [m for m in marks if m.node_id != task.node_id]
    frontier = [f for f in frontier if f != task.node_id]
    writes: list[NodeWrite] = []
    if pending:
        stamp = now or _now_iso()
        full: dict[str, PropValue] = {
            **props,
            "dirty": False,
            "dirty_since": None,
            "dirty_reason": None,
            "recomputed_at": stamp,
            "recompute_attempts": task.attempts + 1,
            "prov_event_id": ev.event_id,
        }
        writes.append(NodeWrite(node_id=task.node_id, expected_seq=int(node["assurance_seq"]), set_props=full))
    writes += [m.node_write() for m in marks]
    if not writes:
        return False
    mutation = AssuranceMutation(
        mutation_id=ev.event_id,
        event=ev,
        node_writes=writes,
        edge_writes=[],
        tasks=recompute_tasks(marks, frontier, ev),
        inputs_hash=ev.inputs_hash,
    )
    persister.persist_assurance_mutation(mutation)
    return True


def _fail(
    task: RecomputeTask,
    exc: Exception,
    *,
    queue: RecomputeQueue,
    reader: RecomputeReader,
    persister: ConflictPersister,
    propagator: Propagator,
    conflict_cfg: ConflictConfig,
    cfg: RecomputeConfig,
    report: LoopReport,
    now: str | None,
) -> None:
    attempts = task.attempts + 1
    message = str(exc)[:_ERROR_CHARS]
    logger.warning("recompute of %s failed (attempt %d of %d): %s", task.node_id, attempts, cfg.max_attempts, exc, exc_info=exc)
    report.errors[task.task_id] = message
    if attempts < cfg.max_attempts:
        queue.set_state(task, "QUEUED", attempts, message)
        report.retried.append(task.node_id)
        return
    try:
        invalidate(
            task.node_id,
            RECOMPUTE_ACTOR,
            "DAG-PV-RECOMPUTE-EXHAUSTED",
            message,
            reader=reader,
            propagator=propagator,
            persister=persister,
            cfg=conflict_cfg,
            now=now,
        )
    except Exception as inv_exc:  # noqa: BLE001 - the node stays PENDING_RECOMPUTE, never ACTIVE
        logger.error("could not invalidate %s after exhausted recompute: %s", task.node_id, inv_exc)
        report.errors[task.task_id] = f"{message}; invalidation failed: {str(inv_exc)[:_ERROR_CHARS]}"
        queue.set_state(task, "QUEUED", attempts, report.errors[task.task_id])
        report.retried.append(task.node_id)
        return
    report.invalidated.append(task.node_id)
    report.exhausted.append(task.node_id)
    queue.set_state(task, "EXHAUSTED", attempts, message)


def recompute_loop(
    queue: RecomputeQueue,
    recomputers: Mapping[str, Recomputer],
    *,
    reader: RecomputeReader,
    persister: ConflictPersister,
    propagator: Propagator,
    cfg: RecomputeConfig,
    conflict_cfg: ConflictConfig,
    now: str | None = None,
) -> LoopReport:
    """Process one claimed batch. Failures are counted per task; none is swallowed."""
    report = LoopReport()
    for task in queue.claim(cfg.batch_size):
        try:
            wrote = _run_task(
                task,
                reader=reader,
                recomputers=recomputers,
                persister=persister,
                propagator=propagator,
                conflict_cfg=conflict_cfg,
                now=now,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed: count the attempt, never leave ACTIVE
            _fail(
                task,
                exc,
                queue=queue,
                reader=reader,
                persister=persister,
                propagator=propagator,
                conflict_cfg=conflict_cfg,
                cfg=cfg,
                report=report,
                now=now,
            )
            continue
        queue.set_state(task, "DONE", task.attempts + 1)
        (report.recomputed if wrote else report.skipped).append(task.node_id)
    return report
