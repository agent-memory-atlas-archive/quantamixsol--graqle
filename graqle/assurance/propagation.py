"""Dependency propagation and explicit invalidation (CR-017 PR-017b).

Spec sections 2.2, 2.3 and 5.3. When a node is invalidated or corrected, every node that
depends on it is marked dirty, in one breadth-first pass over INCOMING ``DERIVED_FROM`` and
``SUPPORTED_BY`` edges (``(x)-[r]->(y {id})`` yields the dependents ``x`` of ``y``). Upstream
nodes are never reached, so the Evidence under an invalidated Claim stays clean.

Rules (CR-017 reviewer checklist, 017b):

* Traversal follows incoming dependency edges only.
* The planning pass is read-only. It returns marks and a frontier; the caller commits
  everything in ONE mutation (see ``Neo4jBatchPersister.persist_assurance_mutation``).
* A node at the depth cap is returned in the frontier and gets a ``DEPTH_CAP`` recompute
  task. It is never left clean, and its own dependents are explored when that task runs.
* ``Agent`` and ``ProvenanceEvent`` nodes are never marked.
* Any driver error becomes :class:`PropagationError`. No partial result is ever returned.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.propagation
# risk: LOW (new module, read-only planning; writes only through the persister)
# dependencies: collections, graqle.assurance.conflicts, graqle.core.exceptions,
#   graqle.ontology.assurance
# constraints: never imports graqle.governance.*; the depth cap is injected, never defaulted
# -- /graqle:intelligence --
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from graqle.assurance.conflicts import (
    AssuranceMutation,
    ConflictConfig,
    ConflictError,
    ConflictPersister,
    ConflictReader,
    EdgeWrite,
    Mark,
    MutationReceipt,
    NodeWrite,
    Propagator,
    PropValue,
    ResolutionEvent,
    recompute_tasks,
    system_event,
)
from graqle.core.exceptions import GraqleError
from graqle.ontology.assurance import EdgeKind, LifecycleStatus, edge_id

__all__ = [
    "PropagationError",
    "PropagationConfig",
    "ReadSessionSource",
    "ReceiptingPersister",
    "propagate_dirty",
    "make_propagator",
    "mark_hard",
    "mark_soft",
    "invalidate",
]

DEPENDENCY_KINDS = ("DERIVED_FROM", "SUPPORTED_BY")
#: Classes that are actors or records, never dependents (kind-shape table of the ontology).
_NEVER_DIRTY = frozenset({"Agent", "ProvenanceEvent"})
_MODES = ("HARD", "SOFT")
#: Incoming edges to ``$id``: the dependents of ``$id``.
_DEP_QUERY = (
    "MATCH (x:CogniNode)-[r:RELATES_TO]->(y:CogniNode {id: $id}) "
    "WHERE r.kind IN ['DERIVED_FROM','SUPPORTED_BY'] AND r.retracted_at IS NULL "
    "RETURN x.id AS xid, r.kind AS via, coalesce(x.assurance_seq,0) AS seq, "
    "x.lifecycle_status AS st, x.assurance_type AS cls"
)


class PropagationError(GraqleError):
    """Planning failed; nothing may be committed for this seed."""

    def __init__(self, seed_id: str, message: str) -> None:
        super().__init__(f"propagation from {seed_id!r} failed: {message}")
        self.seed_id = seed_id


@dataclass(frozen=True)
class PropagationConfig:
    """``max_depth`` has no default: it is a protected value injected from private configuration."""

    max_depth: int

    def __post_init__(self) -> None:
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int) or self.max_depth < 1:
            raise PropagationError("<config>", "max_depth must be an integer of at least 1")


class _Session(Protocol):
    def run(self, query: str, **params: Any) -> Any: ...


class ReadSessionSource(Protocol):
    """A connector exposing ``read_session()`` as a context manager (``Neo4jConnector``)."""

    def read_session(self) -> AbstractContextManager[_Session]: ...


def _status_value(raw: Any) -> str | None:
    if raw is None:
        return None
    return str(getattr(raw, "value", raw))


def _mark(ev: ResolutionEvent, *, node_id: str, via: str, seq: int, prior: str | None, mode: str) -> Mark:
    props: dict[str, PropValue] = {
        "dirty": True,
        "dirty_since": ev.timestamp,
        # A correction reaches its dependents as CORRECTS; an invalidation names the edge kind.
        "dirty_reason": "CORRECTS" if mode == "SOFT" else via,
        "prov_event_id": ev.event_id,
    }
    # Only an ACTIVE node becomes PENDING_RECOMPUTE; any other state is left as it is.
    if prior == LifecycleStatus.ACTIVE.value:
        props["lifecycle_status"] = LifecycleStatus.PENDING_RECOMPUTE.value
    return Mark(node_id=node_id, via=str(props["dirty_reason"]), expected_seq=seq, set_props=props)


def propagate_dirty(
    seed_id: str,
    ev: ResolutionEvent,
    mode: Literal["HARD", "SOFT"] | str,
    session: _Session,
    cfg: PropagationConfig,
) -> tuple[list[Mark], list[str]]:
    """Read-only planning pass. Returns ``(marks, frontier)``; O(V + E_D) with a visited set.

    The seed itself is not marked here (the caller writes it with :func:`mark_hard` or
    :func:`mark_soft`). ``frontier`` lists marked nodes at the depth cap whose dependents
    were not explored.
    """
    if mode not in _MODES:
        raise PropagationError(seed_id, f"unknown mode {mode!r}")
    queue: deque[tuple[str, int]] = deque([(seed_id, 0)])
    visited = {seed_id}
    marks: list[Mark] = []
    frontier: list[str] = []
    try:
        while queue:
            y, depth = queue.popleft()
            if depth >= cfg.max_depth:
                frontier.append(y)  # fail-closed: queued as DEPTH_CAP, never silently clean
                continue
            for row in session.run(_DEP_QUERY, id=y):
                x = row["xid"]
                if x in visited:
                    continue
                visited.add(x)
                if row["cls"] in _NEVER_DIRTY:
                    continue
                seq = row["seq"]
                if isinstance(seq, bool) or not isinstance(seq, int):
                    raise PropagationError(seed_id, f"node {x!r} has a non-integer assurance_seq")
                marks.append(
                    _mark(ev, node_id=x, via=str(row["via"]), seq=seq, prior=_status_value(row["st"]), mode=mode)
                )
                queue.append((x, depth + 1))
    except PropagationError:
        raise
    except Exception as exc:  # noqa: BLE001 - an exception is a failure, never a partial success
        raise PropagationError(seed_id, str(exc)) from exc
    return marks, frontier


class _RawPersister(Protocol):
    def persist_assurance_mutation(self, m: Any, replanner: Any = ...) -> Any: ...


class ReceiptingPersister:
    """Adapts ``Neo4jBatchPersister`` (governance, receipt-agnostic) to :class:`ConflictPersister`.

    Governance never imports this layer, so the persister hands back the connector's plain
    receipt mapping. This adapter turns it into a :class:`MutationReceipt` and refuses any
    other shape, so a malformed result can never read as success.
    """

    def __init__(self, inner: _RawPersister, replanner: Callable[[AssuranceMutation], AssuranceMutation | None] | None = None) -> None:
        self._inner = inner
        self._replanner = replanner

    def persist_assurance_mutation(self, m: AssuranceMutation) -> MutationReceipt:
        raw = (
            self._inner.persist_assurance_mutation(m, self._replanner)
            if self._replanner is not None
            else self._inner.persist_assurance_mutation(m)
        )
        if isinstance(raw, MutationReceipt):
            return raw
        if isinstance(raw, Mapping):
            return MutationReceipt(**dict(raw))
        raise ConflictError(f"persister returned an unusable receipt of type {type(raw).__name__}")


def make_propagator(source: ReadSessionSource, cfg: PropagationConfig) -> Propagator:
    """Bind :func:`propagate_dirty` to a read session, in the shape the resolution handlers take."""

    def plan(seed: str, ev: ResolutionEvent, mode: str) -> tuple[list[Mark], list[str]]:
        try:
            with source.read_session() as session:
                return propagate_dirty(seed, ev, mode, session, cfg)
        except PropagationError:
            raise
        except Exception as exc:  # noqa: BLE001 - opening or closing the session failed
            raise PropagationError(seed, str(exc)) from exc

    return plan


def mark_hard(seed: Mapping[str, Any], ev: ResolutionEvent) -> NodeWrite:
    """INVALIDATES target: the seed becomes INVALIDATED and dirty."""
    return NodeWrite(
        node_id=str(seed["id"]),
        expected_seq=int(seed["assurance_seq"]),
        set_props={
            "lifecycle_status": LifecycleStatus.INVALIDATED.value,
            "dirty": True,
            "dirty_since": ev.timestamp,
            "dirty_reason": "INVALIDATES",
            "prov_event_id": ev.event_id,
        },
    )


def mark_soft(old: Mapping[str, Any], new_id: str, ev: ResolutionEvent) -> NodeWrite:
    """CORRECTS target: the old state becomes SUPERSEDED."""
    return NodeWrite(
        node_id=str(old["id"]),
        expected_seq=int(old["assurance_seq"]),
        set_props={
            "lifecycle_status": LifecycleStatus.SUPERSEDED.value,
            "superseded_by": new_id,
            "correction_kind": "CORRECTS",
            "prov_event_id": ev.event_id,
        },
    )


def invalidate(
    target_id: str,
    actor: str,
    reason_code: str,
    text: str,
    *,
    reader: ConflictReader,
    propagator: Propagator,
    persister: ConflictPersister,
    cfg: ConflictConfig,
    deletion: bool = False,
    now: str | None = None,
) -> MutationReceipt:
    """Explicitly invalidate a node and mark every dependent, in one mutation.

    Also the entry point for evidence deletion: deletion is an invalidation plus a
    ``tombstone`` flag. Bytes are never removed here; payload erasure is a separate job.
    """
    target = reader.load_node(target_id)
    if target is None:
        raise ConflictError(f"node {target_id!r} not found")
    ev = system_event(
        "INVALIDATION",
        target,
        actor=actor,
        code=reason_code,
        text=text,
        decisive=["explicit invalidation"],
        cfg=cfg,
        rule_id="CR017.invalidate",
        extra={"deletion_requested": deletion},
        now=now,
    )
    marks, frontier = propagator(target_id, ev, "HARD")
    seed_write = mark_hard(target, ev)
    if deletion:
        seed_write.set_props["tombstone"] = True
    marks = [m for m in marks if m.node_id != target_id]
    frontier = [f for f in frontier if f != target_id]
    scope = ev.scope_key
    edge = EdgeWrite(
        edge_id=edge_id(ev.event_id, target_id, EdgeKind.INVALIDATES, scope),
        source_id=ev.event_id,
        target_id=target_id,
        kind=EdgeKind.INVALIDATES.value,
        props={"scope_key": scope, "asserted_at": ev.asserted_at, "prov_event_id": ev.event_id, "strength": 1.0},
    )
    mutation = AssuranceMutation(
        mutation_id=ev.event_id,
        event=ev,
        node_writes=[seed_write, *[m.node_write() for m in marks]],
        edge_writes=[edge],
        tasks=recompute_tasks(marks, frontier, ev),
        inputs_hash=ev.inputs_hash,
    )
    return persister.persist_assurance_mutation(mutation)
