"""Persisted CONTRADICTS and append-only resolution events (CR-017 PR-017a).

Spec sections 4.1, 4.2, 4.5, 5.1, 5.2 and 5.4. This module turns detector
output into :class:`ContradictionRecord` values, persists each as exactly one
CONTRADICTS edge, and resolves a contradiction with one of three explicit
handlers (SUPERSEDES, CORRECTS, COEXISTS_WITH). Every resolution is a new
:class:`ResolutionEvent`; nothing is edited in place (spec section 2.7).

Rules (CR-017 reviewer checklist, 017a):

* ``detect_contradictions`` is untouched; ``to_records`` lives beside it.
* ``asserted_at`` never enters :func:`accept_correction`. A correction is
  accepted on authority or independent corroboration only (C06).
* A rejected correction leaves the newcomer PROPOSED and the CONTRADICTS edge
  PENDING.
* COEXISTS_WITH is refused for a same-scope pair.
* ``event_id`` derives from the idempotency key, so an unchanged resolution
  MERGEs onto the same event.
* Raw contradiction values are hashed, never persisted. Persisted records name
  thresholds symbolically (``K_CORROB_MIN``) and never carry their value or a
  merge-priority rank.
* Every failure raises a typed error; no path returns a silent success.

Reads go through :class:`ConflictReader` and writes through
:class:`ConflictPersister`. The sequence-checked Neo4j implementation of the
persister and the propagation planner are PR-017b; ``handle_corrects`` takes
the planner as a required argument so it can never run without one.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.conflicts
# risk: LOW (new module, no runtime consumers in PR-017a)
# dependencies: pydantic, hashlib, graqle.core.exceptions,
#   graqle.ontology.assurance, graqle.ontology.assurance_migration,
#   graqle.scanner.dedup.contradictions, graqle.scanner.dedup.merge,
#   graqle.assurance.reason_codes,
#   graqle.governance.tamper_evidence.canonicalize (lazy)
# constraints: never imported by graqle.governance.*; canonicaliser loaded lazily
# -- /graqle:intelligence --
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from graqle.assurance import reason_codes
from graqle.core.exceptions import GraqleError
from graqle.ontology.assurance import (
    AssuranceClass,
    EdgeKind,
    LifecycleStatus,
    ProvenanceEvent,
    edge_id,
    to_iso_utc,
)
from graqle.ontology.assurance_migration import GLOBAL_SCOPE_KEY
from graqle.scanner.dedup.contradictions import _source_type
from graqle.scanner.dedup.merge import _DEFAULT_PRIORITY

__all__ = [
    "DETECTOR_VERSION",
    "RULE_VERSION",
    "CORROB_SYMBOL",
    "GLOBAL_SCOPE_KEY",
    "ConflictError",
    "ContradictionNotFound",
    "AlreadyResolved",
    "ResolutionRejected",
    "ConflictConfig",
    "ContradictionRecord",
    "NodeWrite",
    "EdgeWrite",
    "RecomputeTask",
    "AssuranceMutation",
    "MutationReceipt",
    "Mark",
    "ResolutionEvent",
    "ConflictReader",
    "ConflictPersister",
    "Propagator",
    "to_records",
    "persist_contradictions",
    "authority",
    "independent_support_count",
    "accept_correction",
    "resolve",
    "handle_supersedes",
    "handle_corrects",
    "handle_coexists",
]

DETECTOR_VERSION = "1"
RULE_VERSION = "1"
#: Symbolic name recorded in place of the corroboration minimum.
CORROB_SYMBOL = "K_CORROB_MIN"

_DETECTED = "DETECTED"
_REJECTED = "CORRECTION_REJECTED"
_IAL_ORDER = {"IAL1": 1, "IAL2": 2, "IAL3": 3}
_SIGNED = frozenset({"SIGNED", "ATTESTED"})
#: Statuses a resolution may activate. Anything else is a terminal or pending
#: state that only recomputation (INV-R2) may leave.
_ACTIVATABLE = frozenset({LifecycleStatus.PROPOSED.value, LifecycleStatus.ACTIVE.value})
_TERMINAL = frozenset({LifecycleStatus.INVALIDATED.value, LifecycleStatus.RETRACTED.value})
# Truncated-digest widths fixed by CR-017 sections 4.1, 4.2 and 4.4. They are MERGE keys,
# not integrity commitments; integrity comes from the tamper-evidence chain.
_ID_HEX = 32
_EVENT_HEX = 26
_TASK_HEX = 24


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class ConflictError(GraqleError):
    """Base of every typed conflict-resolution failure."""


class ContradictionNotFound(ConflictError):
    """No persisted contradiction has this id (never a silent no-op)."""


class AlreadyResolved(ConflictError):
    """The contradiction is RESOLVED; re-resolution is a separate, explicit act."""

    def __init__(self, contradiction_id: str, resolution_event_id: str | None) -> None:
        super().__init__(f"contradiction {contradiction_id} already resolved by {resolution_event_id}")
        self.contradiction_id = contradiction_id
        self.resolution_event_id = resolution_event_id


class ResolutionRejected(ConflictError):
    """A resolution request violates a rule; carries a registered reason code."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------
# Config, canonical helpers
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ConflictConfig:
    """Private tuning surface, injected by the caller.

    ``corrob_min`` has no default: it is a protected value and must come from the
    private configuration. ``merge_priority`` defaults to the public base order
    (lower = higher authority); a source type missing from it ranks weakest.
    """

    corrob_min: int
    config_version: str
    merge_priority: Mapping[str, int] = field(default_factory=lambda: dict(_DEFAULT_PRIORITY))

    def __post_init__(self) -> None:
        if isinstance(self.corrob_min, bool) or not isinstance(self.corrob_min, int):
            raise ConflictError("corrob_min must be an integer")
        if self.corrob_min < 1:
            raise ConflictError("corrob_min must be at least 1")
        if not self.config_version:
            raise ConflictError("config_version is required")
        if not self.merge_priority:
            raise ConflictError("merge_priority must not be empty")

    def rank(self, source_type: str) -> int:
        """Rank of a source type; unknown types rank weakest (fail-closed)."""
        if source_type in self.merge_priority:
            return self.merge_priority[source_type]
        return max(self.merge_priority.values()) + 1


def _canon(obj: dict[str, Any]) -> bytes:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return canon(obj)


def _sha(obj: dict[str, Any]) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


def _value_hash(value: Any) -> str:
    return _sha({"v": value})


def _canon_json(obj: dict[str, Any]) -> str:
    return _canon(obj).decode("utf-8")


def _now_iso() -> str:
    return to_iso_utc(datetime.now(timezone.utc))


def _parse_source_id(source: str) -> str:
    """``"<id> (<type>)"`` -> ``"<id>"`` (contradictions.py source format)."""
    head, sep, tail = source.rpartition(" (")
    if not sep or not tail.endswith(")") or not head:
        raise ConflictError(f"unparseable contradiction source {source!r}")
    return head


def contradiction_edge_id(contradiction_id: str) -> str:
    return "e_" + contradiction_id


# --------------------------------------------------------------------------
# Models (spec 4.1, 4.5)
# --------------------------------------------------------------------------


class ContradictionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contradiction_id: str
    node_a: str
    node_b: str
    kind: str
    key: str
    value_a_hash: str
    value_b_hash: str
    scope_key: str
    detected_at: str
    resolution_status: Literal["PENDING", "RESOLVED"] = "PENDING"
    resolution_event_id: str | None = None
    resolution_kind: Literal["SUPERSEDES", "CORRECTS", "COEXISTS_WITH"] | None = None
    probabilistic: bool = False
    detector_version: str


PropValue = str | int | float | bool | None


class NodeWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str
    expected_seq: int
    set_props: dict[str, PropValue]


class EdgeWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: str
    source_id: str
    target_id: str
    kind: str
    props: dict[str, PropValue]


class RecomputeTask(BaseModel):
    """Queue entry for a dirty node (spec 4.4). The queue itself is PR-017b."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    node_id: str
    reason: str
    prov_event_id: str
    enqueued_at: str
    attempts: int = 0
    state: Literal["QUEUED", "RUNNING", "DONE", "EXHAUSTED"] = "QUEUED"

    @classmethod
    def for_node(cls, node_id: str, *, reason: str, ev: ResolutionEvent) -> RecomputeTask:
        digest = hashlib.sha256((node_id + ev.event_id).encode("utf-8")).hexdigest()
        return cls(
            task_id="rt_" + digest[:_TASK_HEX],
            node_id=node_id,
            reason=reason,
            prov_event_id=ev.event_id,
            enqueued_at=ev.timestamp,
        )


class MutationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mutation_id: str
    replayed: bool = False


@dataclass(frozen=True)
class Mark:
    """One dependent the propagation planner chose to mark."""

    node_id: str
    via: str
    expected_seq: int
    set_props: Mapping[str, PropValue]

    def node_write(self) -> NodeWrite:
        return NodeWrite(node_id=self.node_id, expected_seq=self.expected_seq, set_props=dict(self.set_props))


# --------------------------------------------------------------------------
# Resolution event (spec 4.2)
# --------------------------------------------------------------------------


class ResolutionEvent(ProvenanceEvent):
    """A CR-016 ``ProvenanceEvent`` carrying a resolution and its determinism record."""

    event_type: Literal["RESOLUTION", "INVALIDATION", "RECOMPUTATION"]  # type: ignore[assignment]
    contradiction_id: str | None = None
    resolution_kind: Literal["SUPERSEDES", "CORRECTS", "COEXISTS_WITH"] | None = None
    winner: str | None = None
    loser: str | None = None
    rationale_code: str
    rationale_text: str = Field(max_length=200)
    authority_record: str
    inputs_hash: str
    rule_id: str
    rule_version: str
    config_version: str
    decisive_conditions: list[str]
    idempotency_key: str

    @classmethod
    def build(
        cls,
        *,
        kind: Literal["SUPERSEDES", "CORRECTS", "COEXISTS_WITH"] | None,
        rec: ContradictionRecord,
        actor: str,
        code: str,
        text: str,
        authority_record: str,
        decisive: Sequence[str],
        cfg: ConflictConfig,
        rule_id: str,
        winner: str | None = None,
        loser: str | None = None,
        outcome: str | None = None,
        now: str | None = None,
    ) -> ResolutionEvent:
        """Build an event. ``outcome`` names the unresolved result of a rejection."""
        if not reason_codes.REGISTRY.get(code):
            raise ConflictError(f"unregistered rationale code {code!r}")
        stamp = now or _now_iso()
        inputs = sorted({rec.node_a, rec.node_b})
        label = kind or outcome or _DETECTED
        idem = _sha({"cid": rec.contradiction_id, "kind": label, "inputs": inputs})
        event_id = "pev_" + idem[:_EVENT_HEX]
        inputs_hash = _sha(
            {
                "cid": rec.contradiction_id,
                "kind": label,
                "inputs": inputs,
                "winner": winner,
                "loser": loser,
                "authority_record": authority_record,
                "rule_id": rule_id,
                "rule_version": RULE_VERSION,
                "config_version": cfg.config_version,
            }
        )
        body: dict[str, Any] = {
            "id": event_id,
            "assurance_type": AssuranceClass.PROVENANCE_EVENT.value,
            "event_id": event_id,
            "event_type": "RESOLUTION",
            "actor": actor,
            "inputs": inputs,
            "outputs": [contradiction_edge_id(rec.contradiction_id)],
            "contradiction_id": rec.contradiction_id,
            "resolution_kind": kind,
            "winner": winner,
            "loser": loser,
            "rationale_code": code,
            "rationale_text": text,
            "authority_record": authority_record,
            "inputs_hash": inputs_hash,
            "rule_id": rule_id,
            "rule_version": RULE_VERSION,
            "config_version": cfg.config_version,
            "decisive_conditions": list(decisive),
            "idempotency_key": idem,
            "valid_from": stamp,
            "asserted_at": stamp,
            "timestamp": stamp,
            "scope_key": rec.scope_key,
            "lifecycle_status": LifecycleStatus.ACTIVE.value,
            "schema_version": "1",
        }
        body["canonical_hash"] = _sha(body)
        return cls(**body)

    @classmethod
    def detection(cls, rec: ContradictionRecord, cfg: ConflictConfig, *, now: str | None = None) -> ResolutionEvent:
        """The event that records a detection; ``kind`` stays ``None`` (still PENDING)."""
        return cls.build(
            kind=None,
            rec=rec,
            actor="detector",
            code="DAG-PV-CONTRADICTION-PENDING",
            text="contradiction detected",
            authority_record=_canon_json({"detector_version": rec.detector_version}),
            decisive=["detector reported differing values"],
            cfg=cfg,
            rule_id="CR017.detect",
            now=now or rec.detected_at,
        )


class AssuranceMutation(BaseModel):
    """One transaction unit (spec 4.5)."""

    model_config = ConfigDict(extra="forbid")

    mutation_id: str
    event: ResolutionEvent
    node_writes: list[NodeWrite]
    edge_writes: list[EdgeWrite]
    tasks: list[RecomputeTask]
    inputs_hash: str


# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------


class ConflictReader(Protocol):
    """Read side. Every method returns plain dicts; ``None`` means absent."""

    def load_contradiction(self, contradiction_id: str) -> Mapping[str, Any] | None: ...

    def load_node(self, node_id: str) -> Mapping[str, Any] | None:
        """Node properties including ``assurance_seq``, ``scope_key``, ``valid_from``."""

    def load_agent(self, agent_id: str) -> Mapping[str, Any] | None: ...

    def supporting_evidence(self, node_id: str) -> Sequence[Mapping[str, Any]]:
        """Evidence reachable from ``node_id`` via SUPPORTED_BY, in the current state."""


class ConflictPersister(Protocol):
    def persist_assurance_mutation(self, m: AssuranceMutation) -> MutationReceipt: ...


#: Planning pass: ``(seed_id, event, mode) -> (marks, frontier_ids)``. Read-only.
Propagator = Callable[[str, ResolutionEvent, str], tuple[Sequence[Mark], Sequence[str]]]


# --------------------------------------------------------------------------
# Detection -> records -> persistence (spec 5.1)
# --------------------------------------------------------------------------


def to_records(
    detections: Sequence[Mapping[str, Any]],
    nodes: Mapping[str, Mapping[str, Any]],
    scope_fn: Callable[[Mapping[str, Any]], str],
    *,
    detected_at: str | None = None,
) -> list[ContradictionRecord]:
    """Convert ``detect_contradictions`` output into records. Pure; never mutates input."""
    stamp = detected_at or _now_iso()
    out: list[ContradictionRecord] = []
    for d in detections:
        id_a, id_b = _parse_source_id(d["source_a"]), _parse_source_id(d["source_b"])
        a, b = sorted([id_a, id_b])
        if a not in nodes or b not in nodes:
            raise ConflictError(f"detection references unknown node {a!r} or {b!r}")
        scope_a, scope_b = scope_fn(nodes[a]), scope_fn(nodes[b])
        if not isinstance(scope_a, str) or not isinstance(scope_b, str) or not scope_a or not scope_b:
            raise ConflictError("scope_fn must return a non-empty string for every node")
        scope = scope_a if scope_a == scope_b else GLOBAL_SCOPE_KEY
        cid = _sha({"a": a, "b": b, "key": d["key"], "scope_key": scope})[:_ID_HEX]
        # The detector orders the pair by its own iteration; align hashes to the sorted ids.
        first_is_a = id_a == a
        va, vb = (d["value_a"], d["value_b"]) if first_is_a else (d["value_b"], d["value_a"])
        out.append(
            ContradictionRecord(
                contradiction_id=cid,
                node_a=a,
                node_b=b,
                kind=d["type"],
                key=d["key"],
                value_a_hash=_value_hash(va),
                value_b_hash=_value_hash(vb),
                scope_key=scope,
                detected_at=stamp,
                detector_version=DETECTOR_VERSION,
            )
        )
    return out


def persist_contradictions(
    records: Sequence[ContradictionRecord],
    persister: ConflictPersister,
    cfg: ConflictConfig,
) -> list[MutationReceipt]:
    """Persist each record as exactly one CONTRADICTS edge. No node marks, no propagation (R-CON)."""
    receipts: list[MutationReceipt] = []
    for r in records:
        ev = ResolutionEvent.detection(r, cfg)
        # The detector's `kind` is renamed: on the edge, `kind` is RELATES_TO.kind
        # (CONTRADICTS) and a property of the same name would overwrite it.
        props = r.model_dump(exclude={"node_a", "node_b", "kind"})
        props["detection_kind"] = r.kind
        edge = EdgeWrite(
            edge_id=contradiction_edge_id(r.contradiction_id),
            source_id=r.node_a,
            target_id=r.node_b,
            kind=EdgeKind.CONTRADICTS.value,
            props={
                **props,
                "contradiction_id": r.contradiction_id,
                "asserted_at": r.detected_at,
                "prov_event_id": ev.event_id,
            },
        )
        receipts.append(
            persister.persist_assurance_mutation(
                AssuranceMutation(
                    mutation_id=ev.event_id,
                    event=ev,
                    node_writes=[],
                    edge_writes=[edge],
                    tasks=[],
                    inputs_hash=ev.inputs_hash,
                )
            )
        )
    return receipts


# --------------------------------------------------------------------------
# Authority and the C06 guard (spec 2.4, 5.4)
# --------------------------------------------------------------------------


def _agent_ial(node: Mapping[str, Any], reader: ConflictReader) -> str:
    agent_id = node.get("asserted_by_agent_id")
    agent = reader.load_agent(agent_id) if agent_id else None
    ial = (agent or {}).get("identity_assurance", "IAL1")
    ial = getattr(ial, "value", ial)
    return ial if ial in _IAL_ORDER else "IAL1"  # unknown or missing -> weakest


def _describe(node: Mapping[str, Any], reader: ConflictReader) -> dict[str, Any]:
    return {
        "source_type": _source_type(dict(node)),
        "ial": _agent_ial(node, reader),
        "signed": node.get("authenticity_status") in _SIGNED,
    }


def authority(node: Mapping[str, Any], reader: ConflictReader, cfg: ConflictConfig) -> tuple[int, int, bool]:
    """Lexicographic authority tuple; higher is more authoritative."""
    d = _describe(node, reader)
    return (-cfg.rank(d["source_type"]), _IAL_ORDER[d["ial"]], d["signed"])


def independent_support_count(node_id: str, reader: ConflictReader) -> int:
    """Distinct source roots among ACTIVE Evidence; copies of one source count once (C02)."""
    roots: set[str] = set()
    for ev in reader.supporting_evidence(node_id):
        status = getattr(ev.get("lifecycle_status"), "value", ev.get("lifecycle_status"))
        root = ev.get("canonical_hash")
        if status == LifecycleStatus.ACTIVE.value and isinstance(root, str) and root:
            roots.add(root)
    return len(roots)


def accept_correction(
    new: Mapping[str, Any],
    old: Mapping[str, Any],
    reader: ConflictReader,
    cfg: ConflictConfig,
) -> tuple[bool, str, list[str]]:
    """C06: newness alone never wins. No timestamp of either node is read here."""
    a_new, a_old = authority(new, reader, cfg), authority(old, reader, cfg)
    indep = independent_support_count(str(new["id"]), reader)
    record = _canon_json(
        {
            "new": _describe(new, reader),
            "old": _describe(old, reader),
            "indep_new": indep,
            "k": CORROB_SYMBOL,
        }
    )
    if a_new >= a_old:
        return True, record, ["authority(new) >= authority(old)"]
    if indep >= cfg.corrob_min:
        return True, record, [f"indep(new) >= {CORROB_SYMBOL}"]
    return False, record, ["authority(new) < authority(old)", f"indep(new) < {CORROB_SYMBOL}"]


# --------------------------------------------------------------------------
# Resolution handlers (spec 5.2)
# --------------------------------------------------------------------------


def _seq(node: Mapping[str, Any]) -> int:
    seq = node.get("assurance_seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ConflictError(f"node {node.get('id')!r} has no integer assurance_seq")
    return seq


def _status(node: Mapping[str, Any]) -> str:
    return str(getattr(node.get("lifecycle_status"), "value", node.get("lifecycle_status")))


def _require_activatable(node: Mapping[str, Any]) -> None:
    if _status(node) not in _ACTIVATABLE:
        raise ResolutionRejected(
            f"node {node.get('id')!r} is {_status(node)} and cannot be activated by a resolution",
            code="DAG-PV-CONTRADICTION-PENDING",
        )


def _loser_props(old: Mapping[str, Any], ev: ResolutionEvent, extra: Mapping[str, PropValue]) -> dict[str, PropValue]:
    props: dict[str, PropValue] = {**extra, "prov_event_id": ev.event_id}
    if _status(old) not in _TERMINAL:  # a terminal state is never softened to SUPERSEDED
        props["lifecycle_status"] = LifecycleStatus.SUPERSEDED.value
    return props


def _edge_props(ev: ResolutionEvent, rec: ContradictionRecord) -> dict[str, PropValue]:
    return {
        "scope_key": rec.scope_key,
        "asserted_at": ev.asserted_at,
        "prov_event_id": ev.event_id,
        "strength": 1.0,
        "contradiction_id": rec.contradiction_id,
    }


def _resolved_edge(rec: ContradictionRecord, ev: ResolutionEvent, kind: str) -> EdgeWrite:
    return EdgeWrite(
        edge_id=contradiction_edge_id(rec.contradiction_id),
        source_id=rec.node_a,
        target_id=rec.node_b,
        kind=EdgeKind.CONTRADICTS.value,
        props={"resolution_status": "RESOLVED", "resolution_event_id": ev.event_id, "resolution_kind": kind},
    )


def _mutation(ev: ResolutionEvent, nodes: list[NodeWrite], edges: list[EdgeWrite], tasks: list[RecomputeTask]) -> AssuranceMutation:
    return AssuranceMutation(
        mutation_id=ev.event_id,
        event=ev,
        node_writes=nodes,
        edge_writes=edges,
        tasks=tasks,
        inputs_hash=ev.inputs_hash,
    )


def _load_contradiction(reader: ConflictReader, cid: str) -> ContradictionRecord:
    raw = reader.load_contradiction(cid)
    if raw is None:
        raise ContradictionNotFound(cid)
    return ContradictionRecord(**dict(raw))


def _load_node(reader: ConflictReader, node_id: str) -> Mapping[str, Any]:
    node = reader.load_node(node_id)
    if node is None:
        raise ConflictError(f"node {node_id!r} not found")
    return node


def resolve(
    cid: str,
    kind: Literal["SUPERSEDES", "CORRECTS", "COEXISTS_WITH"],
    *,
    actor: str,
    rationale_code: str,
    rationale_text: str,
    reader: ConflictReader,
    persister: ConflictPersister,
    cfg: ConflictConfig,
    winner_id: str | None = None,
    propagator: Propagator | None = None,
    now: str | None = None,
) -> MutationReceipt:
    """Resolve a PENDING contradiction. ``winner_id`` names the new state for SUPERSEDES/CORRECTS;
    orientation is explicit and never inferred from timestamps."""
    rec = _load_contradiction(reader, cid)
    if rec.resolution_status == "RESOLVED":
        raise AlreadyResolved(cid, rec.resolution_event_id)
    a, b = _load_node(reader, rec.node_a), _load_node(reader, rec.node_b)
    if kind == "COEXISTS_WITH":
        return handle_coexists(rec, a, b, actor, rationale_code, rationale_text, reader, persister, cfg, now=now)
    if kind not in ("SUPERSEDES", "CORRECTS"):
        raise ConflictError(f"unknown resolution kind {kind!r}")
    if winner_id not in (rec.node_a, rec.node_b):
        raise ResolutionRejected(
            "winner_id must be one of the contradicting nodes", code="DAG-PV-CONTRADICTION-PENDING"
        )
    new, old = (a, b) if winner_id == rec.node_a else (b, a)
    if kind == "SUPERSEDES":
        return handle_supersedes(rec, new, old, actor, rationale_code, rationale_text, reader, persister, cfg, now=now)
    if propagator is None:
        raise ConflictError("CORRECTS requires a propagation planner; refusing to leave dependents unmarked")
    return handle_corrects(
        rec, new, old, actor, rationale_code, rationale_text, reader, persister, cfg, propagator=propagator, now=now
    )


def handle_supersedes(
    rec: ContradictionRecord,
    new: Mapping[str, Any],
    old: Mapping[str, Any],
    actor: str,
    code: str,
    text: str,
    reader: ConflictReader,
    persister: ConflictPersister,
    cfg: ConflictConfig,
    *,
    now: str | None = None,
) -> MutationReceipt:
    """Prospective replacement (R-SUP): ``old.valid_until = new.valid_from``; no propagation."""
    _require_activatable(new)
    new_from, old_from = str(new["valid_from"]), str(old["valid_from"])
    if new_from < old_from:  # canonical width: string order is time order
        raise ResolutionRejected(
            "superseding state starts before the superseded state", code="DAG-PV-CONTRADICTION-PENDING"
        )
    ev = ResolutionEvent.build(
        kind="SUPERSEDES",
        rec=rec,
        actor=actor,
        code=code,
        text=text,
        authority_record=_canon_json({"new": _describe(new, reader), "old": _describe(old, reader)}),
        decisive=["explicit supersession"],
        cfg=cfg,
        rule_id="CR017.supersedes",
        winner=str(new["id"]),
        loser=str(old["id"]),
        now=now,
    )
    nodes = [
        NodeWrite(
            node_id=str(old["id"]),
            expected_seq=_seq(old),
            set_props=_loser_props(old, ev, {"superseded_by": str(new["id"]), "valid_until": new_from}),
        ),
        NodeWrite(
            node_id=str(new["id"]),
            expected_seq=_seq(new),
            set_props={"lifecycle_status": LifecycleStatus.ACTIVE.value, "prov_event_id": ev.event_id},
        ),
    ]
    edges = [
        EdgeWrite(
            edge_id=edge_id(str(new["id"]), str(old["id"]), EdgeKind.SUPERSEDES, rec.scope_key),
            source_id=str(new["id"]),
            target_id=str(old["id"]),
            kind=EdgeKind.SUPERSEDES.value,
            props=_edge_props(ev, rec),
        ),
        _resolved_edge(rec, ev, "SUPERSEDES"),
    ]
    return persister.persist_assurance_mutation(_mutation(ev, nodes, edges, []))


def handle_corrects(
    rec: ContradictionRecord,
    new: Mapping[str, Any],
    old: Mapping[str, Any],
    actor: str,
    code: str,
    text: str,
    reader: ConflictReader,
    persister: ConflictPersister,
    cfg: ConflictConfig,
    *,
    propagator: Propagator,
    now: str | None = None,
) -> MutationReceipt:
    """Correction gated by C06; accepted corrections soft-mark ``old`` and its dependents."""
    ok, record, decisive = accept_correction(new, old, reader, cfg)
    if not ok:
        ev = ResolutionEvent.build(
            kind=None,
            rec=rec,
            actor=actor,
            code="DAG-PV-CORRECTION-REJECTED",
            text=text,
            authority_record=record,
            decisive=decisive,
            cfg=cfg,
            rule_id="CR017.accept_correction",
            outcome=_REJECTED,
            now=now,
        )
        writes = [
            NodeWrite(
                node_id=str(new["id"]),
                expected_seq=_seq(new),
                set_props={"lifecycle_status": LifecycleStatus.PROPOSED.value, "prov_event_id": ev.event_id},
            )
        ]
        edges = [
            EdgeWrite(
                edge_id=contradiction_edge_id(rec.contradiction_id),
                source_id=rec.node_a,
                target_id=rec.node_b,
                kind=EdgeKind.CONTRADICTS.value,
                props={"resolution_status": "PENDING", "last_rejected_event_id": ev.event_id},
            )
        ]
        return persister.persist_assurance_mutation(_mutation(ev, writes, edges, []))
    _require_activatable(new)
    ev = ResolutionEvent.build(
        kind="CORRECTS",
        rec=rec,
        actor=actor,
        code=code,
        text=text,
        authority_record=record,
        decisive=decisive,
        cfg=cfg,
        rule_id="CR017.accept_correction",
        winner=str(new["id"]),
        loser=str(old["id"]),
        now=now,
    )
    marked, frontier = propagator(str(old["id"]), ev, "SOFT")
    nodes = [
        NodeWrite(
            node_id=str(old["id"]),
            expected_seq=_seq(old),
            set_props=_loser_props(old, ev, {"superseded_by": str(new["id"]), "correction_kind": "CORRECTS"}),
        ),
        NodeWrite(
            node_id=str(new["id"]),
            expected_seq=_seq(new),
            set_props={"lifecycle_status": LifecycleStatus.ACTIVE.value, "prov_event_id": ev.event_id},
        ),
        *[m.node_write() for m in marked],
    ]
    tasks = [RecomputeTask.for_node(m.node_id, reason=m.via, ev=ev) for m in marked]
    tasks += [RecomputeTask.for_node(f, reason="DEPTH_CAP", ev=ev) for f in frontier]
    edges = [
        EdgeWrite(
            edge_id=edge_id(str(new["id"]), str(old["id"]), EdgeKind.CORRECTS, rec.scope_key),
            source_id=str(new["id"]),
            target_id=str(old["id"]),
            kind=EdgeKind.CORRECTS.value,
            props=_edge_props(ev, rec),
        ),
        _resolved_edge(rec, ev, "CORRECTS"),
    ]
    return persister.persist_assurance_mutation(_mutation(ev, nodes, edges, tasks))


def handle_coexists(
    rec: ContradictionRecord,
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    actor: str,
    code: str,
    text: str,
    reader: ConflictReader,
    persister: ConflictPersister,
    cfg: ConflictConfig,
    *,
    now: str | None = None,
) -> MutationReceipt:
    """R-COEX: both stay ACTIVE; requires distinct ``scope_key``; no propagation."""
    if a.get("scope_key") == b.get("scope_key"):
        raise ResolutionRejected(
            "COEXISTS_WITH requires distinct scope_key; a same-scope contradiction must be SUPERSEDES or CORRECTS",
            code="DAG-PV-CONTRADICTION-PENDING",
        )
    _require_activatable(a)
    _require_activatable(b)
    ev = ResolutionEvent.build(
        kind="COEXISTS_WITH",
        rec=rec,
        actor=actor,
        code=code,
        text=text,
        authority_record=_canon_json({"scope_a": str(a["scope_key"]), "scope_b": str(b["scope_key"])}),
        decisive=["scope_key(a) != scope_key(b)"],
        cfg=cfg,
        rule_id="CR017.coexists",
        now=now,
    )
    nodes = [
        NodeWrite(
            node_id=str(n["id"]),
            expected_seq=_seq(n),
            set_props={"lifecycle_status": LifecycleStatus.ACTIVE.value, "prov_event_id": ev.event_id},
        )
        for n in (a, b)
    ]
    edges = [
        EdgeWrite(
            edge_id=edge_id(str(a["id"]), str(b["id"]), EdgeKind.COEXISTS_WITH, GLOBAL_SCOPE_KEY),
            source_id=str(a["id"]),
            target_id=str(b["id"]),
            kind=EdgeKind.COEXISTS_WITH.value,
            props={**_edge_props(ev, rec), "scope_key": GLOBAL_SCOPE_KEY, "resolution_ref": ev.event_id},
        ),
        _resolved_edge(rec, ev, "COEXISTS_WITH"),
    ]
    return persister.persist_assurance_mutation(_mutation(ev, nodes, edges, []))
