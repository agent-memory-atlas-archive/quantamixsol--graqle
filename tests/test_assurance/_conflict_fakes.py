"""In-memory reader, persister and planner for the CR-017 PR-017a tests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from graqle.assurance.conflicts import (
    AssuranceMutation,
    ConflictConfig,
    ContradictionRecord,
    Mark,
    MutationReceipt,
    ResolutionEvent,
)

# Non-inferential substitutes: deliberately not the real private values.
SUBST_CORROB_MIN = 3
SUBST_PRIORITY = {"code": 4101, "api_spec": 4102, "json_config": 4103, "user_knowledge": 4104, "document": 4105}
NOW = "2026-10-16T08:00:00Z"
EARLIER = "2026-01-01T00:00:00Z"
LATER = "2026-06-01T00:00:00Z"


def make_cfg(corrob_min: int = SUBST_CORROB_MIN) -> ConflictConfig:
    return ConflictConfig(corrob_min=corrob_min, config_version="test-cfg", merge_priority=dict(SUBST_PRIORITY))


def node(
    nid: str,
    *,
    entity_type: str = "DOCUMENT",
    scope: str = "scope-x",
    status: str = "ACTIVE",
    seq: int = 7,
    valid_from: str = EARLIER,
    authenticity: str = "SELF_ASSERTED",
    agent: str | None = None,
    asserted_at: str = NOW,
) -> dict[str, Any]:
    return {
        "id": nid,
        "entity_type": entity_type,
        "properties": {},
        "scope_key": scope,
        "lifecycle_status": status,
        "assurance_seq": seq,
        "valid_from": valid_from,
        "authenticity_status": authenticity,
        "asserted_by_agent_id": agent,
        "asserted_at": asserted_at,
    }


def evidence(eid: str, root: str, status: str = "ACTIVE") -> dict[str, Any]:
    return {"id": eid, "canonical_hash": root, "lifecycle_status": status}


class FakeReader:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.records: dict[str, dict[str, Any]] = {}
        self.agents: dict[str, dict[str, Any]] = {}
        self.support: dict[str, list[dict[str, Any]]] = {}

    def add_record(self, rec: ContradictionRecord) -> None:
        self.records[rec.contradiction_id] = rec.model_dump()

    def load_contradiction(self, contradiction_id: str) -> Mapping[str, Any] | None:
        return self.records.get(contradiction_id)

    def load_node(self, node_id: str) -> Mapping[str, Any] | None:
        return self.nodes.get(node_id)

    def load_agent(self, agent_id: str) -> Mapping[str, Any] | None:
        return self.agents.get(agent_id)

    def supporting_evidence(self, node_id: str) -> Sequence[Mapping[str, Any]]:
        return self.support.get(node_id, [])


class FakePersister:
    """MERGE-by-id semantics: a repeated mutation id is a replay and writes nothing."""

    def __init__(self) -> None:
        self.mutations: dict[str, AssuranceMutation] = {}
        self.events: dict[str, ResolutionEvent] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.calls = 0

    def persist_assurance_mutation(self, m: AssuranceMutation) -> MutationReceipt:
        self.calls += 1
        if m.mutation_id in self.mutations:
            return MutationReceipt(mutation_id=m.mutation_id, replayed=True)
        self.mutations[m.mutation_id] = m
        self.events[m.event.event_id] = m.event
        for e in m.edge_writes:
            self.edges.setdefault(e.edge_id, {"kind": e.kind, "source": e.source_id, "target": e.target_id}).update(e.props)
        return MutationReceipt(mutation_id=m.mutation_id)


def incoming_planner(dependents: Mapping[str, Sequence[str]], seqs: Mapping[str, int] | None = None):
    """Test planner: BFS over a ``{upstream: [dependents]}`` map (incoming edges)."""
    seqs = seqs or {}

    def plan(seed: str, ev: ResolutionEvent, mode: str):
        seen = {seed}
        order: list[str] = []
        queue = [seed]
        while queue:
            cur = queue.pop(0)
            for dep in dependents.get(cur, ()):
                if dep not in seen:
                    seen.add(dep)
                    order.append(dep)
                    queue.append(dep)
        marks = [
            Mark(
                node_id=n,
                via="SUPPORTED_BY",
                expected_seq=seqs.get(n, 0),
                set_props={"lifecycle_status": "PENDING_RECOMPUTE", "dirty": True, "prov_event_id": ev.event_id},
            )
            for n in order
        ]
        return marks, []

    return plan
