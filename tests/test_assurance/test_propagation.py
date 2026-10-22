"""CR-017 PR-017b: AC-5 (incoming-only traversal) and AC-6 (depth cap), plus fail-closed paths."""

from __future__ import annotations

import pytest

from graqle.assurance import propagation
from graqle.assurance.conflicts import ConflictError, ContradictionRecord, ResolutionEvent, resolve
from graqle.assurance.propagation import (
    PropagationConfig,
    PropagationError,
    invalidate,
    make_propagator,
    propagate_dirty,
)

from ._conflict_fakes import NOW, FakePersister, FakeReader, make_cfg, node
from ._propagation_fakes import SUBST_DEPTH, FakeGraph, FakeSession, FakeSource


def _event(seed: str = "claim") -> ResolutionEvent:
    from graqle.assurance.conflicts import system_event

    return system_event(
        "INVALIDATION", node(seed), actor="t", code="DAG-PV-INVALIDATED", text="x",
        decisive=["d"], cfg=make_cfg(), rule_id="CR017.invalidate", now=NOW,
    )


def _layers() -> FakeGraph:
    """Evidence <- Claim <- Abstraction <- Decision (arrows read 'depends on')."""
    g = FakeGraph()
    g.add("evidence", "Evidence")
    g.add("claim", "Claim")
    g.add("abstraction", "Abstraction", seq=4)
    g.add("decision", "Decision", seq=9)
    g.depend("claim", "evidence", "SUPPORTED_BY")
    g.depend("abstraction", "claim")
    g.depend("decision", "abstraction")
    return g


def test_ac5_incoming_traversal_marks_dependents_and_never_upstream_evidence():
    g = _layers()
    marks, frontier = propagate_dirty("claim", _event(), "HARD", FakeSession(g), PropagationConfig(max_depth=8))
    assert [m.node_id for m in marks] == ["abstraction", "decision"]
    assert frontier == []
    assert "evidence" not in {m.node_id for m in marks}
    assert [m.expected_seq for m in marks] == [4, 9]


def test_ac5_query_reads_incoming_edges_and_planning_never_writes():
    g = _layers()
    propagate_dirty("claim", _event(), "HARD", FakeSession(g), PropagationConfig(max_depth=8))
    assert g.queries
    for q in g.queries:
        assert "(x:CogniNode)-[r:RELATES_TO]->(y:CogniNode {id: $id})" in q
        assert not any(w in q.upper() for w in ("SET ", "MERGE", "CREATE", "DELETE", "REMOVE"))


def test_ac5_end_to_end_invalidate_marks_one_mutation_and_leaves_evidence_clean():
    g, reader, persister = _layers(), FakeReader(), FakePersister()
    reader.nodes["claim"] = node("claim", seq=5)
    receipt = invalidate(
        "claim", "owner", "DAG-PV-INVALIDATED", "retracted", reader=reader,
        propagator=make_propagator(FakeSource(g), PropagationConfig(max_depth=8)),
        persister=persister, cfg=make_cfg(), now=NOW,
    )
    assert receipt.replayed is False and persister.calls == 1
    (m,) = persister.mutations.values()
    writes = {w.node_id: w.set_props for w in m.node_writes}
    assert set(writes) == {"claim", "abstraction", "decision"}
    assert writes["claim"]["lifecycle_status"] == "INVALIDATED"
    assert writes["claim"]["dirty_reason"] == "INVALIDATES"
    assert writes["abstraction"]["lifecycle_status"] == "PENDING_RECOMPUTE"
    assert writes["abstraction"]["dirty"] is True
    assert {t.node_id for t in m.tasks} == {"abstraction", "decision"}
    (edge,) = m.edge_writes
    assert edge.kind == "INVALIDATES" and edge.source_id == m.event.event_id and edge.target_id == "claim"
    assert m.event.event_type == "INVALIDATION"


def test_replaying_the_same_invalidation_is_a_noop():
    g, reader, persister = _layers(), FakeReader(), FakePersister()
    reader.nodes["claim"] = node("claim", seq=5)
    kw = dict(
        reader=reader, propagator=make_propagator(FakeSource(g), PropagationConfig(max_depth=8)),
        persister=persister, cfg=make_cfg(), now=NOW,
    )
    first = invalidate("claim", "owner", "DAG-PV-INVALIDATED", "t", **kw)
    second = invalidate("claim", "owner", "DAG-PV-INVALIDATED", "t", **kw)
    assert first.replayed is False and second.replayed is True
    assert len(persister.mutations) == 1


def test_deletion_adds_a_tombstone_and_never_removes_bytes():
    g, reader, persister = _layers(), FakeReader(), FakePersister()
    reader.nodes["evidence"] = node("evidence", seq=1)
    invalidate(
        "evidence", "owner", "DAG-PV-INVALIDATED", "erasure request", reader=reader,
        propagator=make_propagator(FakeSource(g), PropagationConfig(max_depth=8)),
        persister=persister, cfg=make_cfg(), deletion=True, now=NOW,
    )
    (m,) = persister.mutations.values()
    seed = next(w for w in m.node_writes if w.node_id == "evidence")
    assert seed.set_props["tombstone"] is True
    assert {w.node_id for w in m.node_writes} == {"evidence", "claim", "abstraction", "decision"}


def test_ac6_depth_cap_queues_the_frontier_and_never_leaves_it_clean():
    g = FakeGraph()
    g.add("seed")
    for name in ("n1", "n2", "n3"):
        g.add(name)
    g.depend("n1", "seed")
    g.depend("n2", "n1")
    g.depend("n3", "n2")
    marks, frontier = propagate_dirty("seed", _event("seed"), "HARD", FakeSession(g), PropagationConfig(max_depth=SUBST_DEPTH))
    assert [m.node_id for m in marks] == ["n1", "n2"]
    assert frontier == ["n2"]  # n3 is beyond the cap; its owner n2 carries the continuation
    assert all(m.set_props["dirty"] is True for m in marks)


def test_ac6_invalidate_turns_the_frontier_into_a_depth_cap_task():
    g, reader, persister = FakeGraph(), FakeReader(), FakePersister()
    for name in ("seed", "n1", "n2", "n3"):
        g.add(name)
    g.depend("n1", "seed")
    g.depend("n2", "n1")
    g.depend("n3", "n2")
    reader.nodes["seed"] = node("seed", seq=1)
    invalidate(
        "seed", "owner", "DAG-PV-INVALIDATED", "t", reader=reader,
        propagator=make_propagator(FakeSource(g), PropagationConfig(max_depth=SUBST_DEPTH)),
        persister=persister, cfg=make_cfg(), now=NOW,
    )
    (m,) = persister.mutations.values()
    reasons = {t.node_id: t.reason for t in m.tasks}
    assert reasons == {"n1": "DERIVED_FROM", "n2": "DEPTH_CAP"}  # one task per node, none for n3 yet
    assert "n3" not in {w.node_id for w in m.node_writes}


def test_cycles_terminate_and_each_node_is_marked_once():
    g = FakeGraph()
    for name in ("a", "b", "c"):
        g.add(name)
    g.depend("b", "a")
    g.depend("c", "b")
    g.depend("a", "c")  # cycle back to the seed
    marks, _ = propagate_dirty("a", _event("a"), "HARD", FakeSession(g), PropagationConfig(max_depth=8))
    assert [m.node_id for m in marks] == ["b", "c"]


def test_agents_and_provenance_events_are_never_marked():
    g = _layers()
    g.add("agent", "Agent")
    g.add("event", "ProvenanceEvent")
    g.depend("agent", "claim")
    g.depend("event", "claim")
    marks, _ = propagate_dirty("claim", _event(), "HARD", FakeSession(g), PropagationConfig(max_depth=8))
    assert {m.node_id for m in marks} == {"abstraction", "decision"}


def test_only_active_nodes_become_pending_recompute():
    g = FakeGraph()
    g.add("seed")
    g.add("live", status="ACTIVE")
    g.add("gone", status="INVALIDATED")
    g.depend("live", "seed")
    g.depend("gone", "seed")
    marks, _ = propagate_dirty("seed", _event("seed"), "HARD", FakeSession(g), PropagationConfig(max_depth=8))
    by_id = {m.node_id: m.set_props for m in marks}
    assert by_id["live"]["lifecycle_status"] == "PENDING_RECOMPUTE"
    assert "lifecycle_status" not in by_id["gone"] and by_id["gone"]["dirty"] is True


def test_soft_mode_records_corrects_as_the_reason():
    g = _layers()
    marks, _ = propagate_dirty("claim", _event(), "SOFT", FakeSession(g), PropagationConfig(max_depth=8))
    assert {m.set_props["dirty_reason"] for m in marks} == {"CORRECTS"}


def test_driver_error_raises_and_returns_no_partial_marks():
    g = _layers()
    g.fail = True
    with pytest.raises(PropagationError) as exc:
        propagate_dirty("claim", _event(), "HARD", FakeSession(g), PropagationConfig(max_depth=8))
    assert exc.value.seed_id == "claim"


def test_session_open_failure_is_a_propagation_error():
    class Broken:
        def read_session(self):
            raise OSError("no connection")

    plan = make_propagator(Broken(), PropagationConfig(max_depth=8))
    with pytest.raises(PropagationError):
        plan("claim", _event(), "HARD")


def test_unknown_mode_and_bad_config_are_rejected():
    with pytest.raises(PropagationError):
        propagate_dirty("claim", _event(), "MAYBE", FakeSession(_layers()), PropagationConfig(max_depth=8))
    for bad in (0, -1, True, "8"):
        with pytest.raises(PropagationError):
            PropagationConfig(max_depth=bad)  # type: ignore[arg-type]


def test_non_integer_sequence_in_the_graph_aborts_planning():
    g = _layers()
    g.nodes["abstraction"]["seq"] = "four"
    with pytest.raises(PropagationError):
        propagate_dirty("claim", _event(), "HARD", FakeSession(g), PropagationConfig(max_depth=8))


def test_invalidate_unknown_node_raises():
    with pytest.raises(ConflictError):
        invalidate(
            "ghost", "owner", "DAG-PV-INVALIDATED", "t", reader=FakeReader(),
            propagator=lambda s, e, m: ([], []), persister=FakePersister(), cfg=make_cfg(),
        )


def test_invalidate_with_an_unregistered_code_raises():
    reader = FakeReader()
    reader.nodes["x"] = node("x")
    with pytest.raises(ConflictError):
        invalidate(
            "x", "owner", "NOT-A-CODE", "t", reader=reader,
            propagator=lambda s, e, m: ([], []), persister=FakePersister(), cfg=make_cfg(),
        )


def test_corrects_does_not_write_new_or_old_twice_when_they_are_dependents():
    """A dependent that is also the winner must not appear twice in one mutation."""
    g = FakeGraph()
    g.add("old")
    g.add("new")
    g.add("dep")
    g.depend("new", "old", "SUPPORTED_BY")
    g.depend("dep", "new")
    reader, persister = FakeReader(), FakePersister()
    reader.nodes["old"] = node("old", entity_type="CODE", authenticity="SIGNED", seq=1)
    reader.nodes["new"] = node("new", entity_type="CODE", authenticity="SIGNED", seq=2)
    rec = ContradictionRecord(
        contradiction_id="e" * 32, node_a="new", node_b="old", kind="value_mismatch", key="k",
        value_a_hash="a", value_b_hash="b", scope_key="scope-x", detected_at=NOW, detector_version="1",
    )
    reader.add_record(rec)
    resolve(
        "e" * 32, "CORRECTS", actor="t", rationale_code="DAG-PV-SUPERSEDED", rationale_text="fix",
        reader=reader, persister=persister, cfg=make_cfg(), winner_id="new",
        propagator=make_propagator(FakeSource(g), PropagationConfig(max_depth=8)), now=NOW,
    )
    (m,) = persister.mutations.values()
    ids = [w.node_id for w in m.node_writes]
    assert len(ids) == len(set(ids))
    assert {t.node_id for t in m.tasks} == {"dep"}


def test_module_exports_resolve():
    for name in propagation.__all__:
        assert hasattr(propagation, name)
