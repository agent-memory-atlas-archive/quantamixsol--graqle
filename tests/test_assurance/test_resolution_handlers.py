"""CR-017 PR-017a: AC-3 resolution handlers on fixture graphs."""

from __future__ import annotations

import pytest

from graqle.assurance.conflicts import (
    AlreadyResolved,
    ConflictError,
    ContradictionNotFound,
    ContradictionRecord,
    ResolutionRejected,
    resolve,
)

from ._conflict_fakes import (
    EARLIER,
    LATER,
    NOW,
    FakePersister,
    FakeReader,
    incoming_planner,
    make_cfg,
    node,
)


def _record(a: str = "a", b: str = "b", scope: str = "scope-x", **kw) -> ContradictionRecord:
    base = dict(
        contradiction_id="c" * 32, node_a=a, node_b=b, kind="value_mismatch", key="k",
        value_a_hash="h1", value_b_hash="h2", scope_key=scope, detected_at=NOW, detector_version="1",
    )
    base.update(kw)
    return ContradictionRecord(**base)


def _world(a_kw=None, b_kw=None, **rec_kw):
    reader = FakeReader()
    reader.nodes["a"] = node("a", **(a_kw or {}))
    reader.nodes["b"] = node("b", **(b_kw or {}))
    rec = _record(**rec_kw)
    reader.add_record(rec)
    return reader, rec, FakePersister()


def _go(reader, p, kind, **kw):
    return resolve(
        "c" * 32, kind, actor="tester", rationale_code="DAG-PV-SUPERSEDED", rationale_text="because",
        reader=reader, persister=p, cfg=make_cfg(), now=NOW, **kw,
    )


def _writes(p):
    (m,) = p.mutations.values()
    return m, {w.node_id: w.set_props for w in m.node_writes}


def test_supersedes_sets_valid_until_and_marks_nothing_dirty():
    reader, _, p = _world(a_kw={"valid_from": EARLIER}, b_kw={"valid_from": LATER})
    _go(reader, p, "SUPERSEDES", winner_id="b")
    m, w = _writes(p)
    assert w["a"]["valid_until"] == LATER and w["a"]["superseded_by"] == "b"
    assert w["a"]["lifecycle_status"] == "SUPERSEDED"
    assert w["b"]["lifecycle_status"] == "ACTIVE"
    assert not m.tasks
    assert all("dirty" not in props for props in w.values())
    kinds = {e.kind: e for e in m.edge_writes}
    assert (kinds["SUPERSEDES"].source_id, kinds["SUPERSEDES"].target_id) == ("b", "a")
    assert kinds["CONTRADICTS"].props["resolution_status"] == "RESOLVED"
    assert kinds["CONTRADICTS"].props["resolution_event_id"] == m.event.event_id


def test_supersedes_rejects_new_state_that_starts_before_old():
    reader, _, p = _world(a_kw={"valid_from": LATER}, b_kw={"valid_from": EARLIER})
    with pytest.raises(ResolutionRejected):
        _go(reader, p, "SUPERSEDES", winner_id="b")
    assert not p.mutations


def test_supersedes_does_not_soften_a_terminal_status():
    reader, _, p = _world(a_kw={"status": "INVALIDATED"}, b_kw={"valid_from": LATER})
    _go(reader, p, "SUPERSEDES", winner_id="b")
    _, w = _writes(p)
    assert "lifecycle_status" not in w["a"]


def test_supersedes_will_not_activate_an_invalidated_winner():
    reader, _, p = _world(b_kw={"status": "INVALIDATED", "valid_from": LATER})
    with pytest.raises(ResolutionRejected):
        _go(reader, p, "SUPERSEDES", winner_id="b")
    assert not p.mutations


def test_winner_is_explicit_and_must_be_in_the_pair():
    reader, _, p = _world()
    for bad in (None, "zzz"):
        with pytest.raises(ResolutionRejected):
            _go(reader, p, "SUPERSEDES", winner_id=bad)
    assert not p.mutations


def test_corrects_marks_old_superseded_and_all_dependents_pending_recompute():
    reader, _, p = _world(b_kw={"entity_type": "FUNCTION"}, a_kw={"entity_type": "DOCUMENT"})
    plan = incoming_planner({"a": ["d1"], "d1": ["d2"], "d2": []})
    _go(reader, p, "CORRECTS", winner_id="b", propagator=plan)
    m, w = _writes(p)
    assert w["a"]["lifecycle_status"] == "SUPERSEDED" and w["a"]["correction_kind"] == "CORRECTS"
    assert w["a"]["superseded_by"] == "b"
    assert w["b"]["lifecycle_status"] == "ACTIVE"
    for dep in ("d1", "d2"):
        assert w[dep]["lifecycle_status"] == "PENDING_RECOMPUTE"
    assert {t.node_id for t in m.tasks} == {"d1", "d2"}
    assert {e.kind for e in m.edge_writes} == {"CORRECTS", "CONTRADICTS"}


def test_corrects_without_a_planner_is_refused_not_silently_clean():
    reader, _, p = _world(b_kw={"entity_type": "FUNCTION"})
    with pytest.raises(ConflictError):
        _go(reader, p, "CORRECTS", winner_id="b")
    assert not p.mutations


def test_coexists_rejects_same_scope_pair():
    reader, _, p = _world(a_kw={"scope": "s"}, b_kw={"scope": "s"})
    with pytest.raises(ResolutionRejected) as exc:
        _go(reader, p, "COEXISTS_WITH")
    assert exc.value.code == "DAG-PV-CONTRADICTION-PENDING"
    assert not p.mutations


def test_coexists_keeps_both_active_without_propagation():
    reader, _, p = _world(a_kw={"scope": "s1"}, b_kw={"scope": "s2"})
    _go(reader, p, "COEXISTS_WITH")
    m, w = _writes(p)
    assert w["a"]["lifecycle_status"] == "ACTIVE" and w["b"]["lifecycle_status"] == "ACTIVE"
    assert not m.tasks
    assert {e.kind for e in m.edge_writes} == {"COEXISTS_WITH", "CONTRADICTS"}


def test_unknown_contradiction_is_not_found_and_resolved_one_is_refused():
    reader, rec, p = _world()
    with pytest.raises(ContradictionNotFound):
        resolve("nope", "COEXISTS_WITH", actor="t", rationale_code="DAG-PV-SUPERSEDED", rationale_text="x",
                reader=reader, persister=p, cfg=make_cfg())
    reader.records[rec.contradiction_id].update(resolution_status="RESOLVED", resolution_event_id="pev_x")
    with pytest.raises(AlreadyResolved):
        _go(reader, p, "COEXISTS_WITH")
    assert not p.mutations


def test_missing_node_seq_or_node_fails_closed():
    reader, _, p = _world(a_kw={"scope": "s1"}, b_kw={"scope": "s2"})
    reader.nodes["a"]["assurance_seq"] = None
    with pytest.raises(ConflictError):
        _go(reader, p, "COEXISTS_WITH")
    del reader.nodes["a"]
    with pytest.raises(ConflictError):
        _go(reader, p, "COEXISTS_WITH")
    assert not p.mutations


def test_unregistered_rationale_code_is_refused():
    reader, _, p = _world(a_kw={"scope": "s1"}, b_kw={"scope": "s2"})
    with pytest.raises(ConflictError):
        resolve("c" * 32, "COEXISTS_WITH", actor="t", rationale_code="NOT-A-CODE", rationale_text="x",
                reader=reader, persister=p, cfg=make_cfg())
    assert not p.mutations


def test_event_id_is_the_idempotency_key_and_replay_writes_nothing():
    reader, _, p = _world(a_kw={"scope": "s1"}, b_kw={"scope": "s2"})
    _go(reader, p, "COEXISTS_WITH")
    (m,) = p.mutations.values()
    assert m.event.event_id == "pev_" + m.event.idempotency_key[:26]
    again = _go(reader, p, "COEXISTS_WITH")
    assert again.replayed and len(p.mutations) == 1
