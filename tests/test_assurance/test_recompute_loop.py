"""CR-017 PR-017b: AC-15 (recompute exhaustion is INVALIDATED, never ACTIVE) and the loop's fail-closed paths."""

from __future__ import annotations

from typing import Any

import pytest

from graqle.assurance.conflicts import ConflictError, RecomputeTask, system_event
from graqle.assurance.propagation import PropagationConfig, make_propagator
from graqle.assurance.recompute import (
    Neo4jRecomputeQueue,
    RecomputeConfig,
    recompute_loop,
)
from graqle.governance.tamper_evidence.kg_persist import WriteCollisionError

from ._conflict_fakes import NOW, FakePersister, evidence, make_cfg, node
from ._propagation_fakes import (
    SUBST_ATTEMPTS,
    SUBST_BATCH,
    SUBST_DEPTH,
    FakeGraph,
    FakeQueue,
    FakeSource,
    RecomputeFakeReader,
)

CFG = RecomputeConfig(max_attempts=SUBST_ATTEMPTS, batch_size=SUBST_BATCH)


class OkRecomputer:
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        self.calls = 0
        self.extra = extra or {"vector_version": "v2"}

    def recompute(self, n, reader):
        self.calls += 1
        return self.extra


class FailingRecomputer:
    def __init__(self) -> None:
        self.calls = 0

    def recompute(self, n, reader):
        self.calls += 1
        raise RuntimeError("vector service unavailable")


def _task(node_id: str, reason: str = "DERIVED_FROM") -> RecomputeTask:
    ev = system_event(
        "INVALIDATION", node("seed", seq=1), actor="t", code="DAG-PV-INVALIDATED", text="x",
        decisive=["d"], cfg=make_cfg(), rule_id="CR017.invalidate", now=NOW,
    )
    return RecomputeTask.for_node(node_id, reason=reason, ev=ev)


def _setup(*, cls: str = "Claim", status: str = "PENDING_RECOMPUTE", support: int = 1, scope: str = "scope-x"):
    reader = RecomputeFakeReader()
    reader.add("c1", cls=cls, status=status, seq=3)
    reader.support["c1"] = [evidence(f"e{i}", f"root{i}") | {"scope_key": scope} for i in range(support)]
    return reader


def _loop(queue, reader, recomputers, *, persister=None, graph=None):
    persister = persister or FakePersister()
    graph = graph or FakeGraph()
    report = recompute_loop(
        queue, recomputers, reader=reader, persister=persister,
        propagator=make_propagator(FakeSource(graph), PropagationConfig(max_depth=SUBST_DEPTH)),
        cfg=CFG, conflict_cfg=make_cfg(), now=NOW,
    )
    return report, persister


def test_supported_node_is_recomputed_to_active_and_the_task_is_done():
    reader, rec = _setup(), OkRecomputer()
    queue = FakeQueue([_task("c1")])
    report, persister = _loop(queue, reader, {"Claim": rec})
    assert report.recomputed == ["c1"] and not report.errors
    (m,) = persister.mutations.values()
    (w,) = m.node_writes
    assert w.set_props["lifecycle_status"] == "ACTIVE" and w.set_props["dirty"] is False
    assert w.set_props["vector_version"] == "v2" and w.expected_seq == 3
    assert m.event.event_type == "RECOMPUTATION" and m.event.rationale_code == "DAG-PV-RECOMPUTED"
    assert queue.state[_task("c1").task_id][0] == "DONE"


def test_ac15_exhausted_recompute_is_invalidated_with_the_exhausted_code_never_active():
    reader, failing = _setup(), FailingRecomputer()
    queue = FakeQueue([_task("c1")])
    persister = FakePersister()
    first, _ = _loop(queue, reader, {"Claim": failing}, persister=persister)
    assert first.retried == ["c1"] and not first.invalidated
    assert queue.state[_task("c1").task_id] == ("QUEUED", 1)
    assert persister.mutations == {}  # a failed attempt writes nothing
    second, _ = _loop(queue, reader, {"Claim": failing}, persister=persister)
    assert second.invalidated == ["c1"] and second.exhausted == ["c1"]
    assert failing.calls == SUBST_ATTEMPTS
    (m,) = persister.mutations.values()
    assert m.event.event_type == "INVALIDATION" and m.event.rationale_code == "DAG-PV-RECOMPUTE-EXHAUSTED"
    statuses = {w.set_props.get("lifecycle_status") for w in m.node_writes}
    assert statuses == {"INVALIDATED"}
    assert queue.state[_task("c1").task_id][0] == "EXHAUSTED"
    assert "vector service unavailable" in queue.history[-1][3]


def test_no_mutation_ever_writes_active_when_the_recomputer_always_fails():
    reader, queue, persister = _setup(), FakeQueue([_task("c1")]), FakePersister()
    for _ in range(SUBST_ATTEMPTS):
        _loop(queue, reader, {"Claim": FailingRecomputer()}, persister=persister)
    written = [w.set_props.get("lifecycle_status") for m in persister.mutations.values() for w in m.node_writes]
    assert "ACTIVE" not in written


def test_claim_without_support_is_invalidated_without_running_the_recomputer():
    reader, rec = _setup(support=0), OkRecomputer()
    report, persister = _loop(FakeQueue([_task("c1")]), reader, {"Claim": rec})
    (m,) = persister.mutations.values()
    assert m.node_writes[0].set_props["lifecycle_status"] == "INVALIDATED"
    assert m.event.rationale_code == "DAG-PV-INVALIDATED" and rec.calls == 0
    assert report.recomputed == ["c1"]


def test_evidence_from_another_scope_or_inactive_does_not_count_as_support():
    reader = _setup(support=0)
    reader.support["c1"] = [
        evidence("e1", "r1") | {"scope_key": "other-scope"},
        evidence("e2", "r2", status="INVALIDATED") | {"scope_key": "scope-x"},
    ]
    _, persister = _loop(FakeQueue([_task("c1")]), reader, {"Claim": OkRecomputer()})
    (m,) = persister.mutations.values()
    assert m.node_writes[0].set_props["lifecycle_status"] == "INVALIDATED"


def test_invalidated_upstream_forces_invalidation():
    reader = _setup()
    reader.bad_upstream["c1"] = 1
    _, persister = _loop(FakeQueue([_task("c1")]), reader, {"Claim": OkRecomputer()})
    (m,) = persister.mutations.values()
    assert m.node_writes[0].set_props["lifecycle_status"] == "INVALIDATED"


def test_missing_recomputer_fails_the_attempt_closed():
    queue = FakeQueue([_task("c1")])
    report, persister = _loop(queue, _setup(cls="Decision"), {"Claim": OkRecomputer()})
    assert report.retried == ["c1"] and "no recomputer" in report.errors[_task("c1").task_id]
    assert persister.mutations == {}


def test_recomputer_may_not_set_reserved_properties():
    queue = FakeQueue([_task("c1")])
    report, persister = _loop(queue, _setup(), {"Claim": OkRecomputer({"lifecycle_status": "ACTIVE", "dirty": True})})
    assert report.retried == ["c1"] and "reserved" in report.errors[_task("c1").task_id]
    assert persister.mutations == {}


@pytest.mark.parametrize("status", ["INVALIDATED", "SUPERSEDED", "RETRACTED", "ACTIVE"])
def test_a_node_that_is_not_pending_is_never_resurrected(status):
    reader, rec = _setup(status=status), OkRecomputer()
    queue = FakeQueue([_task("c1")])
    report, persister = _loop(queue, reader, {"Claim": rec})
    assert report.skipped == ["c1"] and rec.calls == 0 and persister.mutations == {}
    assert queue.state[_task("c1").task_id][0] == "DONE"


def test_missing_node_counts_as_a_failed_attempt():
    queue = FakeQueue([_task("ghost")])
    report, _ = _loop(queue, RecomputeFakeReader(), {"Claim": OkRecomputer()})
    assert report.retried == ["ghost"]


def test_write_collision_during_recompute_counts_an_attempt_and_is_retried():
    class Colliding(FakePersister):
        def persist_assurance_mutation(self, m):
            raise WriteCollisionError("c1", 3, 4)

    queue = FakeQueue([_task("c1")])
    report, _ = _loop(queue, _setup(), {"Claim": OkRecomputer()}, persister=Colliding())
    assert report.retried == ["c1"]
    assert queue.state[_task("c1").task_id] == ("QUEUED", 1)


def test_failed_invalidation_at_exhaustion_leaves_the_task_queued_and_the_node_not_active():
    class Failing(FakePersister):
        def persist_assurance_mutation(self, m):
            raise RuntimeError("db down")

    queue = FakeQueue([_task("c1")])
    queue.state[_task("c1").task_id] = ("QUEUED", SUBST_ATTEMPTS - 1)
    queue.tasks[_task("c1").task_id] = _task("c1").model_copy(update={"attempts": SUBST_ATTEMPTS - 1})
    report, persister = _loop(queue, _setup(), {"Claim": FailingRecomputer()}, persister=Failing())
    assert report.retried == ["c1"] and not report.invalidated
    assert "invalidation failed" in report.errors[_task("c1").task_id]
    assert queue.state[_task("c1").task_id][0] == "QUEUED"


def test_depth_cap_task_continues_the_propagation_to_the_dependents():
    g = FakeGraph()
    for name in ("c1", "d1", "d2", "d3"):
        g.add(name)
    g.depend("d1", "c1")
    g.depend("d2", "d1")
    g.depend("d3", "d2")
    reader = _setup()
    queue = FakeQueue([_task("c1", "DEPTH_CAP")])
    report, persister = _loop(queue, reader, {"Claim": OkRecomputer()}, graph=g)
    (m,) = persister.mutations.values()
    assert {w.node_id for w in m.node_writes} == {"c1", "d1", "d2"}
    assert {t.node_id: t.reason for t in m.tasks} == {"d1": "DERIVED_FROM", "d2": "DEPTH_CAP"}
    assert report.recomputed == ["c1"]


def test_depth_cap_continuation_failure_counts_an_attempt():
    g = FakeGraph()
    g.add("c1")
    g.fail = True
    queue = FakeQueue([_task("c1", "DEPTH_CAP")])
    report, persister = _loop(queue, _setup(), {"Claim": OkRecomputer()}, graph=g)
    assert report.retried == ["c1"] and persister.mutations == {}


def test_depth_cap_continuation_on_a_terminal_node_still_marks_dependents():
    g = FakeGraph()
    g.add("c1", status="INVALIDATED")
    g.add("d1")
    g.depend("d1", "c1")
    queue = FakeQueue([_task("c1", "DEPTH_CAP")])
    _, persister = _loop(queue, _setup(status="INVALIDATED"), {"Claim": OkRecomputer()}, graph=g)
    (m,) = persister.mutations.values()
    assert [w.node_id for w in m.node_writes] == ["d1"]  # the invalid node itself is not rewritten


def test_batch_size_limits_the_claim():
    reader = _setup()
    reader.add("c2")
    reader.support["c2"] = reader.support["c1"]
    queue = FakeQueue([_task("c1"), _task("c2")])
    cfg = RecomputeConfig(max_attempts=SUBST_ATTEMPTS, batch_size=1)
    report = recompute_loop(
        queue, {"Claim": OkRecomputer()}, reader=reader, persister=FakePersister(),
        propagator=lambda s, e, m: ([], []), cfg=cfg, conflict_cfg=make_cfg(), now=NOW,
    )
    assert len(report.recomputed) == 1


@pytest.mark.parametrize("bad", [0, -1, True, "2", None])
def test_config_values_must_be_positive_integers(bad):
    with pytest.raises(ConflictError):
        RecomputeConfig(max_attempts=bad, batch_size=1)  # type: ignore[arg-type]
    with pytest.raises(ConflictError):
        RecomputeConfig(max_attempts=1, batch_size=bad)  # type: ignore[arg-type]


def test_neo4j_queue_maps_stored_properties_and_ignores_bookkeeping_keys():
    task = _task("c1")

    class Conn:
        def __init__(self) -> None:
            self.set: list[tuple] = []

        def claim_recompute_tasks(self, n):
            return [{**task.model_dump(), "claim_token": "abc", "last_error": "x", "state": "RUNNING"}]

        def set_recompute_task_state(self, *args):
            self.set.append(args)

    conn = Conn()
    queue = Neo4jRecomputeQueue(conn)
    (claimed,) = queue.claim(1)
    assert claimed.task_id == task.task_id and claimed.state == "RUNNING"
    queue.set_state(claimed, "DONE", 1)
    assert conn.set == [(task.task_id, "DONE", 1, None)]
