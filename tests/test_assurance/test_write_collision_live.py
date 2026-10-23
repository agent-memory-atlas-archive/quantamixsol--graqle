"""CR-017 PR-017b live proofs against a scratch Neo4j Community Edition server.

AC-7 live half (two concurrent writers on one planned node), AC-8 replay, atomic rollback, and
the recompute-task claim. CI has no Neo4j, so these SKIP there. A skip is not a pass: run them
against the scratch server and report passes and skips separately.

Safety: connects only to ``GRAQLE_TEST_NEO4J_CE_URI`` (default ``bolt://127.0.0.1:17687``),
refuses port 7687 (the shared DBMS) outright and refuses any server that is not Community
Edition. It deletes only nodes whose id starts with ``cr017b-live-``, the events it wrote
(``rule_id = 'CR017.live-test'``) and the ``:RecomputeTask`` nodes pointing at them.
"""

from __future__ import annotations

import os
import threading
from typing import Any
from urllib.parse import urlparse

import pytest

from graqle.assurance.conflicts import (
    AssuranceMutation,
    EdgeWrite,
    NodeWrite,
    RecomputeTask,
    system_event,
)
from graqle.assurance.propagation import ReceiptingPersister
from graqle.connectors.neo4j import Neo4jConnector
from graqle.governance.tamper_evidence.kg_persist import Neo4jBatchPersister, WriteCollisionError

from ._conflict_fakes import NOW, make_cfg, node

pytestmark = pytest.mark.integration

CE_URI = os.environ.get(
    "GRAQLE_TEST_NEO4J_CE_URI", os.environ.get("NEO4J_URI", "bolt://127.0.0.1:17687")
)
CE_PASSWORD = os.environ.get("NEO4J_PASSWORD", "unused")
SHARED_PORT = 7687
PREFIX = "cr017b-live-"
# Non-inferential substitute for the protected retry count.
SUBST_RETRIES = 2
_CLEANUP = (
    "MATCH (n:CogniNode) WHERE n.id STARTS WITH $p OR n.rule_id = 'CR017.live-test' DETACH DELETE n",
    "MATCH (t:RecomputeTask) WHERE t.node_id STARTS WITH $p DETACH DELETE t",
)


@pytest.fixture
def conn() -> Any:
    port = urlparse(CE_URI).port
    if port == SHARED_PORT:
        pytest.fail(f"refusing {CE_URI}: port {SHARED_PORT} is the shared DBMS")
    try:
        from neo4j import GraphDatabase
    except ImportError:
        pytest.skip("neo4j driver not installed")
    drv = GraphDatabase.driver(CE_URI, auth=("neo4j", CE_PASSWORD))
    try:
        drv.verify_connectivity()
        with drv.session(database="system") as s:
            editions = {
                str(r["edition"]).lower()
                for r in s.run("CALL dbms.components() YIELD edition RETURN edition")
            }
    except Exception as exc:  # noqa: BLE001
        drv.close()
        pytest.skip(f"no scratch Neo4j at {CE_URI} ({type(exc).__name__})")
    editions.discard("")
    if editions != {"community"}:
        drv.close()
        pytest.skip(f"{CE_URI} is not a scratch Community Edition server")
    c = Neo4jConnector(uri=CE_URI, username="neo4j", password=CE_PASSWORD)
    with drv.session(database="neo4j") as s:
        s.run("CREATE CONSTRAINT cogninode_id IF NOT EXISTS FOR (n:CogniNode) REQUIRE n.id IS UNIQUE").consume()
        for q in _CLEANUP:
            s.run(q, p=PREFIX).consume()
    c.create_recompute_schema()
    yield c
    with drv.session(database="neo4j") as s:
        for q in _CLEANUP:
            s.run(q, p=PREFIX).consume()
    drv.close()


def _rows(c: Neo4jConnector, query: str, **params: Any) -> list[dict[str, Any]]:
    with c._get_driver().session(database="neo4j") as s:
        return [dict(r) for r in s.run(query, **params)]


def _make_nodes(c: Neo4jConnector, *ids: str) -> None:
    with c._get_driver().session(database="neo4j") as s:
        for i in ids:
            s.run("CREATE (:CogniNode {id: $id, lifecycle_status: 'ACTIVE'})", id=PREFIX + i).consume()


def _seq(c: Neo4jConnector, nid: str) -> Any:
    (row,) = _rows(c, "MATCH (n:CogniNode {id: $id}) RETURN n.assurance_seq AS s", id=PREFIX + nid)
    return row["s"]


def _mutation(tag: str, shared: str, own: str, *, shared_seq: int = 0, own_seq: int = 0) -> AssuranceMutation:
    ev = system_event(
        "INVALIDATION", node(PREFIX + tag, seq=shared_seq), actor="t", code="DAG-PV-INVALIDATED", text="x",
        decisive=[tag], cfg=make_cfg(), rule_id="CR017.live-test", extra={"tag": tag}, now=NOW,
    )
    return AssuranceMutation(
        mutation_id=ev.event_id,
        event=ev,
        node_writes=[
            NodeWrite(node_id=PREFIX + shared, expected_seq=shared_seq, set_props={"dirty": True, "by": tag}),
            NodeWrite(node_id=PREFIX + own, expected_seq=own_seq, set_props={"dirty": True, "by": tag}),
        ],
        edge_writes=[
            EdgeWrite(
                edge_id=PREFIX + "edge-" + tag, source_id=ev.event_id, target_id=PREFIX + shared,
                kind="INVALIDATES", props={"strength": 1.0},
            )
        ],
        tasks=[RecomputeTask.for_node(PREFIX + own, reason="DERIVED_FROM", ev=ev)],
        inputs_hash=ev.inputs_hash,
    )


def test_ac7_two_concurrent_writers_exactly_one_commits_and_the_loser_changes_nothing(conn: Neo4jConnector) -> None:
    rounds = 8
    for r in range(rounds):
        shared, a, b = f"shared{r}", f"a{r}", f"b{r}"
        _make_nodes(conn, shared, a, b)
        barrier = threading.Barrier(2)
        outcomes: dict[str, Any] = {}

        def writer(tag: str, own: str) -> None:
            persister = Neo4jBatchPersister(conn, write_collision_retries=SUBST_RETRIES)
            m = _mutation(tag, shared, own)
            barrier.wait()
            try:
                outcomes[tag] = persister.persist_assurance_mutation(m)
            except WriteCollisionError as exc:
                outcomes[tag] = exc

        threads = [threading.Thread(target=writer, args=(a, a)), threading.Thread(target=writer, args=(b, b))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        winners = [t for t, o in outcomes.items() if isinstance(o, dict)]
        losers = [t for t, o in outcomes.items() if isinstance(o, WriteCollisionError)]
        assert len(winners) == 1 and len(losers) == 1, outcomes
        win, lose = winners[0], losers[0]
        assert outcomes[lose].node_id == PREFIX + shared
        assert _seq(conn, shared) == 1  # bumped exactly once
        assert _seq(conn, win) == 1 and _seq(conn, lose) is None  # loser's own node untouched
        events = {e["id"] for e in _rows(conn, "MATCH (e:CogniNode) WHERE e.rule_id = 'CR017.live-test' RETURN e.id AS id")}
        assert _mutation(win, shared, win).event.event_id in events
        assert _mutation(lose, shared, lose).event.event_id not in events  # rolled back with the rest
        assert _rows(conn, "MATCH (t:RecomputeTask {node_id: $id}) RETURN t.task_id AS t", id=PREFIX + lose) == []
        assert _rows(conn, "MATCH ()-[r:RELATES_TO {id: $id}]->() RETURN r.id AS i", id=PREFIX + "edge-" + lose) == []


def test_ac7_retry_with_a_replanner_succeeds_after_the_collision(conn: Neo4jConnector) -> None:
    _make_nodes(conn, "shared", "a", "b")
    inner = Neo4jBatchPersister(conn, write_collision_retries=SUBST_RETRIES)
    stale = _mutation("a", "shared", "a")
    # another writer commits first, bumping the shared node's sequence
    assert ReceiptingPersister(inner).persist_assurance_mutation(_mutation("b", "shared", "b")).replayed is False

    def replanner(old: AssuranceMutation) -> AssuranceMutation:
        return _mutation("a", "shared", "a", shared_seq=_seq(conn, "shared"))

    receipt = ReceiptingPersister(inner, replanner=replanner).persist_assurance_mutation(stale)
    assert receipt.replayed is False and receipt.nodes_written == 2
    assert _seq(conn, "shared") == 2 and _seq(conn, "a") == 1


def test_ac8_persisting_the_same_mutation_twice_replays_with_zero_writes(conn: Neo4jConnector) -> None:
    _make_nodes(conn, "shared", "a")
    persister = ReceiptingPersister(Neo4jBatchPersister(conn, write_collision_retries=SUBST_RETRIES))
    m = _mutation("a", "shared", "a")
    first = persister.persist_assurance_mutation(m)
    second = persister.persist_assurance_mutation(m)
    assert first.replayed is False and second.replayed is True
    assert second.nodes_written == 0 and second.edges_written == 0 and second.tasks_written == 0
    assert _seq(conn, "shared") == 1 and _seq(conn, "a") == 1  # not bumped by the replay


def test_a_missing_edge_endpoint_rolls_back_event_and_node_writes(conn: Neo4jConnector) -> None:
    _make_nodes(conn, "shared", "a")
    m = _mutation("a", "shared", "a")
    m.edge_writes[0].target_id = PREFIX + "does-not-exist"
    persister = Neo4jBatchPersister(conn, write_collision_retries=SUBST_RETRIES)
    with pytest.raises(Exception, match="edge endpoint"):
        persister.persist_assurance_mutation(m)
    assert _seq(conn, "shared") is None and _seq(conn, "a") is None
    assert _rows(conn, "MATCH (e:CogniNode {id: $id}) RETURN e.id AS i", id=m.event.event_id) == []


def test_two_workers_never_claim_the_same_recompute_task(conn: Neo4jConnector) -> None:
    ids = [f"w{i}" for i in range(6)]
    _make_nodes(conn, *ids)
    ev = _mutation("w", "w0", "w1").event
    with conn._get_driver().session(database="neo4j") as s:
        for i in ids:
            t = RecomputeTask.for_node(PREFIX + i, reason="DERIVED_FROM", ev=ev)
            s.run("CREATE (t:RecomputeTask) SET t = $p", p=t.model_dump()).consume()
    barrier = threading.Barrier(2)
    claimed: list[list[str]] = [[], []]

    def worker(k: int) -> None:
        barrier.wait()
        claimed[k] = [t["task_id"] for t in conn.claim_recompute_tasks(len(ids))]

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    both = claimed[0] + claimed[1]
    assert len(both) == len(set(both)) == len(ids)
    states = {r["s"] for r in _rows(conn, "MATCH (t:RecomputeTask) WHERE t.node_id STARTS WITH $p RETURN t.state AS s", p=PREFIX)}
    assert states == {"RUNNING"}


def test_task_state_update_and_unknown_task(conn: Neo4jConnector) -> None:
    _make_nodes(conn, "w0")
    ev = _mutation("w", "w0", "w0").event
    t = RecomputeTask.for_node(PREFIX + "w0", reason="DERIVED_FROM", ev=ev)
    with conn._get_driver().session(database="neo4j") as s:
        s.run("CREATE (t:RecomputeTask) SET t = $p", p=t.model_dump()).consume()
    conn.set_recompute_task_state(t.task_id, "DONE", 1)
    (row,) = _rows(conn, "MATCH (t:RecomputeTask {task_id: $i}) RETURN t.state AS s, t.attempts AS a", i=t.task_id)
    assert row == {"s": "DONE", "a": 1}
    with pytest.raises(ValueError):
        conn.set_recompute_task_state("rt_missing", "DONE", 1)


def test_backfill_sets_a_missing_sequence_to_zero(conn: Neo4jConnector) -> None:
    _make_nodes(conn, "bf")
    assert conn.backfill_assurance_seq(10) >= 1
    assert _seq(conn, "bf") == 0
    with pytest.raises(ValueError):
        conn.backfill_assurance_seq(0)
