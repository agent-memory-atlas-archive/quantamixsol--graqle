"""CR-018 PR-018a live proofs for the Neo4j sequencer (AC-4 Neo4j half, AC-20).

CI has no Neo4j, so these SKIP there. A skip is not a pass: run them locally
against a scratch Community Edition server and report passes and skips
separately.

Safety: connects only to ``GRAQLE_TEST_NEO4J_CE_URI`` (default
``bolt://127.0.0.1:17687``), refuses port 7687 (the shared DBMS) outright and
refuses any server whose edition is not ``community``. It deletes only the
``:ProvenanceEvent`` and ``:TrajectoryHead`` nodes it owns.
"""

from __future__ import annotations

import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import pytest

from graqle.assurance.provenance_event import GENESIS_HASH
from graqle.assurance.sequencer import (
    Neo4jTrajectorySequencer,
    SequenceConflictError,
    append_with_retry,
    ensure_provenance_schema,
)

pytestmark = pytest.mark.integration

CE_URI = os.environ.get(
    "GRAQLE_TEST_NEO4J_CE_URI", os.environ.get("NEO4J_URI", "bolt://127.0.0.1:17687")
)
CE_PASSWORD = os.environ.get("NEO4J_PASSWORD", "unused")
SHARED_PORT = 7687
TID = "trj_01J7Q0E9M3W5X7Y9Z1A3B5C7D9"
OTHER_TID = "trj_01J7Q0E9M3W5X7Y9Z1A3B5C7DA"
WORKERS = 64
TEST_BUDGET = 5000


def _h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@pytest.fixture
def driver() -> Any:
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
    with drv.session(database="neo4j") as s:
        s.run("MATCH (n) WHERE n:TrajectoryHead OR n:ProvenanceEvent DETACH DELETE n").consume()
    ensure_provenance_schema(drv, "neo4j")
    yield drv
    with drv.session(database="neo4j") as s:
        s.run("MATCH (n) WHERE n:TrajectoryHead OR n:ProvenanceEvent DETACH DELETE n").consume()
    drv.close()


@pytest.fixture
def seq(driver: Any) -> Neo4jTrajectorySequencer:
    return Neo4jTrajectorySequencer(driver, "neo4j")


def _raw(driver: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    with driver.session(database="neo4j") as s:
        return [dict(r) for r in s.run(query, **params)]


def _assert_chain(results: list[tuple[int, str, str]], count: int) -> None:
    by_seq = sorted(results)
    assert [r[0] for r in by_seq] == list(range(count))
    assert by_seq[0][2] == GENESIS_HASH
    for prev, cur in zip(by_seq, by_seq[1:]):
        assert cur[2] == prev[1]
    assert len({r[2] for r in results}) == count


def test_schema_helper_is_idempotent_and_creates_the_constraints(driver: Any) -> None:
    ensure_provenance_schema(driver, "neo4j")
    names = {r["name"] for r in _raw(driver, "SHOW CONSTRAINTS YIELD name")}
    assert {"prov_event_id", "prov_traj_seq", "traj_head_id"} <= names


def test_genesis_and_walk(seq: Neo4jTrajectorySequencer) -> None:
    assert seq.head(TID) == (-1, GENESIS_HASH)
    seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
    seq.advance(TID, 0, _h("0"), 1, _h("1"))
    assert seq.head(TID) == (1, _h("1"))
    assert seq.head(OTHER_TID) == (-1, GENESIS_HASH)


def test_skip_is_refused_before_any_write(driver: Any, seq: Neo4jTrajectorySequencer) -> None:
    with pytest.raises(SequenceConflictError) as exc:
        seq.advance(TID, -1, GENESIS_HASH, 1, _h("1"))
    assert exc.value.reason == "skip"
    assert _raw(driver, "MATCH (h:TrajectoryHead) RETURN h") == []


def test_second_genesis_loses_the_race(seq: Neo4jTrajectorySequencer) -> None:
    seq.advance(TID, -1, GENESIS_HASH, 0, _h("a"))
    with pytest.raises(SequenceConflictError) as exc:
        seq.advance(TID, -1, GENESIS_HASH, 0, _h("b"))
    assert exc.value.reason == "genesis-race"
    assert seq.head(TID) == (0, _h("a"))


def test_fork_on_a_used_previous_hash_is_refused(seq: Neo4jTrajectorySequencer) -> None:
    """AC-20 (Inv-C3)."""
    seq.advance(TID, -1, GENESIS_HASH, 0, _h("e0"))
    seq.advance(TID, 0, _h("e0"), 1, _h("e1"))
    with pytest.raises(SequenceConflictError) as exc:
        seq.advance(TID, 0, _h("e0"), 1, _h("fork"))
    assert exc.value.reason == "cas-lost"
    with pytest.raises(SequenceConflictError):
        seq.advance(TID, 1, _h("wrong-head"), 2, _h("e2"))
    assert seq.head(TID) == (1, _h("e1"))


def test_unique_trajectory_sequence_constraint_is_the_store_backstop(driver: Any) -> None:
    q = (
        "CREATE (:ProvenanceEvent {event_id:$e, trajectory_id:$t, sequence_number:0})"
    )
    with driver.session(database="neo4j") as s:
        s.run(q, e="evt_A", t=TID).consume()
        with pytest.raises(Exception, match="already exists|Constraint"):
            s.run(q, e="evt_B", t=TID).consume()


def test_64_concurrent_recorders_one_chain(seq: Neo4jTrajectorySequencer) -> None:
    """AC-4, Neo4j backend."""
    barrier = threading.Barrier(WORKERS)

    def run(n: int) -> tuple[int, str, str]:
        barrier.wait()
        return append_with_retry(
            seq, TID, lambda s, p: _h(f"{TID}|{s}|{p}|{n}"), TEST_BUDGET
        )

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(run, range(WORKERS)))
    _assert_chain(results, WORKERS)
    assert seq.head(TID) == (WORKERS - 1, max(results)[1])
