"""CR-016 PR-016b live proofs against a SCRATCH Neo4j Community Edition server.

The ten failing-case tests from the Research ruling (2026-09-28), the positive
paths, key rotation, and AC-6/7/8. CI does NOT run these: there is no Neo4j
there, so they SKIP. A skip is not a pass; run them locally against a scratch
Community Edition server and report pass and skip counts separately.

Safety: this module WIPES the database it connects to. It therefore
* connects only to ``GRAQLE_TEST_NEO4J_CE_URI`` (default ``bolt://127.0.0.1:17687``),
* refuses port 7687 (the shared Desktop DBMS) outright, and
* refuses any server whose edition is not ``community`` before touching data.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from graqle.connectors.neo4j import Neo4jConnector
from graqle.governance.tamper_evidence.kg_persist import AssuranceWriteRefusedError, Neo4jBatchPersister
from graqle.ontology.assurance import AssuranceClass, EdgeKind
from graqle.ontology.assurance_config import AssuranceOntologyConfig
from graqle.ontology.assurance_integrity import (
    IntegrityKeyring,
    key_rotation_ops,
    verify_assurance_integrity,
)
from graqle.ontology.assurance_migration import (
    apply_migration,
    plan_migration,
    rollback_migration,
    verify_migration,
)

sys.path.insert(0, str(Path(__file__).parent))
from _assurance_write_fixtures import KEYRING, SALT, SALT_NEXT, claim_op, edge_op  # noqa: E402

pytestmark = pytest.mark.integration

CE_URI = os.environ.get("GRAQLE_TEST_NEO4J_CE_URI", "bolt://127.0.0.1:17687")
SHARED_PORT = 7687

T1 = ("2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z")
T2 = ("2026-09-02T00:00:00Z", "2026-09-02T00:00:00Z")
T3 = ("2026-09-03T00:00:00Z", "2026-09-03T00:00:00Z")
T4 = ("2026-09-04T00:00:00Z", "2026-09-04T00:00:00Z")


def _scratch_or_skip() -> Neo4jConnector:
    port = urlparse(CE_URI).port
    if port == SHARED_PORT:
        pytest.fail(
            f"refusing {CE_URI}: port {SHARED_PORT} is the shared DBMS; use a scratch server"
        )
    try:
        from neo4j import GraphDatabase
    except ImportError:
        pytest.skip("neo4j driver not installed")
    driver = GraphDatabase.driver(CE_URI, auth=("neo4j", "unused"))
    try:
        driver.verify_connectivity()
        with driver.session(database="system") as s:
            editions = {
                str(r["edition"]).lower()
                for r in s.run("CALL dbms.components() YIELD edition RETURN edition")
            }
    except Exception as exc:  # noqa: BLE001
        driver.close()
        pytest.skip(f"no scratch Neo4j at {CE_URI} ({type(exc).__name__})")
    # Some components report an empty edition; every NON-empty one must be community.
    editions.discard("")
    edition = ",".join(sorted(editions)) or "<none>"
    if editions != {"community"}:
        driver.close()
        pytest.skip(f"{CE_URI} is {edition}, not a scratch Community Edition server; not wiping it")
    conn = Neo4jConnector(uri=CE_URI, username="neo4j", password="unused", database="neo4j")
    conn._driver = driver
    return conn


@pytest.fixture
def ce() -> Any:
    conn = _scratch_or_skip()
    driver = conn._get_driver()
    with driver.session(database="neo4j") as s:
        s.run("MATCH (n) DETACH DELETE n")
    conn.create_assurance_schema()
    yield conn
    driver.close()


@pytest.fixture
def persister(ce: Neo4jConnector) -> Neo4jBatchPersister:
    return Neo4jBatchPersister(ce, ensure_schema=False, integrity_keyring=KEYRING)


def _raw(conn: Neo4jConnector, query: str, **params: Any) -> list[dict[str, Any]]:
    """A raw driver write: what a writer OUTSIDE the SDK path can do on CE."""
    with conn._get_driver().session(database="neo4j") as s:
        return [dict(r) for r in s.run(query, **params)]


def _chain(persister: Neo4jBatchPersister) -> None:
    """v3 SUPERSEDES v2 SUPERSEDES v1, same canonical identity."""
    persister.persist_assurance_ops(
        [
            claim_op("v1", "cid-x", *T1),
            claim_op("v2", "cid-x", *T2),
            claim_op("v3", "cid-x", *T3),
            edge_op("v2", "v1", EdgeKind.SUPERSEDES),
            edge_op("v3", "v2", EdgeKind.SUPERSEDES),
        ]
    )


# ── positive paths ───────────────────────────────────────────────────────────


def test_chain_writes_and_verifies_clean(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    _chain(persister)
    rep = verify_assurance_integrity(ce, KEYRING)
    assert rep.ok, rep.findings
    assert rep.nodes_checked == 3 and rep.edges_checked == 2
    rows = _raw(
        ce,
        "MATCH (a)-[r:RELATES_TO {kind:'SUPERSEDES'}]->(b) RETURN a.id AS a, b.id AS b, "
        "r.supersedes_in AS i, r.supersedes_out AS o",
    )
    assert all(r["i"] == r["b"] and r["o"] == r["a"] for r in rows)  # set inside the CREATE


def test_re_persisting_the_same_ops_is_a_no_op(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    _chain(persister)
    before = _raw(ce, "MATCH (n) RETURN n.id AS id, properties(n) AS p ORDER BY id")
    _chain(persister)
    assert _raw(ce, "MATCH (n) RETURN n.id AS id, properties(n) AS p ORDER BY id") == before
    assert _raw(ce, "MATCH ()-[r]->() RETURN count(r) AS c")[0]["c"] == 2


# ── the ten failing cases (Research ruling 2026-09-28 §2.4) ──────────────────


def test_01_duplicate_version_is_rejected_by_the_db(persister: Neo4jBatchPersister) -> None:
    persister.persist_assurance_ops([claim_op("a", "cid-x", *T1)])
    with pytest.raises(AssuranceWriteRefusedError, match="constraint"):
        persister.persist_assurance_ops(
            [claim_op("b", "cid-x", *T1)]
        )  # same (cid, scope, valid_from)


def test_02_fan_in_supersedes_is_rejected(persister: Neo4jBatchPersister) -> None:
    persister.persist_assurance_ops(
        [
            claim_op("old", "cid-o", *T1),
            claim_op("n1", "cid-1", *T2),
            claim_op("n2", "cid-2", *T3),
            edge_op("n1", "old", EdgeKind.SUPERSEDES),
        ]
    )
    with pytest.raises(AssuranceWriteRefusedError, match="constraint"):
        persister.persist_assurance_ops([edge_op("n2", "old", EdgeKind.SUPERSEDES)])


def test_03_fan_out_supersedes_is_rejected(persister: Neo4jBatchPersister) -> None:
    persister.persist_assurance_ops(
        [
            claim_op("o1", "cid-1", *T1),
            claim_op("o2", "cid-2", *T2),
            claim_op("new", "cid-n", *T3),
            edge_op("new", "o1", EdgeKind.SUPERSEDES),
        ]
    )
    with pytest.raises(AssuranceWriteRefusedError, match="constraint"):
        persister.persist_assurance_ops([edge_op("new", "o2", EdgeKind.SUPERSEDES)])


def test_04_corrects_fork_is_rejected_in_both_directions(persister: Neo4jBatchPersister) -> None:
    persister.persist_assurance_ops(
        [
            claim_op("b", "cid-b", *T1),
            claim_op("c", "cid-c", *T2),
            claim_op("a", "cid-a", *T3),
            claim_op("d", "cid-d", *T4),
            edge_op("a", "b", EdgeKind.CORRECTS),
        ]
    )
    with pytest.raises(AssuranceWriteRefusedError, match="constraint"):
        persister.persist_assurance_ops([edge_op("a", "c", EdgeKind.CORRECTS)])  # a second OUT
    with pytest.raises(AssuranceWriteRefusedError, match="constraint"):
        persister.persist_assurance_ops([edge_op("d", "b", EdgeKind.CORRECTS)])  # a second IN


def test_05_two_node_cycle_is_rejected_by_rule_d(persister: Neo4jBatchPersister) -> None:
    persister.persist_assurance_ops(
        [
            claim_op("a", "cid-a", *T2),
            claim_op("b", "cid-b", *T1),
            edge_op("a", "b", EdgeKind.SUPERSEDES),
        ]
    )
    with pytest.raises(AssuranceWriteRefusedError, match="rule d"):
        persister.persist_assurance_ops([edge_op("b", "a", EdgeKind.SUPERSEDES)])


def test_06_mixed_kind_cycle_is_rejected_by_rule_d(persister: Neo4jBatchPersister) -> None:
    persister.persist_assurance_ops(
        [
            claim_op("a", "cid-a", *T2),
            claim_op("b", "cid-b", *T1),
            edge_op("a", "b", EdgeKind.SUPERSEDES),
        ]
    )
    with pytest.raises(AssuranceWriteRefusedError, match="rule d"):
        persister.persist_assurance_ops([edge_op("b", "a", EdgeKind.CORRECTS)])


def test_07_missing_canonical_id_is_rejected(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    persister.persist_assurance_ops([claim_op("a", None, *T2), claim_op("b", "cid-b", *T1)])
    with pytest.raises(AssuranceWriteRefusedError, match="rule c"):
        persister.persist_assurance_ops([edge_op("a", "b", EdgeKind.SUPERSEDES)])
    assert _raw(ce, "MATCH ()-[r]->() RETURN count(r) AS c")[0]["c"] == 0


def test_08_concurrent_race_commits_exactly_one(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    writers = 8
    persister.persist_assurance_ops(
        [claim_op("old", "cid-o", *T1)]
        + [
            claim_op(f"n{i}", f"cid-{i}", f"2026-09-02T00:00:0{i}Z", f"2026-09-02T00:00:0{i}Z")
            for i in range(writers)
        ]
    )
    barrier = threading.Barrier(writers)
    outcomes: list[str] = []
    lock = threading.Lock()

    def race(i: int) -> None:
        # Own connector and driver per thread: eight separate connections.
        conn = Neo4jConnector(uri=CE_URI, username="neo4j", password="unused", database="neo4j")
        p = Neo4jBatchPersister(conn, ensure_schema=False, integrity_keyring=KEYRING)
        conn._get_driver().verify_connectivity()
        barrier.wait()
        try:
            p.persist_assurance_ops([edge_op(f"n{i}", "old", EdgeKind.SUPERSEDES)])
            result = "committed"
        except AssuranceWriteRefusedError:
            result = "refused"
        finally:
            conn.close()
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=race, args=(i,)) for i in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["committed"] + ["refused"] * (writers - 1)
    assert (
        _raw(ce, "MATCH ()-[r:RELATES_TO {kind:'SUPERSEDES'}]->() RETURN count(r) AS c")[0]["c"]
        == 1
    )


def test_09a_sdk_refuses_to_change_a_write_once_field(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    persister.persist_assurance_ops([claim_op("a", "cid-a", *T1)])
    with pytest.raises(AssuranceWriteRefusedError, match="valid_from"):
        persister.persist_assurance_ops([claim_op("a", "cid-a", T2[0], T1[1])])
    with pytest.raises(AssuranceWriteRefusedError, match="asserted_at"):
        persister.persist_assurance_ops([claim_op("a", "cid-a", T1[0], T2[1])])
    assert _raw(ce, "MATCH (n {id:'a'}) RETURN n.valid_from AS v")[0]["v"] == T1[0]


def test_09b_raw_set_is_not_refused_on_ce_but_is_detected(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    _chain(persister)
    # A REAL raw update: Community Edition has no RBAC, so nothing refuses it.
    _raw(ce, "MATCH (n:CogniNode {id: 'v1'}) SET n.valid_from = $v", v="2026-08-01T00:00:00Z")
    assert (
        _raw(ce, "MATCH (n {id:'v1'}) RETURN n.valid_from AS v")[0]["v"] == "2026-08-01T00:00:00Z"
    )
    rep = verify_assurance_integrity(ce, KEYRING)
    assert not rep.ok
    assert "NODE_DIGEST_MISMATCH" in rep.codes()


def test_10_edge_delete_and_recreate_is_detected(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    _chain(persister)
    persister.persist_assurance_ops(
        [claim_op("other", "cid-z", "2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z")]
    )
    # Neo4j cannot repoint an edge: a raw writer deletes it and recreates it
    # between different endpoints, copying every property and setting the
    # cardinality properties CORRECTLY for the new endpoints.
    _raw(
        ce,
        "MATCH (a {id:'v2'})-[r:RELATES_TO {kind:'SUPERSEDES'}]->(b {id:'v1'}) "
        "MATCH (c {id:'other'}) "
        "WITH a, r, c, properties(r) AS p DELETE r "
        "CREATE (a)-[n:RELATES_TO]->(c) SET n = p, n.supersedes_in = c.id",
    )
    rep = verify_assurance_integrity(ce, KEYRING)
    assert not rep.ok
    assert "EDGE_DIGEST_MISMATCH" in rep.codes()


# ── verifier catches the other raw corruptions ───────────────────────────────


def test_raw_cycle_is_detected_as_an_ordering_violation(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    persister.persist_assurance_ops(
        [
            claim_op("a", "cid-a", *T2),
            claim_op("b", "cid-b", *T1),
            edge_op("a", "b", EdgeKind.SUPERSEDES),
        ]
    )
    _raw(
        ce,
        "MATCH (a {id:'a'}), (b {id:'b'}) "
        "CREATE (b)-[:RELATES_TO {kind:'CORRECTS', corrects_in:'a', "
        "corrects_out:'b', scope_key:'x', asserted_at:'2026-09-30T00:00:00Z'}]->(a)",
    )
    rep = verify_assurance_integrity(ce, KEYRING)
    assert {"ORDERING_VIOLATION", "EDGE_DIGEST_MISSING"} <= rep.codes()


# ── key rotation ─────────────────────────────────────────────────────────────


def test_key_rotation_resigns_in_one_batch_and_old_digests_are_not_tampering(
    ce: Neo4jConnector,
) -> None:
    Neo4jBatchPersister(ce, ensure_schema=False, integrity_keyring=KEYRING).persist_assurance_ops(
        [
            claim_op("v1", "cid-x", *T1),
            claim_op("v2", "cid-x", *T2),
            edge_op("v2", "v1", EdgeKind.SUPERSEDES),
        ]
    )
    only_new = IntegrityKeyring.from_salts(("v2", SALT_NEXT))
    stale = verify_assurance_integrity(ce, only_new)
    assert "UNKNOWN_HMAC_VERSION" in stale.codes()
    assert (
        not {"NODE_DIGEST_MISMATCH", "EDGE_DIGEST_MISMATCH"} & stale.codes()
    )  # rotation != tampering

    overlap = IntegrityKeyring.from_salts(("v2", SALT_NEXT), ("v1", SALT))
    ops = key_rotation_ops(ce, overlap, now="2026-09-30T00:00:00Z")
    Neo4jBatchPersister(ce, ensure_schema=False, integrity_keyring=overlap).persist_assurance_ops(
        ops
    )
    assert _raw(ce, "MATCH (n {event_type:'KEY_ROTATION'}) RETURN count(n) AS c")[0]["c"] == 1
    assert verify_assurance_integrity(ce, only_new).ok


def test_key_rotation_refuses_to_launder_a_tampered_node(ce: Neo4jConnector) -> None:
    Neo4jBatchPersister(ce, ensure_schema=False, integrity_keyring=KEYRING).persist_assurance_ops(
        [claim_op("v1", "cid-x", *T1)]
    )
    _raw(ce, "MATCH (n {id:'v1'}) SET n.asserted_at = '2026-01-01T00:00:00Z'")
    overlap = IntegrityKeyring.from_salts(("v2", SALT_NEXT), ("v1", SALT))
    ops = key_rotation_ops(ce, overlap, now="2026-09-30T00:00:00Z")
    with pytest.raises(AssuranceWriteRefusedError, match="MISMATCH"):
        Neo4jBatchPersister(
            ce, ensure_schema=False, integrity_keyring=overlap
        ).persist_assurance_ops(ops)
    # one transaction: nothing was re-signed and no rotation event exists
    assert _raw(ce, "MATCH (n {id:'v1'}) RETURN n.integrity_hmac_version AS v")[0]["v"] == "v1"
    assert _raw(ce, "MATCH (n {event_type:'KEY_ROTATION'}) RETURN count(n) AS c")[0]["c"] == 0


# ── AC-8: save() round trip ──────────────────────────────────────────────────


def test_ac8_save_round_trips_a_kind_edge_and_leaves_plain_edges_alone(ce: Neo4jConnector) -> None:
    nodes = {
        "x": {"label": "x", "type": "T", "description": ""},
        "y": {"label": "y", "type": "T", "description": ""},
    }
    props = {
        "kind": "SUPPORTED_BY",
        "strength": 0.8,
        "scope_key": "s",
        "asserted_at": "2026-09-30T00:00:00Z",
        "prov_event_id": "pev",
    }
    ce.save(
        nodes,
        {
            "k": {"source": "x", "target": "y", "relationship": "RELATES_TO", "properties": props},
            "p": {"source": "y", "target": "x", "relationship": "IMPORTS", "weight": 1.0},
        },
    )
    _, edges = ce.load()
    assert {k: edges["k"]["properties"][k] for k in props} == props
    from graqle.connectors.neo4j import _ASSURANCE_EDGE_PROPS

    assert not set(edges["p"]["properties"]) & set(_ASSURANCE_EDGE_PROPS)


# ── AC-6 / AC-7: migration ───────────────────────────────────────────────────


class _Rules:
    def __init__(self, ids: list[str]) -> None:
        self.ids = ids

    def assign(self, connector: Any) -> dict[str, AssuranceClass]:
        return {i: AssuranceClass.EVIDENCE for i in self.ids}


def _seed_substrate(conn: Neo4jConnector, n: int) -> None:
    _raw(
        conn,
        "UNWIND range(0, $n - 1) AS i "
        "CREATE (:CogniNode {id: 'sub' + i, label: 'sub' + i, entity_type: 'T', "
        "valid_from: CASE WHEN i = 1 THEN '2020-01-01T00:00:00Z' ELSE null END})",
        n=n,
    )
    _raw(
        conn,
        "UNWIND range(0, $n - 2) AS i MATCH (a {id: 'sub' + i}), (b {id: 'sub' + (i + 1)}) "
        "CREATE (a)-[:RELATES_TO {id: 'r' + i}]->(b)",
        n=n,
    )
    _raw(conn, "MATCH (a {id: 'sub0'}) CREATE (a)-[:HAS_CHUNK]->(:Chunk {id: 'ch0', text: 't'})")


def _snapshot(conn: Neo4jConnector) -> tuple[Any, Any]:
    nodes = _raw(
        conn, "MATCH (n) RETURN n.id AS id, labels(n) AS l, properties(n) AS p ORDER BY id"
    )
    rels = _raw(
        conn,
        "MATCH (a)-[r]->(b) RETURN a.id AS a, type(r) AS t, b.id AS b, properties(r) AS p "
        "ORDER BY a, t, b",
    )
    return nodes, rels


_CFG = AssuranceOntologyConfig(
    secondary_labels_enabled=True,
    label_safe_node_ceiling=100_000,
    migration_batch_size=97,
    scope_key_fields=("f_alpha",),
)


def test_ac6_ac7_migration_plan_apply_reapply_rollback(
    ce: Neo4jConnector, persister: Neo4jBatchPersister
) -> None:
    import time

    n = 6449  # the research-DB node count named by AC-6, as SYNTHETIC substrate on scratch CE
    _seed_substrate(ce, n)
    before = _snapshot(ce)
    assigned = [f"sub{i}" for i in range(0, n, 13)]  # includes sub1, which already has a valid_from
    plan = plan_migration(ce, _CFG, _Rules(assigned))
    assert len(plan.plan_hash) == 64 and plan.total_nodes == n and plan.labels_enabled

    dry = apply_migration(persister, plan)  # dry run by default
    assert not dry.applied and _snapshot(ce) == before

    t0 = time.perf_counter()
    rep = apply_migration(persister, plan, dry_run=False)
    elapsed = time.perf_counter() - t0
    print(
        f"\nAC-15 migration timing: {n} nodes, {len(assigned)} assigned, "
        f"{rep.ops} ops, {elapsed:.2f}s"
    )
    assert rep.applied and rep.verified and verify_migration(ce, plan)
    assert rep.labels_applied == len(assigned) + 1  # + the MIGRATION event itself
    assert verify_assurance_integrity(ce, KEYRING).ok

    after_once = _snapshot(ce)
    again = apply_migration(persister, plan, dry_run=False)  # AC-6: idempotent
    assert again.applied and _snapshot(ce) == after_once

    # sub1 kept the valid_from it had before the migration
    assert (
        _raw(ce, "MATCH (n {id:'sub1'}) RETURN n.valid_from AS v")[0]["v"] == "2020-01-01T00:00:00Z"
    )

    out = rollback_migration(persister)  # AC-7
    assert out["events"] == 1 and out["nodes"] == len(assigned)
    assert _snapshot(ce) == before  # every node, label, property and edge, HAS_CHUNK included
