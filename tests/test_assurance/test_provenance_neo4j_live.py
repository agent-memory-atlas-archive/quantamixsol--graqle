"""CR-018 PR-018b live proof (ALWAYS-3): recorder + Neo4j sequencer/store/escrow on a scratch CE.

Runs only when ``GRAQLE_TEST_NEO4J_CE_URI`` is set (plus ``NEO4J_PASSWORD``); the
shared DBMS on port 7687 is refused outright. Every node the test creates is
removed again by its own unique ids.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from graqle.assurance._ids import new_id, rfc3339
from graqle.assurance.provenance_event import (
    Activity,
    Actor,
    ActorType,
    Assessment,
    EventType,
    IdentityAssurance,
    Inputs,
)
from graqle.assurance.provenance_recorder import ProvenanceRecorder
from graqle.assurance.provenance_settings import ProvenanceSettings
from graqle.assurance.provenance_store import Neo4jProvenanceStore, ProvenanceStoreError
from graqle.assurance.salt_escrow import Neo4jSaltEscrow, SaltEscrowError
from graqle.assurance.sequencer import Neo4jTrajectorySequencer, ensure_provenance_schema
from graqle.assurance.signing import DagSigner
from graqle.governance.custody.ed25519_key_manifest import Ed25519KeyManifest

URI = os.environ.get("GRAQLE_TEST_NEO4J_CE_URI", "")
pytestmark = pytest.mark.skipif(not URI, reason="GRAQLE_TEST_NEO4J_CE_URI not set (scratch CE only)")

KID = "kid-live"


@pytest.fixture
def driver():
    assert ":7687" not in URI, "refusing to run against the shared DBMS"
    from neo4j import GraphDatabase

    drv = GraphDatabase.driver(URI, auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
    ensure_provenance_schema(drv)
    yield drv
    drv.close()


@pytest.fixture
def rig(driver, tmp_path):
    now = datetime.now(timezone.utc)
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "k.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pem.chmod(0o600)
    manifest = Ed25519KeyManifest()
    manifest.register(KID, key.public_key(), now - timedelta(days=1), now + timedelta(days=30))
    cfg = ProvenanceSettings(
        signing_key_id=KID,
        signing_key_version=1,
        signing_key_path=str(pem),
        coverage_policy_path="cp.yaml",
        sequencer="neo4j",
        salt_escrow="neo4j",
    )
    rec = ProvenanceRecorder(
        cfg,
        DagSigner(cfg, manifest),
        Neo4jTrajectorySequencer(driver),
        Neo4jSaltEscrow(driver),
        Neo4jProvenanceStore(driver),
    )
    traj = new_id("trj")
    created: list[str] = []
    yield rec, traj, created
    with driver.session() as session:
        session.run("MATCH (e:ProvenanceEvent {trajectory_id:$t}) DETACH DELETE e", t=traj).consume()
        session.run("MATCH (h:TrajectoryHead {trajectory_id:$t}) DELETE h", t=traj).consume()
        session.run("MATCH (s:ProvenanceSalt) WHERE s.event_id IN $ids DELETE s", ids=created).consume()


def _record(rec: ProvenanceRecorder, traj: str, created: list[str]):
    evt = rec.record(
        event_type=EventType.DECISION_GATE_EVALUATED,
        actor=Actor(
            agent_id="agent-live",
            type=ActorType.SOFTWARE_AGENT,
            identity_assurance=IdentityAssurance.IAL2,
            kid=KID,
        ),
        activity=Activity(
            decision_id=new_id("dec"),
            trajectory_id=traj,
            checkpoint=0,
            model_version="m",
            rule_set_version="r",
            policy_bundle_version="p",
            config_version="c",
        ),
        inputs=Inputs(evidence_refs=["e1"]),
        assessment=Assessment(outcome="HOLD"),
        occurred_at=rfc3339(datetime.now(timezone.utc)),
    )
    created.append(evt.event_id)
    return evt


def test_chain_is_stored_linked_and_escrowed(driver, rig):
    rec, traj, created = rig
    first, second = _record(rec, traj, created), _record(rec, traj, created)
    assert second.ordering.previous_event_hash == first.integrity.canonical_hash
    with driver.session() as session:
        linked = session.run(
            "MATCH (b:ProvenanceEvent {event_id:$b})-[:PRECEDED_BY]->(a:ProvenanceEvent {event_id:$a}) "
            "RETURN count(*) AS n",
            a=first.event_id,
            b=second.event_id,
        ).single()["n"]
        assert linked == 1
        stored = session.run(
            "MATCH (e:ProvenanceEvent {trajectory_id:$t}) RETURN count(e) AS n", t=traj
        ).single()["n"]
        assert stored == 2
        salts = session.run(
            "MATCH (s:ProvenanceSalt {event_id:$id}) RETURN count(s) AS n", id=first.event_id
        ).single()["n"]
        assert salts > 0


def test_duplicate_slot_fails_closed_on_the_uniqueness_constraint(driver, rig):
    rec, traj, created = rig
    evt = _record(rec, traj, created)
    committed = {
        "event_id": new_id("evt"),
        "event_type": evt.event_type.value,
        "schema_version": evt.schema_version,
        "activity": {"trajectory_id": traj, "checkpoint": 0},
        "ordering": {
            "sequence_number": evt.ordering.sequence_number,  # slot already occupied
            "previous_event_hash": evt.ordering.previous_event_hash,
        },
        "integrity": {
            "canonical_hash": "x" * 64,
            "signature": {"kid": KID, "key_version": 1, "signed_at": rfc3339(datetime.now(timezone.utc))},
        },
    }
    with pytest.raises(ProvenanceStoreError):
        Neo4jProvenanceStore(driver).persist(committed)
    with driver.session() as session:
        n = session.run(
            "MATCH (e:ProvenanceEvent {trajectory_id:$t, sequence_number:$s}) RETURN count(e) AS n",
            t=traj,
            s=evt.ordering.sequence_number,
        ).single()["n"]
    assert n == 1


def test_duplicate_escrow_is_refused(driver, rig):
    rec, traj, created = rig
    evt = _record(rec, traj, created)
    with pytest.raises(SaltEscrowError):
        Neo4jSaltEscrow(driver).put(evt.event_id, {"actor.agent_id": b"\x00" * 32})
