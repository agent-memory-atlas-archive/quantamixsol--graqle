"""CR-018 PR-018b: recorder, signer, rotation, settings, store (AC-1/2/5/6/7/18, AC-14 part)."""

from __future__ import annotations

import ast
import json
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from graqle.assurance import provenance_recorder as pr
from graqle.assurance._ids import NS_DAG, new_id, rfc3339
from graqle.assurance.provenance_event import (
    Activity,
    Actor,
    ActorType,
    Assessment,
    EventType,
    IdentityAssurance,
    Inputs,
    canonical_hash,
)
from graqle.assurance.provenance_settings import ProvenanceSettings, load_provenance_settings
from graqle.assurance.provenance_store import (
    FileProvenanceStore,
    Neo4jProvenanceStore,
    ProvenanceStoreError,
)
from graqle.assurance.salt_escrow import FileSaltEscrow, Neo4jSaltEscrow, SaltEscrowError
from graqle.assurance.sequencer import FileLockTrajectorySequencer
from graqle.assurance.signing import DagSigner, RotationPlan, retire_due, rotate
from graqle.config.exceptions import ConfigurationError
from graqle.governance.custody.ed25519_key_manifest import Ed25519KeyManifest, KeyState
from graqle.governance.tamper_evidence.canonicalize import canon
from graqle.governance.tamper_evidence.leaf_input_schema import LEAF_HASH_FIELDS, LEAF_INPUT_VERSION

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
KID = "kid-a"


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _pem(tmp: Path, key: Ed25519PrivateKey, mode: int = 0o600) -> Path:
    p = tmp / "k.pem"
    p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    p.chmod(mode)
    return p


def _cfg(path: Path | None, **over) -> ProvenanceSettings:
    base = dict(
        signing_key_id=KID,
        signing_key_version=1,
        signing_key_path=str(path) if path else None,
        coverage_policy_path="cp.yaml",
    )
    base.update(over)
    return ProvenanceSettings(**base)


class Rig:
    def __init__(self, tmp: Path, **cfg_over) -> None:
        self.clock = Clock()
        self.key = Ed25519PrivateKey.generate()
        self.manifest = Ed25519KeyManifest()
        self.manifest.register(
            KID, self.key.public_key(), T0 - timedelta(days=1), T0 + timedelta(days=60)
        )
        self.cfg = _cfg(_pem(tmp, self.key), **cfg_over)
        self.signer = DagSigner(self.cfg, self.manifest, self.clock)
        self.store = FileProvenanceStore(tmp / "events")
        self.escrow = FileSaltEscrow(tmp / "salts")
        self.rec = pr.ProvenanceRecorder(
            self.cfg,
            self.signer,
            FileLockTrajectorySequencer(tmp / "seq"),
            self.escrow,
            self.store,
            clock=self.clock,
        )

    def record(self, traj: str, **kw):
        return self.rec.record(
            event_type=EventType.DECISION_GATE_EVALUATED,
            actor=Actor(
                agent_id="agent-1",
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
            occurred_at=rfc3339(self.clock()),
            **kw,
        )


# ---- settings (AC-6) ---------------------------------------------------------

ENV = (
    "GRAQLE_DAG_SIGNING_KEY_ID",
    "GRAQLE_DAG_SIGNING_KEY_VERSION",
    "GRAQLE_DAG_SIGNING_KEY_PATH",
    "GRAQLE_DAG_COVERAGE_POLICY_PATH",
)


def _env(monkeypatch, skip: str | None = None, value: str = "x") -> None:
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "1")
    for name in ENV:
        if name != skip:
            monkeypatch.setenv(name, "1" if name.endswith("VERSION") else value)


def test_flag_off_returns_none_even_with_nothing_set(monkeypatch):
    for name in (*ENV, "GRAQLE_DAG_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    assert load_provenance_settings() is None


@pytest.mark.parametrize("missing", ENV)
def test_flag_on_missing_required_raises_naming_the_setting(monkeypatch, missing):
    _env(monkeypatch, skip=missing)
    with pytest.raises(ConfigurationError) as exc:
        load_provenance_settings()
    assert missing in str(exc.value)


@pytest.mark.parametrize("blank", ["", "   "])
def test_flag_on_blank_value_is_missing(monkeypatch, blank):
    _env(monkeypatch, value=blank)
    with pytest.raises(ConfigurationError):
        load_provenance_settings()


def test_flag_on_all_set_loads(monkeypatch):
    _env(monkeypatch)
    cfg = load_provenance_settings()
    assert cfg is not None and cfg.signing_key_id == "x" and cfg.signing_key_version == 1


def test_max_age_must_exceed_overlap(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("GRAQLE_DAG_KEY_MAX_AGE_DAYS", "5")
    monkeypatch.setenv("GRAQLE_DAG_KEY_OVERLAP_DAYS", "5")
    with pytest.raises(ConfigurationError):
        load_provenance_settings()


def test_zero_retry_budget_rejected(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setenv("GRAQLE_DAG_SEQ_RETRY_BUDGET", "0")
    with pytest.raises(ConfigurationError):
        load_provenance_settings()


def test_yaml_sourced_key_path_is_not_a_settings_source(tmp_path, monkeypatch):
    """The key path comes only from the environment: a yaml file in cwd is ignored."""
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "graqle.yaml").write_text("signing_key_path: /tmp/evil.pem\n")
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "1")
    with pytest.raises(ConfigurationError):
        load_provenance_settings()


def test_unknown_algo_rejected():
    with pytest.raises(ValueError):
        _cfg(None, args_hash_algo="md5")


# ---- signer (AC-5, AC-6) -------------------------------------------------------


def test_signature_verifies_and_retired_kid_still_verifies(tmp_path):
    rig = Rig(tmp_path)
    evt = rig.record("trj_" + "A" * 26)
    sig = evt.integrity.signature
    msg = canon(
        {
            "schema_version": evt.schema_version,
            "canonical_hash": evt.integrity.canonical_hash,
            "previous_event_hash": evt.ordering.previous_event_hash,
            "sequence_number": evt.ordering.sequence_number,
            "kid": sig.kid,
            "signed_at": sig.signed_at,
        }
    )
    at = datetime.fromisoformat(sig.signed_at[:-1] + "+00:00")
    assert rig.manifest.verify(sig.kid, msg, bytes.fromhex(sig.sig), at=at)
    rig.manifest.retire(KID)
    assert rig.manifest.verify(sig.kid, msg, bytes.fromhex(sig.sig), at=at)


def test_revoked_kid_does_not_verify(tmp_path):
    rig = Rig(tmp_path)
    evt = rig.record("trj_" + "B" * 26)
    sig = evt.integrity.signature
    msg = canon(
        {
            "schema_version": evt.schema_version,
            "canonical_hash": evt.integrity.canonical_hash,
            "previous_event_hash": evt.ordering.previous_event_hash,
            "sequence_number": evt.ordering.sequence_number,
            "kid": sig.kid,
            "signed_at": sig.signed_at,
        }
    )
    at = datetime.fromisoformat(sig.signed_at[:-1] + "+00:00")
    # The signature is genuine for this exact message; only revocation can fail it.
    assert rig.manifest.verify(sig.kid, msg, bytes.fromhex(sig.sig), at=at)
    rig.manifest.revoke(KID)
    assert not rig.manifest.verify(sig.kid, msg, bytes.fromhex(sig.sig), at=at)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_group_readable_key_file_rejected(tmp_path):
    key = Ed25519PrivateKey.generate()
    m = Ed25519KeyManifest()
    m.register(KID, key.public_key(), T0 - timedelta(days=1), T0 + timedelta(days=9))
    with pytest.raises(ConfigurationError):
        DagSigner(_cfg(_pem(tmp_path, key, mode=0o640)), m, Clock())


def test_key_not_matching_manifest_rejected(tmp_path):
    m = Ed25519KeyManifest()
    m.register(KID, Ed25519PrivateKey.generate().public_key(), T0 - timedelta(days=1), T0 + timedelta(days=9))
    with pytest.raises(ConfigurationError):
        DagSigner(_cfg(_pem(tmp_path, Ed25519PrivateKey.generate())), m, Clock())


def test_unknown_kid_expired_key_and_overage_rejected(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = _pem(tmp_path, key)
    empty = Ed25519KeyManifest()
    with pytest.raises(ConfigurationError):
        DagSigner(_cfg(path), empty, Clock())
    old = Ed25519KeyManifest()
    old.register(KID, key.public_key(), T0 - timedelta(days=1), T0 + timedelta(days=9))
    with pytest.raises(ConfigurationError):
        DagSigner(_cfg(path), old, Clock(T0 + timedelta(days=30)))  # outside window
    wide = Ed25519KeyManifest()
    wide.register(KID, key.public_key(), T0 - timedelta(days=400), T0 + timedelta(days=9))
    with pytest.raises(ConfigurationError):
        DagSigner(_cfg(path), wide, Clock())  # older than key_max_age_days


def test_missing_key_path_rejected():
    with pytest.raises(ConfigurationError):
        DagSigner(_cfg(None), Ed25519KeyManifest(), Clock())


def test_garbage_key_file_rejected_without_leaking_content(tmp_path):
    p = tmp_path / "k.pem"
    p.write_text("not a key SECRETMARKER")
    p.chmod(0o600)
    m = Ed25519KeyManifest()
    with pytest.raises(ConfigurationError) as exc:
        DagSigner(_cfg(p), m, Clock())
    assert "SECRETMARKER" not in str(exc.value)


# ---- rotation (AC-7) ------------------------------------------------------------


def test_rotation_overlap_then_retire(tmp_path):
    rig = Rig(tmp_path)
    new_key = Ed25519PrivateKey.generate()
    plan = rotate(
        rig.cfg, rig.manifest, rig.rec, new_kid="kid-b", new_private_key=new_key, config_version="c",
        clock=rig.clock,
    )
    assert isinstance(plan, RotationPlan) and plan.kid == KID
    assert plan.retire_at == T0 + timedelta(days=rig.cfg.key_overlap_days)
    assert rig.manifest.get("kid-b").state is KeyState.ACTIVE
    # during overlap the old kid is ACTIVE and still signs
    assert retire_due(rig.manifest, [plan], rig.clock) == []
    assert rig.manifest.get(KID).state is KeyState.ACTIVE
    rig.record("trj_" + "C" * 26)
    # exactly at the end of the overlap it is RETIRED, not REVOKED
    rig.clock.now = plan.retire_at
    assert retire_due(rig.manifest, [plan], rig.clock) == [KID]
    assert rig.manifest.get(KID).state is KeyState.RETIRED
    assert retire_due(rig.manifest, [plan], rig.clock) == []


def test_key_rotated_event_signed_by_new_kid_on_system_trajectory(tmp_path):
    rig = Rig(tmp_path)
    rotate(
        rig.cfg, rig.manifest, rig.rec, new_kid="kid-b",
        new_private_key=Ed25519PrivateKey.generate(), config_version="c", clock=rig.clock,
    )
    stored = [json.loads(p.read_text()) for p in (tmp_path / "events").glob("evt_*.json") if "anchor" not in p.name]
    assert len(stored) == 1
    e = stored[0]
    assert e["event_type"] == "key_rotated"
    assert e["integrity"]["signature"]["kid"] == "kid-b"
    assert e["integrity"]["signature"]["key_version"] == rig.cfg.signing_key_version + 1
    assert e["activity"]["trajectory_id"] == "trj_" + "0" * 26


# ---- recorder -------------------------------------------------------------------


def test_chain_links_and_committed_form_hides_redactable_values(tmp_path):
    rig = Rig(tmp_path)
    traj = "trj_" + "D" * 26
    e0, e1 = rig.record(traj), rig.record(traj)
    assert (e0.ordering.sequence_number, e1.ordering.sequence_number) == (0, 1)
    assert e1.ordering.previous_event_hash == e0.integrity.canonical_hash
    stored = rig.store.load(e1.event_id)
    assert "agent-1" not in json.dumps(stored)
    assert set(stored["integrity"]["field_commitments"]) == {
        "actor.agent_id", "inputs.evidence_refs", "inputs.claim_refs", "inputs.instruction_refs",
    }
    # hash recomputed from the stored committed form + escrowed salts matches
    salts = rig.escrow.get(e1.event_id)
    again, _ = canonical_hash(e1.model_dump(mode="json"), salts)
    assert again == e1.integrity.canonical_hash
    assert oct(stat.S_IMODE(next((tmp_path / "salts").glob("evt_*.json")).stat().st_mode)) == "0o600"


def test_salts_are_escrowed_before_persist(tmp_path):
    rig = Rig(tmp_path)
    order: list[str] = []
    real_put, real_persist = rig.escrow.put, rig.store.persist
    rig.escrow.put = lambda *a: (order.append("escrow"), real_put(*a))[1]
    rig.store.persist = lambda *a: (order.append("persist"), real_persist(*a))[1]
    rig.record("trj_" + "E" * 26)
    assert order == ["escrow", "persist"]


def test_escrow_failure_is_a_hard_failure(tmp_path):
    rig = Rig(tmp_path)

    def boom(*a):
        raise SaltEscrowError("down")

    rig.escrow.put = boom
    with pytest.raises(pr.ProvenanceUnavailableError) as exc:
        rig.record("trj_" + "F" * 26)
    assert exc.value.reason_code == "DAG-PV-RECORD-FAILED"
    assert not list((tmp_path / "events").glob("evt_*.json")) if (tmp_path / "events").exists() else True


def test_sign_failure_fails_closed_without_event(tmp_path):
    rig = Rig(tmp_path)
    rig.manifest.retire(KID)  # signer can no longer sign
    with pytest.raises(pr.ProvenanceUnavailableError) as exc:
        rig.record("trj_" + "G" * 26)
    assert exc.value.reason_code == "DAG-PV-RECORD-FAILED"
    assert rig.rec.sequencer.head("trj_" + "G" * 26)[0] == -1  # head not advanced


def test_conflict_with_spent_budget_maps_to_seq_conflict(tmp_path):
    from graqle.assurance.sequencer import SequenceConflictError

    rig = Rig(tmp_path)

    class Racing:
        def head(self, t):
            return (-1, "0" * 64)

        def advance(self, t, *a):
            raise SequenceConflictError(t, -1, "cas-lost")

    rig.rec.sequencer = Racing()
    with pytest.raises(pr.ProvenanceUnavailableError) as exc:
        rig.record("trj_" + "H" * 26)
    assert exc.value.reason_code == "DAG-PV-SEQ-CONFLICT"


def test_new_reason_codes_registered():
    from graqle.assurance.reason_codes import REGISTRY

    for code in (
        "DAG-PV-SEQ-CONFLICT", "DAG-PV-RECORD-FAILED", "DAG-PV-KEY-ROTATED", "DAG-PV-KEYING_UNRECOGNISED",
    ):
        assert code in REGISTRY


# ---- leaf record, committer path (AC-1 committer path, AC-2) --------------------


class FakeStatus:
    value = "committed"


class FakeCommitter:
    def __init__(self) -> None:
        self.calls: list[tuple[dict, uuid.UUID]] = []
        self.cr = SimpleNamespace(
            record_hash="a" * 64, batch_id=None, merkle_root_hex=None, commit_status=FakeStatus(),
            rekor_log_index=None, rekor_log_id=None,
        )

    def submit(self, record, trace_id=None):
        self.calls.append((record, trace_id))
        return self.cr

    def commit_record_for(self, record):
        return self.cr


def _anchored_rig(tmp_path, committer, keying="deployment_salt_v1"):
    rig = Rig(tmp_path, merkle_batch=True)
    rig.rec.committer = committer
    rig.rec._keying = lambda: keying
    return rig


def test_leaf_record_has_exactly_the_five_frozen_keys_and_no_tuning_values(tmp_path):
    committer = FakeCommitter()
    rig = _anchored_rig(tmp_path, committer)
    evt = rig.record("trj_" + "J" * 26)
    (record, trace_id), = committer.calls
    assert tuple(record) == LEAF_HASH_FIELDS
    assert LEAF_INPUT_VERSION == "1.0.0" and record["proof_format_version"] == "1.0.0"
    assert record["content_hash"] == evt.integrity.canonical_hash
    meta = record["governance_metadata"]
    assert meta["schema_version"] == "2" and meta["outcome"] == "HOLD"
    assert not set(meta) & {"weight", "threshold", "cap", "confidence_vector"}
    assert trace_id == uuid.uuid5(NS_DAG, evt.event_id)
    assert trace_id == uuid.uuid5(NS_DAG, evt.event_id)  # deterministic


def test_anchor_ref_follows_commit_status(tmp_path):
    committer = FakeCommitter()
    rig = _anchored_rig(tmp_path, committer)
    evt = rig.record("trj_" + "K" * 26)
    anchor = tmp_path / "events" / f"{evt.event_id}.anchor.json"
    assert not anchor.exists()  # PENDING: nothing to point at, reported honestly as None
    for status, extra in (("committed", {}), ("anchored", {"rekor_log_index": 7, "rekor_log_id": "log"}),
                          ("replay_queued", {})):
        committer.cr = SimpleNamespace(
            record_hash="a" * 64, batch_id="b1", merkle_root_hex="c" * 64,
            commit_status=SimpleNamespace(value=status),
            rekor_log_index=extra.get("rekor_log_index"), rekor_log_id=extra.get("rekor_log_id"),
        )
        assert rig.rec.refresh_anchor(evt)
        assert json.loads(anchor.read_text())["commit_status"] == status


def test_committer_failure_never_propagates_and_event_stays_valid(tmp_path):
    committer = FakeCommitter()

    def boom(*a, **k):
        raise RuntimeError("committer down")

    committer.submit = boom
    rig = _anchored_rig(tmp_path, committer)
    evt = rig.record("trj_" + "R" * 26)
    assert rig.store.load(evt.event_id)["integrity"]["canonical_hash"] == evt.integrity.canonical_hash


@pytest.mark.parametrize("bad", ["joint_canonical_v0", "", "deployment_salt_v1 ", "DEPLOYMENT_SALT_V1"])
def test_unrecognised_keying_refuses_before_any_write(tmp_path, bad):
    committer = FakeCommitter()
    rig = _anchored_rig(tmp_path, committer, keying=bad)
    with pytest.raises(pr.ProvenanceUnavailableError) as exc:
        rig.record("trj_" + "M" * 26)
    assert exc.value.reason_code == "DAG-PV-KEYING_UNRECOGNISED"
    assert committer.calls == [] and rig.rec.sequencer.head("trj_" + "M" * 26)[0] == -1


def test_batch_off_never_calls_committer(tmp_path):
    committer = FakeCommitter()
    rig = Rig(tmp_path)  # merkle_batch False
    rig.rec.committer = committer
    rig.record("trj_" + "N" * 26)
    assert committer.calls == []


def test_leaf_schema_files_unchanged_by_this_pr():
    import subprocess

    root = Path(__file__).resolve().parents[2]
    for base in ("origin/master", "private/master"):
        out = subprocess.run(
            ["git", "diff", "--name-only", f"{base}", "HEAD", "--",  # tree compare: this branch's history is not a descendant of master's
             "graqle/governance/tamper_evidence/leaf_input_schema.py",
             "graqle/governance/tamper_evidence/committer.py",
             "graqle/config/attestation_config.py"],
            cwd=root, capture_output=True, text=True,
        )
        if out.returncode == 0:
            assert out.stdout.strip() == ""
            return
    pytest.skip("no master ref available")


# ---- AC-14 / AC-18 static --------------------------------------------------------


def test_recorder_has_no_numeric_literals_beyond_0_1_32_64():
    src = Path(pr.__file__).read_text(encoding="utf-8")
    bad = [
        n.value for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float))
        and not isinstance(n.value, bool) and n.value not in (0, 1, 32, 64)
    ]
    assert bad == []


def test_no_kg_file_is_opened_for_writing():
    root = Path(pr.__file__).parent
    for name in ("provenance_recorder.py", "provenance_store.py", "signing.py", "salt_escrow.py"):
        tree = ast.parse((root / name).read_text(encoding="utf-8"))
        literals = [
            a.value
            for call in ast.walk(tree)
            if isinstance(call, ast.Call)
            for a in [*call.args, *(k.value for k in call.keywords)]
            if isinstance(a, ast.Constant) and isinstance(a.value, str)
        ]
        assert not [s for s in literals if s.startswith("graqle") and s.endswith(".json")]


# ---- Neo4j backends: every write via execute_write (AC-18 runtime spy) -----------


class SpyDriver:
    def __init__(self) -> None:
        self.writes = 0
        self.direct_runs = 0
        self.cypher: list[str] = []
        self.fail = False

    def session(self, database=None):
        drv = self

        class _S:
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

            def execute_write(s, fn):
                drv.writes += 1
                if drv.fail:
                    raise RuntimeError("down")

                class _Tx:
                    def run(self_tx, q, **kw):
                        drv.cypher.append(q)
                        return SimpleNamespace(single=lambda: {"n": 0})

                return fn(_Tx())

            def execute_read(s, fn):
                class _Tx:
                    def run(self_tx, q, **kw):
                        return [{"p": "actor.agent_id", "h": "ab" * 32}]

                return fn(_Tx())

            def run(s, *a, **k):
                drv.direct_runs += 1

        return _S()


def test_neo4j_store_and_escrow_write_only_through_execute_write(tmp_path):
    drv = SpyDriver()
    rig = Rig(tmp_path)
    rig.store = Neo4jProvenanceStore(drv)
    rig.escrow = Neo4jSaltEscrow(drv)
    rig.rec.store, rig.rec.escrow = rig.store, rig.escrow
    evt = rig.record("trj_" + "P" * 26)
    assert drv.writes == 2 and drv.direct_runs == 0
    assert any("ProvenanceSalt" in q for q in drv.cypher)
    assert any("ProvenanceEvent" in q for q in drv.cypher)
    assert rig.escrow.get(evt.event_id) == {"actor.agent_id": bytes.fromhex("ab" * 32)}
    rig.store.attach_anchor(evt.event_id, {"leaf_hash": "a" * 64})
    assert drv.direct_runs == 0


def test_neo4j_failures_fail_closed():
    drv = SpyDriver()
    drv.fail = True
    with pytest.raises(SaltEscrowError):
        Neo4jSaltEscrow(drv).put("evt_" + "0" * 26, {"actor.agent_id": b"\x00" * 32})
    with pytest.raises(ProvenanceStoreError):
        Neo4jProvenanceStore(drv).attach_anchor("evt_" + "0" * 26, {})


def test_file_store_refuses_duplicate_slot_and_event(tmp_path):
    rig = Rig(tmp_path)
    evt = rig.record("trj_" + "Q" * 26)
    committed = rig.store.load(evt.event_id)
    with pytest.raises(ProvenanceStoreError):
        rig.store.persist(committed)
    forked = json.loads(json.dumps(committed))
    forked["event_id"] = new_id("evt")
    with pytest.raises(ProvenanceStoreError):  # same (trajectory, sequence) slot
        rig.store.persist(forked)
