"""CR-018 PR-018b: DagSettings.provenance mount, manifest store, `graq dag rotate-key` (AC-6/7)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from graqle.assurance.key_manifest_store import ManifestRecord, load_manifest, save_manifest
from graqle.assurance.provenance_settings import ProvenanceSettings
from graqle.assurance.settings import DagSettings, load_dag_settings, reset_dag_settings_cache
from graqle.assurance.signing import DagSigner
try:  # the `graq dag` CLI is not part of the 0.87.0 port; rotate-key tests skip without it
    from graqle.cli.commands.dag import dag_app
except ImportError:
    dag_app = None
from graqle.config.exceptions import ConfigurationError
from graqle.governance.custody.ed25519_key_manifest import Ed25519KeyManifest, KeyState

KID = "kid-a"
NEW_KID = "kid-b"
NOW = datetime.now(timezone.utc)

_DAG_REQUIRED = {
    "GRAQLE_DAG_CONFIG_SALT": "s" * 40,
    "GRAQLE_DAG_CAP_VALUE": "0.5",
    "GRAQLE_DAG_HG05_POISONING_THRESHOLD": "0.5",
    "GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD": "0.5",
    "GRAQLE_DAG_CALIBRATOR_VERSION": "v",
    "GRAQLE_DAG_TRAJECTORY_ESTIMATOR": "e",
    "GRAQLE_DAG_MAX_RETRY_BUDGET": "1",
    "GRAQLE_DAG_CIRCUIT_BREAKER_WINDOW": "1",
    "GRAQLE_DAG_SCOPE_KEY_FIELDS_REF": "x",
    "GRAQLE_DAG_MERGE_PRIORITY_REF": "sdk_default",
}


def _pem(path: Path, key: Ed25519PrivateKey) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def dag_env(tmp_path, monkeypatch):
    """Flag on, file backends, a saved one-key manifest; cwd is the temp dir."""
    for name in list(os.environ):
        if name.startswith("GRAQLE_DAG_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
    key = Ed25519PrivateKey.generate()
    manifest = Ed25519KeyManifest()
    manifest.register(KID, key.public_key(), NOW - timedelta(days=1), NOW + timedelta(days=60))
    manifest_path = tmp_path / "key_manifest.json"
    save_manifest(manifest_path, manifest, {KID: 1})
    key_path = _pem(tmp_path / "k.pem", key)
    env = {
        **_DAG_REQUIRED,
        "GRAQLE_DAG_ENABLED": "1",
        "GRAQLE_DAG_SIGNING_KEY_ID": KID,
        "GRAQLE_DAG_SIGNING_KEY_VERSION": "1",
        "GRAQLE_DAG_SIGNING_KEY_PATH": str(key_path),
        "GRAQLE_DAG_KEY_MANIFEST_PATH": str(manifest_path),
        "GRAQLE_DAG_COVERAGE_POLICY_PATH": "cp.yaml",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    reset_dag_settings_cache()
    yield SimpleNs(tmp=tmp_path, manifest_path=manifest_path, key_path=key_path)
    reset_dag_settings_cache()


class SimpleNs:
    def __init__(self, **kw) -> None:
        self.__dict__.update(kw)


def _rotate(env, out: Path | None = None, kid: str = NEW_KID):
    if dag_app is None:
        pytest.skip("graq dag CLI not present in this release")
    out = out or env.tmp / "new.pem"
    return CliRunner().invoke(dag_app, ["rotate-key", "--new-kid", kid, "--new-key-out", str(out)])


# ---- DagSettings.provenance (ruling R3) --------------------------------------


def test_provenance_is_none_when_flag_off(monkeypatch):
    monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    assert DagSettings().provenance is None


def test_provenance_reads_through_when_on_and_drift_lock_accepts_its_env(dag_env):
    settings = load_dag_settings()  # would raise on GRAQLE_DAG_SIGNING_KEY_PATH etc. without the mount
    prov = settings.provenance
    assert isinstance(prov, ProvenanceSettings)
    assert prov.signing_key_id == KID and prov.signing_key_version == 1


def test_unknown_dag_env_var_is_still_rejected(dag_env, monkeypatch):
    monkeypatch.setenv("GRAQLE_DAG_NOT_A_SETTING", "1")
    with pytest.raises(ConfigurationError):
        load_dag_settings(force=True)


# ---- manifest store ---------------------------------------------------------------


def test_store_roundtrip_keeps_state_versions_and_holds_no_private_material(tmp_path):
    key = Ed25519PrivateKey.generate()
    manifest = Ed25519KeyManifest()
    manifest.register(KID, key.public_key(), NOW, NOW + timedelta(days=9), private_key=key)
    manifest.register(NEW_KID, Ed25519PrivateKey.generate().public_key(), NOW, NOW + timedelta(days=9))
    manifest.retire(KID)
    path = tmp_path / "m.json"
    retire_at = {KID: NOW}
    save_manifest(path, manifest, {KID: 1, NEW_KID: 2}, retire_at)
    raw = path.read_text()
    assert "PRIVATE" not in raw
    rec = load_manifest(path)
    assert isinstance(rec, ManifestRecord)
    assert rec.manifest.get(KID).state is KeyState.RETIRED
    assert rec.versions == {KID: 1, NEW_KID: 2} and rec.high_water == 2
    assert rec.retire_at[KID] == NOW


@pytest.mark.parametrize("content", ["", "{", "[]", '{"format": "other", "keys": []}', '{"format": "graqle.dag.key_manifest.v1"}'])
def test_malformed_manifest_fails_closed(tmp_path, content):
    path = tmp_path / "m.json"
    path.write_text(content)
    with pytest.raises(ConfigurationError):
        load_manifest(path)


def test_missing_manifest_fails_closed(tmp_path):
    with pytest.raises(ConfigurationError):
        load_manifest(tmp_path / "absent.json")


def test_save_refuses_a_kid_without_a_version(tmp_path):
    manifest = Ed25519KeyManifest()
    manifest.register(KID, Ed25519PrivateKey.generate().public_key(), NOW, NOW + timedelta(days=1))
    with pytest.raises(ConfigurationError):
        save_manifest(tmp_path / "m.json", manifest, {})


def test_signer_refuses_version_below_high_water(dag_env):
    rec = load_manifest(dag_env.manifest_path)
    cfg = load_dag_settings().provenance
    with pytest.raises(ConfigurationError, match="high-water"):
        DagSigner(cfg, rec.manifest, high_water=2)
    DagSigner(cfg, rec.manifest, high_water=1)  # equal is fine


# ---- graq dag rotate-key -------------------------------------------------------------


def test_rotate_key_flag_off_exits_3(dag_env, monkeypatch):
    monkeypatch.delenv("GRAQLE_DAG_ENABLED")
    result = _rotate(dag_env)
    assert result.exit_code == 3
    assert not (dag_env.tmp / "new.pem").exists()


def test_rotate_key_registers_successor_persists_and_signs_with_it(dag_env):
    result = _rotate(dag_env)
    assert result.exit_code == 0, result.output
    assert f"GRAQLE_DAG_SIGNING_KEY_ID={NEW_KID}" in result.output
    assert "GRAQLE_DAG_SIGNING_KEY_VERSION=2" in result.output
    assert "PRIVATE" not in result.output
    new_pem = dag_env.tmp / "new.pem"
    assert new_pem.stat().st_mode & 0o777 == 0o600
    rec = load_manifest(dag_env.manifest_path)
    assert rec.versions == {KID: 1, NEW_KID: 2}
    assert rec.manifest.get(KID).state is KeyState.ACTIVE  # retired later, never revoked
    assert KID in rec.retire_at and rec.retire_at[KID] > datetime.now(timezone.utc)
    # The key_rotated event exists on the system trajectory, signed by the new kid.
    events = list(Path(".graqle/dag/events").glob("evt_*.json"))
    assert len(events) == 1 and NEW_KID in events[0].read_text()
    # Switching the environment over yields a working signer; the old version is now refused.
    cfg = ProvenanceSettings(
        signing_key_id=NEW_KID,
        signing_key_version=2,
        signing_key_path=str(new_pem),
        coverage_policy_path="cp.yaml",
    )
    DagSigner(cfg, rec.manifest, high_water=rec.high_water)
    stale = ProvenanceSettings(
        signing_key_id=NEW_KID,
        signing_key_version=1,
        signing_key_path=str(new_pem),
        coverage_policy_path="cp.yaml",
    )
    with pytest.raises(ConfigurationError, match="high-water"):
        DagSigner(stale, rec.manifest, high_water=rec.high_water)


def test_second_rotation_retires_the_first_keys_elapsed_overlap(dag_env, monkeypatch):
    assert _rotate(dag_env).exit_code == 0
    rec = load_manifest(dag_env.manifest_path)
    save_manifest(
        dag_env.manifest_path, rec.manifest, rec.versions, {KID: NOW - timedelta(days=1)}
    )
    monkeypatch.setenv("GRAQLE_DAG_SIGNING_KEY_ID", NEW_KID)
    monkeypatch.setenv("GRAQLE_DAG_SIGNING_KEY_VERSION", "2")
    monkeypatch.setenv("GRAQLE_DAG_SIGNING_KEY_PATH", str(dag_env.tmp / "new.pem"))
    reset_dag_settings_cache()
    assert _rotate(dag_env, dag_env.tmp / "newer.pem", "kid-c").exit_code == 0
    assert load_manifest(dag_env.manifest_path).manifest.get(KID).state is KeyState.RETIRED


def test_rotate_key_never_overwrites_an_existing_key_file(dag_env):
    existing = dag_env.tmp / "new.pem"
    existing.write_text("keep me")
    result = _rotate(dag_env, existing)
    assert result.exit_code == 2
    assert existing.read_text() == "keep me"
    assert load_manifest(dag_env.manifest_path).versions == {KID: 1}


def test_rotate_key_rejects_a_known_kid_and_leaves_no_key_file(dag_env):
    result = _rotate(dag_env, kid=KID)
    assert result.exit_code == 2
    assert not (dag_env.tmp / "new.pem").exists()


def test_rotate_key_fails_closed_without_a_manifest(dag_env):
    dag_env.manifest_path.unlink()
    result = _rotate(dag_env)
    assert result.exit_code == 2
    assert not (dag_env.tmp / "new.pem").exists()


def test_rotate_key_failure_after_key_write_removes_the_key_file(dag_env, monkeypatch):
    from graqle.assurance import key_manifest_store

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(key_manifest_store, "save_manifest", boom)
    result = _rotate(dag_env)
    assert result.exit_code == 2
    assert not (dag_env.tmp / "new.pem").exists()
    assert load_manifest(dag_env.manifest_path).versions == {KID: 1}


def test_rotate_key_without_neo4j_credentials_fails_closed(dag_env, monkeypatch):
    monkeypatch.setenv("GRAQLE_DAG_SEQUENCER", "neo4j")
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
    reset_dag_settings_cache()
    result = _rotate(dag_env)
    assert result.exit_code == 2
    assert not (dag_env.tmp / "new.pem").exists()
