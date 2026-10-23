"""CR-018 PR-018b: DagSettings.provenance mount, manifest store, high-water refusal (AC-6/7)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from graqle.assurance.key_manifest_store import ManifestRecord, load_manifest, save_manifest
from graqle.assurance.provenance_settings import ProvenanceSettings
from graqle.assurance.settings import DagSettings, load_dag_settings, reset_dag_settings_cache
from graqle.assurance.signing import DagSigner
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

