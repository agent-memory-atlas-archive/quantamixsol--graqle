"""CR-012 / PR-012a — ``graqle.assurance.settings`` (AC-1 … AC-5 + review checklist).

Every numeric value in this file is a NON-INFERENTIAL SUBSTITUTE (CR-012 §12,
CR-013 §12: cap 0.31, HG-05 0.61, HG-07 0.51). No real threshold, cap, weight,
half-life or budget appears here.

Covers:
  AC-1  flag parse — positive allowlist, unknown ⇒ OFF
  AC-2  yaml ``assurance.enabled`` ⇒ ConfigurationError at ``from_yaml`` BEFORE env interpolation
  AC-3  flag on + missing required ⇒ ConfigurationError naming the exact env vars; nothing cached
  AC-4  0 rejected for cap / HG-05 / HG-07 / retry budget (lesson R5)
  AC-5  ``.env.example`` names every DagSettings field; no numeric TS values
  checklist (1)-(6): env wins over private file; env-only flag; config_version
  hides secret values; startup validator; no import of graqle.assurance from
  graqle.config.settings at import time; ``model_dump`` never carries ``enabled``.

See: .gsm/external/Change Requests/DAG-2026/
     CR-012-DAG-foundation-flag-schema-reason-codes-hygiene.md
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: tests.test_assurance.test_settings
# risk: LOW (impact radius: 0 modules)
# dependencies: pytest, graqle.assurance.settings, graqle.config.settings
# constraints: substitute values only (TS-2/TS-3)
# -- /graqle:intelligence --
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest

import graqle.assurance.settings as dag
from graqle.assurance.settings import (
    REQUIRED_WHEN_ENABLED,
    SECRET_VALUED_FIELDS,
    ConfigurationError,
    DagSettings,
    config_provenance,
    config_version,
    env_name,
    is_dag_enabled,
    load_dag_settings,
    reset_dag_settings_cache,
    validate_flag_consistency,
)
from graqle.config.settings import AssuranceConfig, GraqleConfig

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENV_EXAMPLE = _REPO_ROOT / ".env.example"

# Substitute values — deliberately NOT the real ones.
# The salt is a 40-byte test substitute (PR-339 B1: >= 32 bytes required).
_SUBSTITUTE_SALT = "test-substitute-salt-0123456789abcdef-XYZ"
_SUBSTITUTE_REQUIRED: dict[str, str] = {
    "GRAQLE_DAG_CONFIG_SALT": _SUBSTITUTE_SALT,
    "GRAQLE_DAG_CAP_VALUE": "0.31",
    "GRAQLE_DAG_HG05_POISONING_THRESHOLD": "0.61",
    "GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD": "0.51",
    "GRAQLE_DAG_CALIBRATOR_VERSION": "cal-test-v0",
    "GRAQLE_DAG_TRAJECTORY_ESTIMATOR": "causal_baseline",
    "GRAQLE_DAG_MAX_RETRY_BUDGET": "3",
    "GRAQLE_DAG_CIRCUIT_BREAKER_WINDOW": "5",
    "GRAQLE_DAG_SIGNING_KEY_ID": "kid-test-2026",
    "GRAQLE_DAG_SIGNING_KEY_VERSION": "1",
}


@pytest.fixture(autouse=True)
def _isolated_dag_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Strip every GRAQLE_DAG_* / GRAQLE_TRACE_SCHEMA_* var, point the private
    file at a non-existent path, and reset the module cache before AND after."""
    for key in list(dag.os.environ):
        if key.upper().startswith("GRAQLE_DAG_") or key.upper().startswith("GRAQLE_TRACE_SCHEMA_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GRAQLE_DAG_SECRETS_PATH", str(tmp_path / "absent-private.yaml"))
    reset_dag_settings_cache()
    yield
    reset_dag_settings_cache()


def _set_required(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> None:
    for k, v in {**_SUBSTITUTE_REQUIRED, **overrides}.items():
        monkeypatch.setenv(k, v)


# ─────────────── AC-1 flag parse ─────────────────────────────────────────────


@pytest.mark.parametrize("raw", [None, "", "false", "0", "garbage", "no", "off", "TRUE ISH", "2"])
def test_ac1_flag_off_values(monkeypatch: pytest.MonkeyPatch, raw: str | None) -> None:
    if raw is None:
        monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    else:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", raw)
    assert is_dag_enabled() is False


@pytest.mark.parametrize("raw", ["1", "true", "yes", "on", " TRUE ", "On", "\tYes\n", "ON"])
def test_ac1_flag_on_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", raw)
    assert is_dag_enabled() is True


def test_ac1_dagsettings_enabled_uses_same_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "garbage")
    assert DagSettings().enabled is False
    assert DagSettings(enabled="yes", **_lower(_SUBSTITUTE_REQUIRED)).enabled is True


def _lower(env: dict[str, str]) -> dict[str, str]:
    return {k[len("GRAQLE_DAG_"):].lower(): v for k, v in env.items()}


# ─────────────── AC-2 yaml assurance.enabled rejected ────────────────────────


def _write_yaml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "graqle.yaml"
    p.write_text(body, encoding="utf-8")
    return p


@pytest.mark.parametrize(
    "body",
    [
        "assurance:\n  enabled: false\n",
        "assurance:\n  enabled: true\n",
        "assurance:\n  enabled: null\n",
        # an env-ref must be caught BEFORE interpolation
        "assurance:\n  enabled: ${GRAQLE_DAG_ENABLED}\n",
    ],
)
def test_ac2_yaml_assurance_enabled_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    # Equal to the env value on purpose: presence alone is the violation (INV-FLAG-2).
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "false")
    path = _write_yaml(tmp_path, body)
    with pytest.raises(ConfigurationError, match="assurance.enabled"):
        GraqleConfig.from_yaml(path)


def test_ac2_empty_assurance_block_is_fine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_yaml(tmp_path, "assurance: {}\n")
    cfg = GraqleConfig.from_yaml(path)
    assert cfg.assurance.enabled is False
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "on")
    _set_required(monkeypatch)
    assert cfg.assurance.enabled is True  # derived live, never stored


def test_ac2_assurance_config_forbids_enabled_field_directly() -> None:
    with pytest.raises(Exception):  # pydantic ValidationError (extra forbidden)
        AssuranceConfig.model_validate({"enabled": True})


def test_assurance_enabled_never_serialised(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dumped config must be re-loadable without smuggling the flag into yaml."""
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    dumped = GraqleConfig().model_dump()
    assert dumped["assurance"] == {}
    assert "enabled" not in GraqleConfig().model_dump(mode="json")["assurance"]


# ─────────────── AC-3 required-when-enabled ──────────────────────────────────


def test_ac3_flag_on_missing_required_names_every_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    with pytest.raises(ConfigurationError) as ei:
        load_dag_settings()
    msg = str(ei.value)
    for field in REQUIRED_WHEN_ENABLED:
        assert env_name(field) in msg
    assert "No placeholder fallback exists" in msg
    assert dag._cache is None, "no partial object may be cached"
    assert config_provenance() == {}


def test_ac3_flag_on_partial_required_names_only_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    _set_required(monkeypatch)
    monkeypatch.delenv("GRAQLE_DAG_SIGNING_KEY_ID")
    monkeypatch.delenv("GRAQLE_DAG_MAX_RETRY_BUDGET")
    with pytest.raises(ConfigurationError) as ei:
        load_dag_settings()
    msg = str(ei.value)
    assert "GRAQLE_DAG_SIGNING_KEY_ID" in msg and "GRAQLE_DAG_MAX_RETRY_BUDGET" in msg
    assert "GRAQLE_DAG_CAP_VALUE" not in msg
    # names only — never the present values
    assert "0.31" not in msg and "0.61" not in msg and "0.51" not in msg


def test_ac3_flag_on_complete_env_loads_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    _set_required(monkeypatch)
    s = load_dag_settings()
    assert s.enabled is True
    assert s is load_dag_settings()  # cached
    prov = config_provenance()
    assert prov["cap_value"] == "ENV"
    assert prov["rbac_timeout_ms"] == "SAFE_DEFAULT"
    assert prov["ontology_shapes_path"] == "UNSET"


def test_flag_off_needs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_dag_settings()
    assert s.enabled is False and s.cap_value is None


def test_cache_invalidates_when_flag_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    first = load_dag_settings()
    assert first.enabled is False
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    _set_required(monkeypatch)
    second = load_dag_settings()
    assert second is not first and second.enabled is True


# ─────────────── AC-4 zero rejected ──────────────────────────────────────────


@pytest.mark.parametrize(
    "var",
    [
        "GRAQLE_DAG_CAP_VALUE",
        "GRAQLE_DAG_HG05_POISONING_THRESHOLD",
        "GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD",
        "GRAQLE_DAG_MAX_RETRY_BUDGET",
    ],
)
@pytest.mark.parametrize("flag", ["true", "false"])
def test_ac4_zero_rejected(monkeypatch: pytest.MonkeyPatch, var: str, flag: str) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", flag)
    _set_required(monkeypatch, **{var: "0"})
    with pytest.raises(ConfigurationError, match="DAG settings invalid") as ei:
        load_dag_settings()
    assert var in str(ei.value)  # names the env var, never the value
    assert "zero is rejected" in str(ei.value)
    assert dag._cache is None


@pytest.mark.parametrize(
    ("var", "bad"),
    [
        ("GRAQLE_DAG_CAP_VALUE", "1"),        # lt=1
        ("GRAQLE_DAG_CAP_VALUE", "-0.31"),
        ("GRAQLE_DAG_HG05_POISONING_THRESHOLD", "1.5"),
        ("GRAQLE_DAG_CAP_VALUE", "nan"),
        ("GRAQLE_DAG_CAP_VALUE", ""),
        ("GRAQLE_DAG_PROPAGATION_MAX_DEPTH", "0"),
        ("GRAQLE_DAG_RBAC_TIMEOUT_MS", "0"),
        ("GRAQLE_DAG_ESCALATION_ROLE", "not-a-role"),
        ("GRAQLE_DAG_HG03_IMPACT_TIER_MIN", "EXTREME"),
        ("GRAQLE_DAG_ARGS_HASH_ALGO", "md5"),
    ],
)
def test_boundary_values_rejected_without_echoing_input(
    monkeypatch: pytest.MonkeyPatch, var: str, bad: str
) -> None:
    _set_required(monkeypatch, **{var: bad})
    with pytest.raises(ConfigurationError) as ei:
        load_dag_settings()
    msg = str(ei.value)
    assert bad == "" or bad not in msg, "rejected input value must not be echoed"
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


def test_boundary_one_accepted_for_le_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(
        monkeypatch,
        GRAQLE_DAG_HG05_POISONING_THRESHOLD="1",
        GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD="1.0",
    )
    s = load_dag_settings()
    assert s.hg05_poisoning_threshold == 1.0 and s.hg07_materiality_threshold == 1.0


def test_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_dag_settings()
    with pytest.raises(Exception):
        s.enabled = True  # type: ignore[misc]


# ─────────────── AC-5 .env.example ───────────────────────────────────────────


def _env_example_assignments() -> dict[str, str]:
    assert _ENV_EXAMPLE.is_file(), ".env.example missing at repo root"
    out: dict[str, str] = {}
    for line in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        out[name.strip()] = value.split("#", 1)[0].strip()
    return out


def test_ac5_every_field_has_an_env_example_line() -> None:
    names = _env_example_assignments()
    missing = [env_name(f) for f in DagSettings.model_fields if env_name(f) not in names]
    assert not missing, f".env.example lacks: {missing}"


def test_ac5_env_example_has_no_numeric_tuning_values() -> None:
    numeric = re.compile(r"^-?\d+(\.\d+)?$")
    offenders = {
        k: v for k, v in _env_example_assignments().items()
        if k.startswith("GRAQLE_DAG_") and numeric.match(v)
    }
    assert not offenders, f"numeric literals are TS-3 and must be placeholders: {offenders}"


def test_ac5_env_example_declares_flag_off_and_schema_pins() -> None:
    names = _env_example_assignments()
    assert names["GRAQLE_DAG_ENABLED"] == "false"
    assert names["GRAQLE_TRACE_SCHEMA_VERSION"] == "3"
    assert names["GRAQLE_TRACE_SCHEMA_STRICT"] == "false"


# ─────────────── private file layering (brief §8.3) ──────────────────────────


def _write_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    p = tmp_path / "graqle_secrets.yaml"
    p.write_text(body, encoding="utf-8")
    p.chmod(0o600)  # PR-339 M3: the loader refuses group/world-readable files on POSIX
    monkeypatch.setenv("GRAQLE_DAG_SECRETS_PATH", str(p))
    return p


def test_private_file_supplies_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_private(tmp_path, monkeypatch, "cap_value: 0.31\nGRAQLE_DAG_MAX_RETRY_BUDGET: 3\n")
    s = load_dag_settings()
    assert s.cap_value == 0.31 and s.max_retry_budget == 3
    prov = config_provenance()
    assert prov["cap_value"] == "SECRETS_FILE" and prov["max_retry_budget"] == "SECRETS_FILE"


def test_env_wins_over_private_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_private(tmp_path, monkeypatch, "cap_value: 0.31\n")
    monkeypatch.setenv("GRAQLE_DAG_CAP_VALUE", "0.37")
    s = load_dag_settings()
    assert s.cap_value == 0.37
    assert config_provenance()["cap_value"] == "ENV"


def test_private_file_cannot_set_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_private(tmp_path, monkeypatch, "enabled: true\ncap_value: 0.31\n")
    with pytest.raises(ConfigurationError, match="environment-only"):
        load_dag_settings()
    assert is_dag_enabled() is False


def test_private_file_unknown_key_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_private(tmp_path, monkeypatch, "cap_valeu: 0.31\n")
    with pytest.raises(ConfigurationError, match="unknown keys.*cap_valeu"):
        load_dag_settings()


@pytest.mark.parametrize("body", ["- a\n- b\n", "cap_value: [0.31\n"])
def test_private_file_malformed_rejected_without_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    p = _write_private(tmp_path, monkeypatch, body)
    with pytest.raises(ConfigurationError) as ei:
        load_dag_settings()
    assert str(p) in str(ei.value)
    assert "0.31" not in str(ei.value)


def test_unknown_prefixed_env_var_is_a_drift_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_NOT_A_FIELD", "1")
    with pytest.raises(ConfigurationError, match="GRAQLE_DAG_NOT_A_FIELD"):
        load_dag_settings()


# ─────────────── config_version (Senior chain 4) ─────────────────────────────


def test_config_version_stable_and_prefixed(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    a = config_version(load_dag_settings())
    b = config_version(load_dag_settings(force=True))
    assert a == b and re.fullmatch(r"sha256:[0-9a-f]{64}", a)


def test_config_version_changes_with_a_secret_value(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    a = config_version(load_dag_settings())
    monkeypatch.setenv("GRAQLE_DAG_CAP_VALUE", "0.37")
    b = config_version(load_dag_settings(force=True))
    assert a != b


def test_config_version_payload_never_carries_secret_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required(
        monkeypatch,
        GRAQLE_DAG_CV_MAX_RAW_CAL_DIVERGENCE="0.41",
        GRAQLE_DAG_TEMPORAL_HALFLIFE_DAYS="7",
    )
    s = load_dag_settings()
    payload = dag._config_version_payload(s)
    for f in SECRET_VALUED_FIELDS:
        assert f not in payload
    flat = repr(payload)
    for v in ("0.31", "0.61", "0.51", "0.41"):
        assert v not in flat
    assert payload["_secret_fields_set"] == sorted(SECRET_VALUED_FIELDS)
    assert re.fullmatch(r"[0-9a-f]{64}", payload["_secrets_digest"])
    # non-secret fields ARE visible (they are public symbols)
    assert payload["escalation_role"] == "lead" and payload["args_hash_algo"] == "sha256"


def test_config_version_flag_off_has_no_secret_digest() -> None:
    payload = dag._config_version_payload(load_dag_settings())
    assert payload["_secret_fields_set"] == [] and payload["_secrets_digest"] is None


def test_config_version_fails_closed_on_canon_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_: object) -> bytes:
        raise RuntimeError("canon down")

    import graqle.governance.tamper_evidence.canonicalize as canonmod

    monkeypatch.setattr(canonmod, "canon", _boom)
    with pytest.raises(ConfigurationError, match="config_version could not be computed"):
        config_version(load_dag_settings())


# ─────────────── startup validator (blueprint B1) ────────────────────────────


def test_validate_flag_consistency_off_is_noop() -> None:
    validate_flag_consistency(GraqleConfig())
    assert dag._cache is None  # nothing loaded when off


def test_validate_flag_consistency_on_loads_and_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    _set_required(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="graqle.assurance.settings"):
        validate_flag_consistency(GraqleConfig())
    assert dag._cache is not None
    rec = [r for r in caplog.records if "DAG enabled" in r.getMessage()]
    assert rec and "config_version=sha256:" in rec[0].getMessage()
    assert "0.31" not in rec[0].getMessage()


def test_validate_flag_consistency_on_incomplete_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    with pytest.raises(ConfigurationError, match="required DAG settings are absent"):
        validate_flag_consistency(GraqleConfig())


def test_validate_flag_consistency_mismatch_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Fake:
        class assurance:  # noqa: N801 — stand-in for a monkey-patched config
            enabled = True

    with pytest.raises(ConfigurationError, match="single source violated"):
        validate_flag_consistency(_Fake())


def test_validate_flag_consistency_requires_assurance_section() -> None:
    with pytest.raises(ConfigurationError, match="no 'assurance' section"):
        validate_flag_consistency(object())


def test_from_yaml_runs_startup_validator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    path = _write_yaml(tmp_path, "project_name: t\n")
    with pytest.raises(ConfigurationError, match="required DAG settings are absent"):
        GraqleConfig.from_yaml(path)
    _set_required(monkeypatch)
    assert GraqleConfig.from_yaml(path).assurance.enabled is True


# ─────────────── import isolation (review checklist item 6) ──────────────────


@pytest.mark.slow_subprocess
def test_config_settings_import_does_not_load_assurance() -> None:
    code = (
        "import sys, graqle.config.settings; "
        "assert not [m for m in sys.modules if m.startswith('graqle.assurance')], "
        "[m for m in sys.modules if m.startswith('graqle.assurance')]"
    )
    subprocess.run([sys.executable, "-c", code], cwd=_REPO_ROOT, check=True)


@pytest.mark.slow_subprocess
def test_assurance_settings_import_does_not_load_governance() -> None:
    """assurance -> governance is the allowed direction, but the canonicaliser is
    loaded lazily inside config_version() so flag-off import cost stays zero.
    (graqle.config.settings IS loaded transitively via the graqle.config package
    __init__ — that is package init, not a cycle: config.settings never imports
    assurance at module level; see the test above.)"""
    code = (
        "import sys, graqle.assurance.settings; "
        "bad = [m for m in sys.modules if m.startswith('graqle.governance')]; "
        "assert not bad, bad"
    )
    subprocess.run([sys.executable, "-c", code], cwd=_REPO_ROOT, check=True)


# ─────────────── PR-339 round 2 — B1 salt · M1 blank strings · M2 cache key · M3 paths ──


def test_b1_salt_required_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    _set_required(monkeypatch)
    monkeypatch.delenv("GRAQLE_DAG_CONFIG_SALT")
    with pytest.raises(ConfigurationError, match="GRAQLE_DAG_CONFIG_SALT"):
        load_dag_settings()
    assert dag._cache is None


def test_b1_short_salt_rejected_without_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch, GRAQLE_DAG_CONFIG_SALT="too-short")
    with pytest.raises(ConfigurationError) as ei:
        load_dag_settings()
    assert "GRAQLE_DAG_CONFIG_SALT" in str(ei.value)
    assert "too-short" not in str(ei.value)


def test_b1_identical_secrets_different_salts_differ(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    a = config_version(load_dag_settings())
    assert config_provenance()["keying"] == "deployment_salt_v1"
    monkeypatch.setenv("GRAQLE_DAG_CONFIG_SALT", _SUBSTITUTE_SALT[::-1])
    b = config_version(load_dag_settings())
    assert a != b


def test_b1_salt_never_in_payload_dump_repr_logs_or_provenance(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _set_required(monkeypatch)
    with caplog.at_level(logging.DEBUG, logger="graqle.assurance.settings"):
        s = load_dag_settings()
        config_version(s)
    payload = dag._config_version_payload(s)
    assert "config_salt" not in payload
    flat = " ".join(
        [
            repr(payload),
            repr(s),
            str(s.model_dump(mode="json")),
            repr(dict(config_provenance())),
            *(r.getMessage() for r in caplog.records),
        ]
    )
    assert _SUBSTITUTE_SALT not in flat
    assert s.config_salt is not None
    assert s.config_salt.get_secret_value() == _SUBSTITUTE_SALT


def test_b1_flag_off_without_salt_uses_joint_keying() -> None:
    s = load_dag_settings()
    assert s.config_salt is None
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", config_version(s))
    assert config_provenance()["keying"] == "joint_canonical_v1"


@pytest.mark.parametrize(
    "var",
    [
        "GRAQLE_DAG_CALIBRATOR_VERSION",
        "GRAQLE_DAG_TRAJECTORY_ESTIMATOR",
        "GRAQLE_DAG_SIGNING_KEY_ID",
        "GRAQLE_DAG_SIGNING_KEY_VERSION",
        "GRAQLE_DAG_CONFIG_SALT",
    ],
)
@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_m1_blank_string_counts_as_absent(
    monkeypatch: pytest.MonkeyPatch, var: str, blank: str
) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    _set_required(monkeypatch, **{var: blank})
    with pytest.raises(ConfigurationError, match=var):
        load_dag_settings()
    assert dag._cache is None


def test_m2_env_change_invalidates_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    first = load_dag_settings()
    monkeypatch.setenv("GRAQLE_DAG_CAP_VALUE", "0.37")
    second = load_dag_settings()
    assert second is not first and second.cap_value == 0.37


def test_m2_rotated_private_file_invalidates_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _write_private(tmp_path, monkeypatch, "cap_value: 0.31\n")
    first = load_dag_settings()
    assert first.cap_value == 0.31
    p.write_text("cap_value: 0.37\n", encoding="utf-8")
    st = p.stat()
    dag.os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000))
    second = load_dag_settings()
    assert second is not first and second.cap_value == 0.37


def test_m2_unchanged_environment_serves_cache() -> None:
    assert load_dag_settings() is load_dag_settings()


def test_m3_path_fields_excluded_from_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(
        monkeypatch,
        GRAQLE_DAG_BENCH_RESULTS_DIR="bench-a",
        GRAQLE_DAG_ONTOLOGY_SHAPES_PATH="shapes-a.ttl",
    )
    s = load_dag_settings()
    payload = dag._config_version_payload(s)
    for f in ("secrets_path", "recompute_queue_path", "bench_results_dir", "ontology_shapes_path"):
        assert f not in payload
    assert payload["signing_key_id"] == "kid-test-2026"  # a public kid stays in clear
    a = config_version(s)
    monkeypatch.setenv("GRAQLE_DAG_BENCH_RESULTS_DIR", "bench-b")
    assert config_version(load_dag_settings()) == a  # topology change, same semantics


def test_m3_non_regular_secrets_file_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRAQLE_DAG_SECRETS_PATH", str(tmp_path))  # a directory, not a file
    with pytest.raises(ConfigurationError, match="regular file"):
        load_dag_settings()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_m3_posix_group_or_world_readable_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _write_private(tmp_path, monkeypatch, "cap_value: 0.31\n")
    p.chmod(0o644)
    with pytest.raises(ConfigurationError, match="chmod 600"):
        load_dag_settings()
    p.chmod(0o600)
    assert load_dag_settings().cap_value == 0.31


@pytest.mark.skipif(sys.platform != "win32", reason="Windows warning path")
def test_m3_windows_warns_that_mode_bits_are_unchecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _write_private(tmp_path, monkeypatch, "cap_value: 0.31\n")
    with caplog.at_level(logging.WARNING, logger="graqle.assurance.settings"):
        load_dag_settings()
    assert any("permission" in r.getMessage().lower() for r in caplog.records)


def test_n1_rbac_import_failure_is_attributable(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def _fake(name, *args, **kwargs):  # noqa: ANN001
        if name == "graqle.core.rbac":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake)
    with pytest.raises(ConfigurationError, match="core.rbac unavailable"):
        DagSettings(escalation_role="lead")


def test_n4_canon_failure_type_logged_at_debug(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import graqle.governance.tamper_evidence.canonicalize as canonmod

    def _boom(_: object) -> bytes:
        raise RuntimeError("canon down")

    monkeypatch.setattr(canonmod, "canon", _boom)
    with caplog.at_level(logging.DEBUG, logger="graqle.assurance.settings"):
        with pytest.raises(ConfigurationError):
            config_version(load_dag_settings())
    assert any("RuntimeError" in r.getMessage() for r in caplog.records)
    assert not any("canon down" in r.getMessage() for r in caplog.records)
