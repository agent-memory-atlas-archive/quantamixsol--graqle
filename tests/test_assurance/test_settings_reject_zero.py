"""ConfidenceVectorSettings: required values, zero rejection, provenance, deprecated alias."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from graqle.assurance.confidence_vector import DimensionName, EntityClass
from graqle.assurance.cv_settings import (
    SOURCE_CLASSES,
    BootstrapSettings,
    ConfidenceVectorSettings,
    load_confidence_vector_settings,
)
from graqle.assurance.projection import Penalties, ProjectionStrategyName
from graqle.assurance.settings import DagSettings
from graqle.config.exceptions import ConfigurationError

from ._proj_fakes import FLAG, MANDATORY, cv_env

P = "GRAQLE_DAG_CV_"


def _load(env: dict[str, str], secrets: dict | None = None, dag: DagSettings | None = None):
    return load_confidence_vector_settings(
        environ=env, secrets={} if secrets is None else secrets, dag=dag or DagSettings()
    )


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return cv_env(str(tmp_path))


class TestHappyPath:
    def test_loads_and_stamps_provenance(self, env) -> None:
        s = _load(env)
        assert s.projection_strategy is ProjectionStrategyName.RULE_ONLY
        assert s.config_provenance["weights"] == "SAFE_DEFAULT"
        assert s.config_provenance["penalties"] == "SAFE_DEFAULT"
        assert s.config_provenance["policy_thresholds"] == "ENV"
        assert s.config_provenance["calibrator_ttl_seconds"] == "ENV"
        assert s.config_version.startswith("sha256:")

    def test_explicit_weights_replace_the_placeholder(self, env) -> None:
        for d in DimensionName:
            env[f"{P}WEIGHT_{d.name}"] = "0.125" if d is DimensionName.CONTEXT_FIT else "0.145833333333"
        # 6 * 0.145833333333 + 0.125 = 1.0 within the sum tolerance
        s = _load(env)
        assert s.config_provenance["weights"] == "ENV"

    def test_secrets_section_fills_gaps_and_env_wins(self, env) -> None:
        del env[f"{P}MAX_DIVERGENCE"]
        del env[f"{P}POLICY_THRESHOLD_ENTITY"]
        secrets = {"max_divergence": 0.3, "policy_threshold_entity": 0.2, "tree_max_depth": 4}
        env[f"{P}POLICY_THRESHOLD_ENTITY"] = "0.6"
        s = _load(env, secrets)
        assert s.max_divergence == pytest.approx(0.3)
        assert s.config_provenance["max_divergence"] == "SECRETS_YAML"
        assert s.policy_thresholds[EntityClass.ENTITY] == pytest.approx(0.6)
        assert s.config_provenance["policy_thresholds"] == "ENV"

    def test_settings_are_frozen(self, env) -> None:
        s = _load(env)
        with pytest.raises(Exception):
            s.max_divergence = 0.9  # type: ignore[misc]


class TestFlag:
    def test_flag_off_refuses_to_construct(self, env) -> None:
        env[FLAG] = "false"
        with pytest.raises(ConfigurationError, match="GRAQLE_DAG_ENABLED"):
            _load(env)

    def test_flag_absent_refuses_to_construct(self, env) -> None:
        del env[FLAG]
        with pytest.raises(ConfigurationError):
            _load(env)


REQUIRED = [
    "CALIBRATOR_TTL_SECONDS",
    "MAX_DIVERGENCE",
    "CALIBRATOR_REGISTRY_PATH",
    *[f"POLICY_THRESHOLD_{c.name}" for c in EntityClass],
    *[f"MANDATORY_DIMS_{c.name}" for c in EntityClass],
    *[f"HALF_LIFE_SECONDS_{s.upper()}" for s in SOURCE_CLASSES],
]


@pytest.mark.parametrize("suffix", REQUIRED)
def test_each_required_variable_missing_raises_and_names_it(env, suffix: str) -> None:
    del env[P + suffix]
    with pytest.raises(ConfigurationError) as err:
        _load(env)
    assert P + suffix in str(err.value)


ZERO_CASES = [
    "CALIBRATOR_TTL_SECONDS",
    "MAX_DIVERGENCE",
    "POLICY_THRESHOLD_ENTITY",
    "POLICY_THRESHOLD_DECISION",
    "HALF_LIFE_SECONDS_CODE",
    "HALF_LIFE_SECONDS_WEB",
    "SOURCE_SATURATION",
    "SAME_BUNDLE_SECONDS",
    "BOOTSTRAP_RESAMPLES",
    "BOOTSTRAP_ALPHA",
    f"RULE_FLOOR_{MANDATORY[0].name}",
]


@pytest.mark.parametrize("suffix", ZERO_CASES)
def test_zero_is_rejected(env, suffix: str) -> None:
    env[P + suffix] = "0"
    with pytest.raises(ConfigurationError):
        _load(env)


@pytest.mark.parametrize("suffix", ["MAX_DIVERGENCE", "POLICY_THRESHOLD_RELATION", "BOOTSTRAP_ALPHA"])
@pytest.mark.parametrize("bad", ["1.0", "-0.2", "nan", "inf", "abc"])
def test_out_of_range_or_non_numeric_is_rejected(env, suffix: str, bad: str) -> None:
    env[P + suffix] = bad
    with pytest.raises(ConfigurationError):
        _load(env)


@pytest.mark.parametrize("name", ["SOURCE_RELIABILITY", "CONTEXT_FIT"])
def test_zero_weight_is_rejected(env, name: str) -> None:
    for d in DimensionName:
        env[f"{P}WEIGHT_{d.name}"] = "0.2"
    env[f"{P}WEIGHT_{name}"] = "0"
    with pytest.raises(ConfigurationError):
        _load(env)


def test_weights_must_sum_to_one(env) -> None:
    for d in DimensionName:
        env[f"{P}WEIGHT_{d.name}"] = "0.2"
    with pytest.raises(ConfigurationError, match="sum to 1"):
        _load(env)


def test_partial_weights_are_rejected(env) -> None:
    env[f"{P}WEIGHT_CORROBORATION"] = "0.5"
    with pytest.raises(ConfigurationError, match="every dimension or none"):
        _load(env)


def test_partial_penalties_are_rejected(env) -> None:
    env[f"{P}PENALTY_STALENESS"] = "0.1"
    with pytest.raises(ConfigurationError, match="all three or none"):
        _load(env)


@pytest.mark.parametrize("bad", ["0", "-1", "nan"])
def test_penalty_zero_negative_or_nan_is_rejected(env, bad: str) -> None:
    for name in ("CONTRADICTION", "STALENESS", "DEPENDENCY"):
        env[f"{P}PENALTY_{name}"] = "0.1"
    env[f"{P}PENALTY_STALENESS"] = bad
    with pytest.raises(ConfigurationError):
        _load(env)


def test_direct_construction_also_rejects_zero(env) -> None:
    ok = _load(env)
    fields = {k: getattr(ok, k) for k in ConfidenceVectorSettings.model_fields}
    fields["calibrator_ttl_seconds"] = 0
    with pytest.raises(ConfigurationError):
        ConfidenceVectorSettings(**fields)
    with pytest.raises(ConfigurationError):
        Penalties(contradiction=0.0, staleness=0.1, dependency=0.1)
    with pytest.raises(ConfigurationError):
        BootstrapSettings(resamples=0)


def test_unknown_mandatory_dimension_is_rejected(env) -> None:
    env[f"{P}MANDATORY_DIMS_ENTITY"] = "corroboration,not_a_dimension"
    with pytest.raises(ConfigurationError, match="unknown dimension"):
        _load(env)


def test_empty_mandatory_dimensions_are_rejected(env) -> None:
    env[f"{P}MANDATORY_DIMS_ENTITY"] = " , "
    with pytest.raises(ConfigurationError):
        _load(env)


def test_unknown_strategy_is_rejected(env) -> None:
    env[f"{P}PROJECTION_STRATEGY"] = "ensemble"
    with pytest.raises(ConfigurationError, match="PROJECTION_STRATEGY"):
        _load(env)


def test_unknown_variable_and_unknown_secret_key_are_rejected(env) -> None:
    env[f"{P}NOT_A_SETTING"] = "1"
    with pytest.raises(ConfigurationError, match="NOT_A_SETTING"):
        _load(env)
    del env[f"{P}NOT_A_SETTING"]
    with pytest.raises(ConfigurationError, match="NOT_A_SETTING"):
        _load(env, {"not_a_setting": 1})


def test_existing_dag_variables_with_the_vector_prefix_are_not_flagged(env) -> None:
    env[f"{P}WEIGHTS_REF"] = "cv_weights_v1"
    assert _load(env)


class TestStrategyArtefacts:
    def test_rule_only_needs_a_floor_per_mandatory_dimension(self, env) -> None:
        del env[f"{P}RULE_FLOOR_{MANDATORY[0].name}"]
        with pytest.raises(ConfigurationError, match="floor"):
            _load(env)

    def test_monotonic_needs_knots(self, env) -> None:
        env[f"{P}PROJECTION_STRATEGY"] = "monotonic"
        with pytest.raises(ConfigurationError, match="knots"):
            _load(env)

    def test_tree_needs_path_and_depth(self, env) -> None:
        env[f"{P}PROJECTION_STRATEGY"] = "calibrated_tree"
        with pytest.raises(ConfigurationError, match="tree"):
            _load(env)

    def test_bad_knots_file_is_rejected(self, env, tmp_path: Path) -> None:
        env[f"{P}PROJECTION_STRATEGY"] = "linear"
        p = tmp_path / "k.json"
        p.write_text('{"corroboration": [[0.0, 1.0], [1.0, 0.0]]}')
        env[f"{P}KNOTS_PATH"] = str(p)
        with pytest.raises(ConfigurationError, match="monotone"):
            _load(env)
        env[f"{P}KNOTS_PATH"] = str(tmp_path / "absent.json")
        with pytest.raises(ConfigurationError, match="KNOTS_PATH"):
            _load(env)


class TestDeprecatedHoursAlias:
    def test_hours_name_reads_through_as_seconds(self, env, caplog) -> None:
        del env[f"{P}CALIBRATOR_TTL_SECONDS"]
        env["GRAQLE_DAG_CALIBRATOR_TTL_HOURS"] = "2"
        with caplog.at_level(logging.WARNING):
            s = _load(env)
        assert s.calibrator_ttl_seconds == 2 * 3600
        assert any("deprecated" in r.message for r in caplog.records)
        assert s.config_provenance["calibrator_ttl_seconds"] == "ENV"

    def test_both_names_is_ambiguous(self, env) -> None:
        env["GRAQLE_DAG_CALIBRATOR_TTL_HOURS"] = "2"
        with pytest.raises(ConfigurationError, match="both set"):
            _load(env)

    def test_hours_default_does_not_satisfy_the_requirement(self, env) -> None:
        del env[f"{P}CALIBRATOR_TTL_SECONDS"]
        with pytest.raises(ConfigurationError, match="CALIBRATOR_TTL_SECONDS"):
            _load(env)

    def test_hours_from_the_private_file_reads_through(self, env) -> None:
        del env[f"{P}CALIBRATOR_TTL_SECONDS"]
        dag = DagSettings(calibrator_ttl_hours=3)
        s = _load(env, dag=dag)
        assert s.calibrator_ttl_seconds == 3 * 3600
        assert s.config_provenance["calibrator_ttl_seconds"] == "SECRETS_YAML"

    def test_non_numeric_hours_is_rejected(self, env) -> None:
        del env[f"{P}CALIBRATOR_TTL_SECONDS"]
        env["GRAQLE_DAG_CALIBRATOR_TTL_HOURS"] = "soon"
        with pytest.raises(ConfigurationError):
            _load(env)


def test_error_messages_never_echo_values(env) -> None:
    env[f"{P}MAX_DIVERGENCE"] = "7.77777"
    with pytest.raises(ConfigurationError) as err:
        _load(env)
    assert "7.77777" not in str(err.value)


def test_os_environment_is_the_default_source(monkeypatch: pytest.MonkeyPatch, env) -> None:
    dag = DagSettings()  # built before the flag is set: it needs no required values off
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("GRAQLE_DAG_SECRETS_PATH", str(Path(env[f"{P}CALIBRATOR_REGISTRY_PATH"]) / "none.yaml"))
    assert os.environ[FLAG] == "true"
    assert load_confidence_vector_settings(secrets={}, dag=dag).calibrator_ttl_seconds == 100
