"""RoutingSettings: required values, no placeholder fallback, fail closed (CR-015 PR-015b)."""

from __future__ import annotations

import pytest

from graqle.assurance.gate import ImpactTier
from graqle.assurance.routing_settings import RoutingSettings
from graqle.assurance.settings import ConfigurationError

_P = "GRAQLE_DAG_"


def _env() -> dict[str, str]:
    env = {f"{_P}TIER_AUTOMATION_MAX": "high"}
    for t in ImpactTier:
        env[f"{_P}TRAJECTORY_FLOOR_{t.value}"] = "0.25"
        env[f"{_P}RESIDUAL_RISK_BUDGET_{t.value}"] = "0.75"
    return env


def test_loads_every_value_from_the_environment() -> None:
    s = RoutingSettings.from_env(_env())
    assert s.tier_automation_max is ImpactTier.HIGH and s.residual_risk_combinator == "max"
    assert set(s.trajectory_floor) == set(ImpactTier) == set(s.residual_risk_budget)


@pytest.mark.parametrize("missing", [f"{_P}TIER_AUTOMATION_MAX", f"{_P}TRAJECTORY_FLOOR_HIGH", f"{_P}RESIDUAL_RISK_BUDGET_LOW"])
def test_any_absent_required_value_fails_closed(missing: str) -> None:
    env = _env()
    del env[missing]
    with pytest.raises(ConfigurationError, match=missing):
        RoutingSettings.from_env(env)


@pytest.mark.parametrize("bad", ["0", "1", "-0.5", "nan", "inf", "abc", "1.5"])
def test_floor_and_budget_must_lie_strictly_inside_unit_interval(bad: str) -> None:
    for name in (f"{_P}TRAJECTORY_FLOOR_LOW", f"{_P}RESIDUAL_RISK_BUDGET_CRITICAL"):
        env = _env()
        env[name] = bad
        with pytest.raises(ConfigurationError):
            RoutingSettings.from_env(env)


def test_unknown_ceiling_or_combinator_rejected() -> None:
    env = _env()
    env[f"{_P}TIER_AUTOMATION_MAX"] = "extreme"
    with pytest.raises(ConfigurationError):
        RoutingSettings.from_env(env)
    env = _env()
    env[f"{_P}RESIDUAL_RISK_COMBINATOR"] = "mean"
    with pytest.raises(ConfigurationError):
        RoutingSettings.from_env(env)


def test_private_combinator_is_selectable() -> None:
    env = _env()
    env[f"{_P}RESIDUAL_RISK_COMBINATOR"] = "private"
    assert RoutingSettings.from_env(env).residual_risk_combinator == "private"
