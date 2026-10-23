"""CR-015 PR-015c: ReplanSettings loader fails closed (GRAQLE_DAG_MAX_RETRY_BUDGET)."""

from __future__ import annotations

import pytest

from graqle.assurance.replan import ReplanController
from graqle.assurance.replan_settings import ReplanSettings
from graqle.assurance.settings import ConfigurationError

NAME = "GRAQLE_DAG_MAX_RETRY_BUDGET"


def test_missing_budget_raises() -> None:
    with pytest.raises(ConfigurationError, match=NAME):
        ReplanSettings.from_env({})


@pytest.mark.parametrize("raw", ["0", "-1", "abc", "1.5", "  "])
def test_unusable_budget_raises(raw: str) -> None:
    with pytest.raises(ConfigurationError):
        ReplanSettings.from_env({NAME: raw})


def test_direct_construction_rejects_zero_and_bool() -> None:
    for bad in (0, -3, True):
        with pytest.raises(ConfigurationError):
            ReplanSettings(max_retry_budget=bad)


def test_valid_budget_loads_and_feeds_controller() -> None:
    settings = ReplanSettings.from_env({NAME: " 7 "})
    assert settings.max_retry_budget == 7
    ReplanController(settings.max_retry_budget)


def test_reads_process_environment_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(NAME, "3")
    assert ReplanSettings.from_env().max_retry_budget == 3
    monkeypatch.delenv(NAME)
    with pytest.raises(ConfigurationError):
        ReplanSettings.from_env()
