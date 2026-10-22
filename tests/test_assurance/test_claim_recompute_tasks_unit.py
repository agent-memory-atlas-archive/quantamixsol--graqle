"""PR #441 B-1/M-1: claim_recompute_tasks builds its claim token without a live server."""

from __future__ import annotations

import pytest

from .test_write_collision import ScriptedDriver, _connector


def _capturing(driver: ScriptedDriver, sink: list[dict]) -> None:
    original = driver.run

    def run(query, **params):
        sink.append(params)
        return original(query, **params)

    driver.run = run  # type: ignore[method-assign]


def test_claim_builds_a_hex_token_and_returns_the_claimed_rows():
    driver = ScriptedDriver({"SET t.claim_token": [[{"props": {"task_id": "t1", "state": "RUNNING"}}]]})
    seen: list[dict] = []
    _capturing(driver, seen)
    rows = _connector(driver).claim_recompute_tasks(3)
    assert rows == [{"task_id": "t1", "state": "RUNNING"}]
    token = seen[0]["token"]
    assert isinstance(token, str) and len(token) == 16 and int(token, 16) >= 0
    assert seen[0]["n"] == 3


def test_each_claim_uses_a_fresh_token():
    driver = ScriptedDriver({"SET t.claim_token": [[]]})
    seen: list[dict] = []
    _capturing(driver, seen)
    conn = _connector(driver)
    conn.claim_recompute_tasks(1)
    conn.claim_recompute_tasks(1)
    assert seen[0]["token"] != seen[1]["token"]


@pytest.mark.parametrize("bad", [0, -1, True, "2", None])
def test_invalid_batch_size_is_refused_before_any_statement(bad):
    driver = ScriptedDriver({})
    with pytest.raises(ValueError):
        _connector(driver).claim_recompute_tasks(bad)  # type: ignore[arg-type]
    assert driver.statements == []
