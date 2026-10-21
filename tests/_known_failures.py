"""TEST-01: tracked known-failures list.

``tests/known_failures.json`` lists environment-dependent tests (nodeid +
reason + owner). Listed tests still run; a failure is reported as xfail with
the recorded reason instead of failing the run. Fail closed: a malformed list
or an entry missing nodeid/reason/owner aborts collection, and any failing test
that is not listed fails as usual.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

KNOWN_FAILURES_PATH = Path(__file__).with_name("known_failures.json")
REQUIRED_FIELDS = ("nodeid", "reason", "owner")


def load_known_failures() -> dict[str, dict]:
    data = json.loads(KNOWN_FAILURES_PATH.read_text(encoding="utf-8"))
    entries = data["known_failures"]
    result: dict[str, dict] = {}
    for entry in entries:
        missing = [f for f in REQUIRED_FIELDS if not str(entry.get(f, "")).strip()]
        if missing:
            raise pytest.UsageError(
                f"{KNOWN_FAILURES_PATH.name}: entry {entry!r} missing {missing}"
            )
        result[entry["nodeid"]] = entry
    return result


def pytest_collection_modifyitems(config, items):
    known = load_known_failures()
    for item in items:
        entry = known.get(item.nodeid)
        if entry is not None:
            item.add_marker(
                pytest.mark.xfail(
                    reason=f"known failure (owner {entry['owner']}): {entry['reason']}",
                    strict=False,
                )
            )
