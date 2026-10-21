"""TEST-01: the tracked known-failures list is well-formed and fails closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import _known_failures as kf


def test_every_entry_has_nodeid_reason_owner():
    entries = kf.load_known_failures()
    assert entries
    for nodeid, entry in entries.items():
        assert "::" in nodeid
        assert entry["reason"].strip() and entry["owner"].strip()


def test_entry_missing_owner_aborts_collection(tmp_path, monkeypatch):
    bad = tmp_path / "known_failures.json"
    bad.write_text(
        json.dumps({"known_failures": [{"nodeid": "t.py::x", "reason": "r"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(kf, "KNOWN_FAILURES_PATH", bad)
    with pytest.raises(pytest.UsageError):
        kf.load_known_failures()


def test_listed_failure_runs_as_xfail_and_unlisted_still_fails(pytester, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("PYTHONPATH", str(repo_root))
    pytester.makepyfile(
        test_sample="""
        def test_listed():
            assert False

        def test_unlisted():
            assert False
        """
    )
    pytester.makeconftest(
        """
        import json, pathlib
        from tests import _known_failures as kf
        kf.KNOWN_FAILURES_PATH = pathlib.Path("kf.json")
        from tests._known_failures import pytest_collection_modifyitems  # noqa: F401
        """
    )
    (pytester.path / "kf.json").write_text(
        json.dumps(
            {
                "known_failures": [
                    {
                        "nodeid": "test_sample.py::test_listed",
                        "reason": "env",
                        "owner": "me",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(failed=1, xfailed=1)
