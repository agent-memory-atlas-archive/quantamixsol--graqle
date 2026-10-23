"""CR-013 PR-013c: sensitivity report (AC-18)."""

from __future__ import annotations

import json

import pytest

from graqle.assurance.hard_gates import GATE_ORDER, default_registry
from graqle.assurance.sensitivity import REDACTED, sensitivity_report
from graqle.assurance.settings import config_version

from ._builders import HG05_SUB, HG07_SUB, leaks, make_ctx, make_settings

REGISTRY = default_registry()
SETTINGS = make_settings()
FINGERPRINT = config_version(SETTINGS)  # the test-substitute fingerprint
SWEPT = {"HG-01", "HG-03", "HG-05", "HG-07"}


def test_report_covers_all_seven_gates() -> None:
    report = sensitivity_report(REGISTRY, SETTINGS, make_ctx())
    assert tuple(report["gates"]) == GATE_ORDER
    for rule_id in GATE_ORDER:
        entry = report["gates"][rule_id]
        assert isinstance(entry["base_passed"], bool)
        if rule_id in SWEPT:
            assert entry["inputs"] and "note" not in entry
        else:
            assert entry["inputs"] == {} and "note" in entry


def test_default_report_is_redacted_everywhere() -> None:
    report = sensitivity_report(REGISTRY, SETTINGS, make_ctx())
    assert report["redacted"] is True
    blob = json.dumps(report, default=str)
    for secret in (HG05_SUB, HG07_SUB):
        assert not leaks(secret, blob)
    for rule_id in SWEPT:
        for record in report["gates"][rule_id]["inputs"].values():
            assert record["series"] is None
            assert all(t["value"] == REDACTED for t in record["transitions"])
    assert REDACTED in report["markdown"]


def test_each_swept_gate_has_a_transition() -> None:
    report = sensitivity_report(REGISTRY, SETTINGS, make_ctx(risk_level="HIGH"))
    expected = {
        "HG-01": "valid_until_offset_days",
        "HG-03": "risk_tier",
        "HG-05": "poisoning_severity",
        "HG-07": "materiality",
    }
    for rule_id, name in expected.items():
        assert report["gates"][rule_id]["inputs"][name]["transitions"], rule_id


def test_wrong_fingerprint_stays_redacted() -> None:
    other = make_settings(config_salt="another-substitute-salt-0123456789abcdef")
    report = sensitivity_report(REGISTRY, other, make_ctx(), unredacted_fingerprint=FINGERPRINT)
    assert report["redacted"] is True
    assert all(r["series"] is None for g in report["gates"].values() for r in g["inputs"].values())


def test_matching_fingerprint_reveals_the_test_substitute_transitions() -> None:
    report = sensitivity_report(
        REGISTRY, SETTINGS, make_ctx(), steps=101, unredacted_fingerprint=FINGERPRINT
    )
    assert report["redacted"] is False
    hg05 = report["gates"]["HG-05"]["inputs"]["poisoning_severity"]
    assert [t["direction"] for t in hg05["transitions"]] == ["PASS->FAIL"]
    assert hg05["transitions"][0]["value"] == pytest.approx(HG05_SUB, abs=0.011)
    hg07 = report["gates"]["HG-07"]["inputs"]["materiality"]
    assert hg07["transitions"][0]["value"] == pytest.approx(HG07_SUB, abs=0.011)
    assert hg05["series"][0] == (0.0, True) and hg05["series"][-1][1] is False


def test_fewer_than_two_steps_is_rejected() -> None:
    with pytest.raises(ValueError):
        sensitivity_report(REGISTRY, SETTINGS, make_ctx(), steps=1)


def test_report_is_deterministic() -> None:
    a = sensitivity_report(REGISTRY, SETTINGS, make_ctx())
    b = sensitivity_report(REGISTRY, SETTINGS, make_ctx())
    assert a == b
