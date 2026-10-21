"""CR-LIC-01 — GRAQLE_ENFORCE_CAPS is not a free-tier bypass.

"Outside pytest" is simulated by patching ``caps.under_pytest`` to False; ``Path.home`` is
redirected so the user-level marker never touches the developer's real home.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from graqle.licensing import caps
from graqle.licensing import meter as meter_mod
from graqle.licensing.reasoning_quota import (
    FREE_REASONS_PER_MONTH,
    QUOTA_FILENAME,
    ReasoningQuota,
    ReasoningQuotaExceeded,
    quota_enforcement_enabled,
)


@pytest.fixture
def prod(monkeypatch, tmp_path):
    """Free tier, NOT under pytest, flag set to opt out."""
    monkeypatch.setattr(caps, "paid_tier", lambda: False)
    monkeypatch.setattr(caps, "under_pytest", lambda: False)
    monkeypatch.setattr(caps, "_notice_shown", False)
    monkeypatch.delenv("GRAQLE_USER_DIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setenv("GRAQLE_ENFORCE_CAPS", "0")
    return home


# -- AC-1 / AC-2 ------------------------------------------------------------


def test_free_flag_zero_outside_pytest_still_blocks_reasoning(prod, tmp_path):
    assert quota_enforcement_enabled() is True
    q = ReasoningQuota(tmp_path / "proj" / ".graqle")
    for _ in range(FREE_REASONS_PER_MONTH):
        q.check_and_record()
    with pytest.raises(ReasoningQuotaExceeded):
        q.check_and_record()


def test_free_flag_zero_outside_pytest_still_enforces_node_cap(prod):
    assert meter_mod.enforcement_enabled() is True


def test_notice_is_one_line_and_logged_once(prod, caplog):
    with caplog.at_level("WARNING", logger="graqle.licensing.caps"):
        caps.caps_enforced()
        caps.caps_enforced()
    assert len([r for r in caplog.records if "ignored" in r.getMessage()]) == 1


def test_paid_tier_flag_is_noop(prod, monkeypatch, tmp_path):
    monkeypatch.setattr(caps, "paid_tier", lambda: True)
    monkeypatch.setattr("graqle.licensing.reasoning_quota._paid_tier", lambda: True)
    assert quota_enforcement_enabled() is False
    q = ReasoningQuota(tmp_path / ".graqle")
    for _ in range(FREE_REASONS_PER_MONTH + 5):
        q.check_and_record()  # never raises


def test_under_pytest_flag_still_works(monkeypatch):
    monkeypatch.setattr(caps, "paid_tier", lambda: False)
    monkeypatch.setenv("GRAQLE_ENFORCE_CAPS", "0")
    assert caps.under_pytest() is True
    assert quota_enforcement_enabled() is False
    assert meter_mod.enforcement_enabled() is False


def test_env_cannot_fake_pytest(prod, monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "fake::call")
    assert caps.caps_enforced() is True


def test_flag_unset_or_truthy_enforces(prod, monkeypatch):
    monkeypatch.delenv("GRAQLE_ENFORCE_CAPS")
    assert caps.caps_enforced() is True
    monkeypatch.setenv("GRAQLE_ENFORCE_CAPS", "1")
    assert caps.caps_enforced() is True


# -- AC-3 -------------------------------------------------------------------


def test_deleting_quota_file_is_not_a_reset(prod, tmp_path):
    d = tmp_path / "proj" / ".graqle"
    q = ReasoningQuota(d)
    for _ in range(FREE_REASONS_PER_MONTH):
        q.check_and_record()
    (d / QUOTA_FILENAME).unlink()
    with pytest.raises(ReasoningQuotaExceeded):
        ReasoningQuota(d).check_and_record()


def test_corrupt_quota_file_resumes_from_marker(prod, tmp_path):
    d = tmp_path / "proj" / ".graqle"
    q = ReasoningQuota(d)
    for _ in range(3):
        q.check_and_record()
    (d / QUOTA_FILENAME).write_text("{not json", encoding="utf-8")
    assert ReasoningQuota(d).check_and_record().used == 4


def test_higher_of_two_wins(prod, tmp_path):
    d = tmp_path / "proj" / ".graqle"
    q = ReasoningQuota(d)
    q.check_and_record()
    month = q._month()
    (d / QUOTA_FILENAME).write_text(json.dumps({month: 7}), encoding="utf-8")
    assert ReasoningQuota(d).check_and_record().used == 8


def test_marker_unavailable_keeps_enforcing(prod, tmp_path, monkeypatch):
    monkeypatch.setattr(ReasoningQuota, "_marker_path", lambda self: None)
    q = ReasoningQuota(tmp_path / "proj" / ".graqle")
    for _ in range(FREE_REASONS_PER_MONTH):
        q.check_and_record()
    with pytest.raises(ReasoningQuotaExceeded):
        q.check_and_record()


def test_marker_write_is_atomic_no_tmp_left(prod, tmp_path):
    q = ReasoningQuota(tmp_path / "proj" / ".graqle")
    q.check_and_record()
    leftovers = [p.name for p in (prod / ".graqle").iterdir() if p.suffix == ".tmp"]
    assert leftovers == []
    assert (prod / ".graqle" / "reasoning_quota_marker.json").exists()


def test_projects_do_not_share_a_marker_count(prod, tmp_path):
    a = ReasoningQuota(tmp_path / "a" / ".graqle")
    for _ in range(FREE_REASONS_PER_MONTH):
        a.check_and_record()
    assert ReasoningQuota(tmp_path / "b" / ".graqle").check_and_record().used == 1


# -- AC-4 -------------------------------------------------------------------


def _fresh_free_manager(monkeypatch, tmp_path):
    import graqle.licensing.manager as mgr

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GRAQLE_LICENSE_KEY", raising=False)
    monkeypatch.setattr(mgr, "_manager", None)
    return mgr


def test_hub_gate_ignores_flag_and_quota_file(prod, tmp_path, monkeypatch):
    mgr = _fresh_free_manager(monkeypatch, tmp_path)
    ReasoningQuota(tmp_path / ".graqle").check_and_record()
    try:
        # No paid-licence fixture: the free tier must not get the feature.
        assert mgr.has_feature("multi_project_hub") is False
        monkeypatch.setenv("GRAQLE_ENFORCE_CAPS", "1")
        assert mgr.has_feature("multi_project_hub") is False
    finally:
        monkeypatch.setattr(mgr, "_manager", None)


def test_hub_gate_expired_licence_still_denied(prod, tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    import graqle.licensing.manager as mgr

    lic = mgr.License(
        tier=mgr.LicenseTier.ENTERPRISE,
        holder="x",
        email="x@example.invalid",
        issued_at=datetime.now(timezone.utc) - timedelta(days=800),
        expires_at=datetime.now(timezone.utc) - timedelta(days=400),
        features=["multi_project_hub"],
    )
    manager = mgr.LicenseManager.__new__(mgr.LicenseManager)
    manager._license = lic
    monkeypatch.setattr(mgr, "_manager", manager)
    try:
        assert mgr.has_feature("multi_project_hub") is False
    finally:
        monkeypatch.setattr(mgr, "_manager", None)


# -- AC-5 -------------------------------------------------------------------


def test_doctor_caps_line_free_never_off(prod):
    from graqle.cli.commands.doctor import _check_caps

    status, _, detail = _check_caps()
    assert detail == "caps: enforced"
    assert "off" not in detail


def test_doctor_caps_line_paid(monkeypatch):
    from graqle.cli.commands.doctor import _check_caps

    monkeypatch.setattr(caps, "paid_tier", lambda: True)
    assert _check_caps()[2] == "caps: off (paid licence)"
