"""Licensing tests: keep the user-level quota marker out of the developer's real ~/.graqle."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_user_dir(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("GRAQLE_USER_DIR", str(tmp_path_factory.mktemp("user_graqle")))


@pytest.fixture(autouse=True)
def _clean_meter_env(monkeypatch):
    """TEST-01: start from the default (unset) meter environment.

    GRAQLE_ENFORCE_CAPS / GRAQLE_ENFORCE_GRACE_DAYS left in the shell or by an
    earlier test would otherwise flip the cap/grace tests.
    """
    from graqle.licensing.meter import ENFORCE_ENV, GRACE_ENV

    monkeypatch.delenv(ENFORCE_ENV, raising=False)
    monkeypatch.delenv(GRACE_ENV, raising=False)
