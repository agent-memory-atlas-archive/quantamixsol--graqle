"""Licensing tests: keep the user-level quota marker out of the developer's real ~/.graqle."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_user_dir(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("GRAQLE_USER_DIR", str(tmp_path_factory.mktemp("user_graqle")))
