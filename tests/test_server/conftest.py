"""Server test defaults.

SEC-01: the server now refuses to start without an API key unless the explicit
loopback-only dev opt-in is set. Tests that build the app in-process without a
key declare that opt-in here; test_sec01_auth_failclosed.py clears it again to
prove the refusal paths.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _unauthenticated_dev_optin(monkeypatch):
    monkeypatch.setenv("GRAQLE_ALLOW_UNAUTHENTICATED_DEV", "1")
    monkeypatch.setenv("GRAQLE_SERVE_HOST", "127.0.0.1")
