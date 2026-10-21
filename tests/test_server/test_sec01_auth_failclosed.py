"""SEC-01 finding 3: no API key -> the server fails closed unless the explicit,
loopback-only dev opt-in is set."""

from __future__ import annotations

import logging

import pytest

from graqle.server import middleware as mw


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("COGNIGRAPH_API_KEY", "COGNIGRAPH_API_KEYS", mw.UNAUTH_DEV_ENV, mw.SERVE_HOST_ENV):
        monkeypatch.delenv(var, raising=False)


class _App:
    def __init__(self):
        self.added = []

    def add_middleware(self, cls, **kw):
        self.added.append(cls)


def test_no_key_no_optin_refuses():
    with pytest.raises(mw.AuthConfigError):
        mw.setup_auth_middleware(_App())


def test_no_key_optin_without_known_host_refuses(monkeypatch):
    monkeypatch.setenv(mw.UNAUTH_DEV_ENV, "1")
    with pytest.raises(mw.AuthConfigError):
        mw.setup_auth_middleware(_App())


@pytest.mark.parametrize("host", ["0.0.0.0", "10.1.2.3", "example.com", "::"])
def test_optin_with_non_loopback_bind_refuses(monkeypatch, host):
    monkeypatch.setenv(mw.UNAUTH_DEV_ENV, "1")
    monkeypatch.setenv(mw.SERVE_HOST_ENV, host)
    with pytest.raises(mw.AuthConfigError):
        mw.setup_auth_middleware(_App())


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_optin_on_loopback_serves_with_warning(monkeypatch, caplog, host):
    monkeypatch.setenv(mw.UNAUTH_DEV_ENV, "1")
    monkeypatch.setenv(mw.SERVE_HOST_ENV, host)
    app = _App()
    with caplog.at_level(logging.WARNING, logger="graqle.server.middleware"):
        mw.setup_auth_middleware(app)  # does not raise
    assert any("AUTHENTICATION DISABLED" in r.message for r in caplog.records)
    assert app.added == []  # no auth middleware installed, as before


def test_configured_key_installs_middleware_unchanged(monkeypatch):
    monkeypatch.setenv("COGNIGRAPH_API_KEY", "secret")
    app = _App()
    mw.setup_auth_middleware(app)
    assert len(app.added) == 1
