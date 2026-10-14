"""CR-INFRA-02 PR-a: `graq mcp serve` transport flag (AC 1 stdio default, AC 4 refusal)."""

from __future__ import annotations

import graqle.plugins.mcp_dev_server as dev
import graqle.plugins.mcp_http_transport as ht
from typer.testing import CliRunner

from graqle.cli.main import app

runner = CliRunner()


class _StubServer:
    stdio_ran = False

    def __init__(self, config_path="graqle.yaml", read_only=False, **_kw) -> None:
        self.config_path = config_path

    async def run_stdio(self) -> None:
        type(self).stdio_ran = True


def test_default_transport_is_stdio_and_never_touches_http(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dev, "KogniDevServer", _StubServer)
    monkeypatch.setattr(ht, "run_http", lambda *a, **k: (_ for _ in ()).throw(AssertionError("http used")))
    _StubServer.stdio_ran = False
    result = runner.invoke(app, ["mcp", "serve"])
    assert result.exit_code == 0, result.output
    assert _StubServer.stdio_ran is True


def test_http_non_loopback_without_token_refuses_before_loading_graph(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(ht.DEFAULT_TOKEN_ENV, raising=False)

    def _boom(*a, **k):
        raise AssertionError("graph server constructed before auth check")

    monkeypatch.setattr(dev, "KogniDevServer", _boom)
    result = runner.invoke(app, ["mcp", "serve", "--transport", "http", "--host", "0.0.0.0"])
    assert result.exit_code == 2


def test_http_loopback_dispatches_to_run_http(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(ht.DEFAULT_TOKEN_ENV, raising=False)
    monkeypatch.setattr(dev, "KogniDevServer", _StubServer)
    seen = {}
    monkeypatch.setattr(ht, "run_http", lambda server, host, port: seen.update(host=host, port=port))
    result = runner.invoke(app, ["mcp", "serve", "--transport", "http", "--port", "9123"])
    assert result.exit_code == 0, result.output
    assert seen == {"host": "127.0.0.1", "port": 9123}


def test_unknown_transport_rejected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["mcp", "serve", "--transport", "carrier-pigeon"])
    assert result.exit_code == 2
