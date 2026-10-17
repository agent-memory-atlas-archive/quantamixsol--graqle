"""CR-INFRA-02 PR-c: thin stdio relay (AC5 helper checks, AC6)."""

from __future__ import annotations

import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time

import pytest

from graqle.plugins.mcp_relay import Relay, RelayConfigError, normalise_url, run_relay


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _FakeServer:
    """Stands in for KogniDevServer: echoes the method and the bound session."""

    async def _handle_jsonrpc(self, message):
        if "id" not in message:
            return None
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"method": message["method"]}}


@pytest.fixture()
def live_server():
    import uvicorn

    from graqle.plugins.mcp_http_transport import create_app

    port = _free_port()
    config = uvicorn.Config(create_app(_FakeServer()), host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _run(url: str, *messages: dict) -> list[dict]:
    out = io.StringIO()
    run_relay(url, stdin=io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), stdout=out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_normalise_url_adds_mcp_path_and_rejects_non_http():
    assert normalise_url("http://127.0.0.1:9") == "http://127.0.0.1:9/mcp"
    assert normalise_url("http://h:9/mcp/") == "http://h:9/mcp"
    with pytest.raises(RelayConfigError):
        normalise_url("file:///etc/passwd")


def test_token_refused_over_plain_http_to_non_loopback():
    with pytest.raises(RelayConfigError):
        Relay("http://example.com:9", token="t")
    Relay("http://127.0.0.1:9", token="t")  # loopback is fine


def test_relays_to_live_http_server_with_session(live_server):
    replies = _run(
        live_server,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},  # 202, no reply line
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[1]["result"] == {"method": "tools/list"}


def test_ac6_server_down_gives_clear_error(monkeypatch):
    port = _free_port()  # nothing listening
    replies = _run(
        f"http://127.0.0.1:{port}",
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "graq_inspect"}},
    )
    assert replies[0]["error"]["code"] == -32003
    assert "unreachable" in replies[0]["error"]["message"]
    assert replies[1]["result"]["isError"] is True
    assert "No local graph was loaded" in replies[1]["result"]["content"][0]["text"]


def test_ac6_server_down_constructs_no_server_and_loads_no_graph(monkeypatch):
    from graqle.core.graph import Graqle
    from graqle.plugins.mcp_dev_server import KogniDevServer

    def _boom(*a, **k):
        raise AssertionError("relay must not build a server or load a graph")

    monkeypatch.setattr(KogniDevServer, "__init__", _boom)
    for loader in ("from_json", "from_neo4j", "from_networkx"):
        monkeypatch.setattr(Graqle, loader, _boom)
    replies = _run(f"http://127.0.0.1:{_free_port()}", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert replies[0]["error"]["code"] == -32003


def test_ac6_relay_imports_no_ml_stack():
    code = (
        "import sys, io;"
        "from graqle.plugins.mcp_relay import run_relay;"
        "run_relay('http://127.0.0.1:1', stdin=io.StringIO('{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\\n'), stdout=io.StringIO());"
        "bad=[m for m in ('torch','sentence_transformers','neo4j') if m in sys.modules];"
        "print(bad)"
    )
    import graqle

    root = str(pathlib.Path(graqle.__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": root}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


def test_auth_failure_is_reported_not_passed_through(live_server, monkeypatch):
    # server without token accepts; a bad HTTP status must surface as an error reply
    replies = _run(live_server + "/nope", {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert "error" in replies[0] and "HTTP 404" in replies[0]["error"]["message"]


def test_parse_error_and_non_object_get_error_replies():
    out = io.StringIO()
    run_relay("http://127.0.0.1:1", stdin=io.StringIO("not json\n[1]\n"), stdout=out)
    codes = [json.loads(line)["error"]["code"] for line in out.getvalue().splitlines()]
    assert codes == [-32700, -32600]
