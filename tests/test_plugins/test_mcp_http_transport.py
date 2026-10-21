"""CR-INFRA-02 PR-a: HTTP transport for the MCP dev server (AC 4; AC 2 transport part)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from graqle.plugins import mcp_http_transport as t
from tests.test_plugins.ws_helpers import ws_client


class _FakeServer:
    """Stands in for KogniDevServer: only the JSON-RPC entry point is used."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def _handle_jsonrpc(self, request: dict):
        self.calls.append(request)
        if request.get("method") == "boom":
            raise RuntimeError("secret internals")
        if request.get("id") is None:
            return None
        return {"jsonrpc": "2.0", "id": request["id"], "result": {"echo": request["method"]}}


def _init(client: TestClient, **kw):
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, **kw)


def test_loopback_detection():
    assert t.is_loopback_host("127.0.0.1")
    assert t.is_loopback_host("::1")
    assert t.is_loopback_host("localhost")
    assert not t.is_loopback_host("0.0.0.0")
    assert not t.is_loopback_host("192.168.1.5")
    assert not t.is_loopback_host("example.com")


def test_non_loopback_without_token_refuses(monkeypatch):
    monkeypatch.delenv(t.DEFAULT_TOKEN_ENV, raising=False)
    with pytest.raises(t.HttpTransportConfigError):
        t.resolve_auth_token("0.0.0.0")


def test_run_http_refuses_before_binding(monkeypatch):
    monkeypatch.delenv(t.DEFAULT_TOKEN_ENV, raising=False)
    with pytest.raises(t.HttpTransportConfigError):
        t.run_http(_FakeServer(), host="0.0.0.0", port=0)


def test_non_loopback_with_token_ok_and_loopback_needs_none(monkeypatch):
    monkeypatch.setenv("MY_TOK", "s3cret")
    assert t.resolve_auth_token("0.0.0.0", "MY_TOK") == "s3cret"
    monkeypatch.delenv(t.DEFAULT_TOKEN_ENV, raising=False)
    assert t.resolve_auth_token("127.0.0.1") is None


def test_request_without_or_with_wrong_token_rejected():
    server = _FakeServer()
    client = ws_client(server, host="0.0.0.0", token="s3cret")
    assert _init(client).status_code == 401
    assert _init(client, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert _init(client, headers={"Authorization": "Basic s3cret"}).status_code == 401
    assert server.calls == []
    assert _init(client, headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_session_lifecycle_and_two_concurrent_sessions():
    server = _FakeServer()
    client = ws_client(server)
    a = _init(client).headers[t.SESSION_HEADER]
    b = _init(client).headers[t.SESSION_HEADER]
    assert a != b
    for sid in (a, b):
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                        headers={t.SESSION_HEADER: sid})
        assert r.status_code == 200 and r.json()["result"] == {"echo": "tools/list"}
    assert client.delete("/mcp", headers={t.SESSION_HEADER: a}).status_code == 200
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
                    headers={t.SESSION_HEADER: a})
    assert r.status_code == 404


def test_missing_or_unknown_session_rejected_and_not_dispatched():
    server = _FakeServer()
    client = ws_client(server)
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    assert client.post("/mcp", json=body).status_code == 400
    assert client.post("/mcp", json=body, headers={t.SESSION_HEADER: "nope"}).status_code == 404
    assert server.calls == []


def test_notification_gets_202():
    client = ws_client(_FakeServer())
    sid = _init(client).headers[t.SESSION_HEADER]
    r = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers={t.SESSION_HEADER: sid})
    assert r.status_code == 202


def test_bad_json_and_batch_rejected():
    client = ws_client(_FakeServer())
    assert client.post("/mcp", content=b"{not json").status_code == 400
    assert client.post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "initialize"}]).status_code == 400


def test_handler_exception_fails_closed_without_leaking():
    client = ws_client(_FakeServer())
    sid = _init(client).headers[t.SESSION_HEADER]
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "boom"},
                    headers={t.SESSION_HEADER: sid})
    assert r.status_code == 500
    assert "secret internals" not in r.text


def test_foreign_origin_rejected_on_loopback_bind():
    client = ws_client(_FakeServer())
    assert _init(client, headers={"Origin": "https://evil.example"}).status_code == 403
    assert _init(client, headers={"Origin": "http://localhost:3000"}).status_code == 200


def test_get_not_allowed():
    client = ws_client(_FakeServer())
    assert client.get("/mcp").status_code == 405
