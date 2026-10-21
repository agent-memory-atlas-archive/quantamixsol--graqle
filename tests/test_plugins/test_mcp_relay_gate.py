"""CR-INFRA-02f: hub side of the hybrid relay (/relay/gate, /relay/snapshot). Fail closed."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("httpx")
from starlette.testclient import TestClient  # noqa: E402

from graqle.plugins import mcp_session_state  # noqa: E402
from graqle.plugins.mcp_http_transport import create_app  # noqa: E402


class FakeServer:
    """Stands in for KogniDevServer: lifecycle/plan calls flip the session's gate flags."""

    def __init__(self, governance=None, read_only=False):
        self.read_only = read_only
        self._config = SimpleNamespace(governance=governance)
        self._graph = SimpleNamespace(nodes={"a": 1, "b": 2})
        self._graph_mtime = 100.0
        self.write_reply = json.dumps({"dry_run": True})

    async def _handle_jsonrpc(self, message):
        state = mcp_session_state._current.get()
        name = (message.get("params") or {}).get("name")
        if name == "graq_lifecycle":
            state.session_started = True
        if name == "graq_plan":
            state.plan_active = True
        if "id" not in message:
            return None
        return {"jsonrpc": "2.0", "id": message["id"], "result": {}}

    async def _handle_write(self, args):
        return self.write_reply


GOV = SimpleNamespace(session_gate_enabled=True, plan_mandatory=True, edit_enforcement=False)


def _client(server, tmp_path, token=None):
    app = create_app(server, token=token, allowed_roots=[tmp_path])
    client = TestClient(app)
    headers = {"X-Graqle-Workspace-Root": str(tmp_path)}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers=headers)
    sid = r.headers["mcp-session-id"]
    h = {"Mcp-Session-Id": sid, **({"Authorization": f"Bearer {token}"} if token else {})}
    return client, h


def _call(client, h, name):
    client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": {}}}, headers=h)


def _gate(client, h, tool, arguments=None):
    r = client.post("/relay/gate", json={"tool": tool, "arguments": arguments or {}}, headers=h)
    return r.status_code, r.json()


def test_cg01_and_cg02_are_enforced_per_request_and_follow_the_session(tmp_path):
    client, h = _client(FakeServer(GOV), tmp_path)
    code, answer = _gate(client, h, "graq_bash")
    assert answer["allow"] is False and "CG-01" in answer["reason"]
    _call(client, h, "graq_lifecycle")
    code, answer = _gate(client, h, "graq_bash")
    assert answer["allow"] is False and "CG-02" in answer["reason"]
    _call(client, h, "graq_plan")
    assert _gate(client, h, "graq_bash")[1]["allow"] is True
    assert _gate(client, h, "kogni_git_commit")[1]["allow"] is True  # alias


def test_gates_are_per_session_not_global(tmp_path):
    server = FakeServer(GOV)
    c1, h1 = _client(server, tmp_path)
    c2, h2 = _client(server, tmp_path)
    _call(c1, h1, "graq_lifecycle")
    _call(c1, h1, "graq_plan")
    assert _gate(c1, h1, "graq_bash")[1]["allow"] is True
    assert _gate(c2, h2, "graq_bash")[1]["allow"] is False


def test_read_only_server_and_non_mutating_tools_are_refused(tmp_path):
    client, h = _client(FakeServer(SimpleNamespace(session_gate_enabled=False, plan_mandatory=False, edit_enforcement=False), read_only=True), tmp_path)
    assert _gate(client, h, "graq_bash")[1]["allow"] is False
    client, h = _client(FakeServer(SimpleNamespace(session_gate_enabled=False, plan_mandatory=False, edit_enforcement=False)), tmp_path)
    assert _gate(client, h, "graq_bash")[1]["allow"] is True
    assert _gate(client, h, "graq_read")[1]["allow"] is False  # not a mutating tool: never "allowed" by accident
    assert _gate(client, h, "graq_nonsense")[1]["allow"] is False


def test_unknown_session_malformed_body_and_missing_config_fail_closed(tmp_path):
    client, h = _client(FakeServer(GOV), tmp_path)
    r = client.post("/relay/gate", json={"tool": "graq_bash"}, headers={"Mcp-Session-Id": "nope"})
    assert r.status_code == 404 and r.json()["allow"] is False
    r = client.post("/relay/gate", content=b"not json", headers=h)
    assert r.status_code == 400 and r.json()["allow"] is False
    r = client.post("/relay/gate", json={"tool": 5}, headers=h)
    assert r.status_code == 400
    r = client.post("/relay/gate", json={"arguments": {}}, headers=h)
    assert r.status_code == 400
    server = FakeServer(None)
    server._config = None
    client, h = _client(server, tmp_path)
    assert _gate(client, h, "graq_bash")[1]["allow"] is False


def test_unexpected_error_in_gate_evaluation_denies(tmp_path):
    class Boom(FakeServer):
        @property
        def read_only(self):
            raise RuntimeError("boom")

        @read_only.setter
        def read_only(self, value):
            pass

    client, h = _client(Boom(GOV), tmp_path)
    code, answer = _gate(client, h, "graq_bash")
    assert answer["allow"] is False and "refused" in answer["reason"]


def test_token_is_required_on_the_side_channels(tmp_path):
    client, h = _client(FakeServer(GOV), tmp_path, token="secret")
    anon = {"Mcp-Session-Id": h["Mcp-Session-Id"]}
    assert client.post("/relay/gate", json={"tool": "graq_bash"}, headers=anon).status_code == 401
    assert client.post("/relay/snapshot", json={}, headers=anon).status_code == 401


def test_write_content_scan_of_the_hub_handler_applies(tmp_path):
    gov = SimpleNamespace(session_gate_enabled=False, plan_mandatory=False, edit_enforcement=False)
    server = FakeServer(gov)
    client, h = _client(server, tmp_path)
    args = {"file_path": str(tmp_path / "a.txt"), "content": "x", "dry_run": False}
    assert _gate(client, h, "graq_write", args)[1]["allow"] is True
    server.write_reply = json.dumps({"error": "PATENT_GATE", "message": "blocked"})
    code, answer = _gate(client, h, "graq_write", args)
    assert answer["allow"] is False and "PATENT_GATE" in answer["reason"]
    server.write_reply = "not json"
    assert _gate(client, h, "graq_write", args)[1]["allow"] is False


def test_edit_enforcement_cg03_blocks_overwriting_existing_code(tmp_path):
    gov = SimpleNamespace(session_gate_enabled=False, plan_mandatory=False, edit_enforcement=True)
    client, h = _client(FakeServer(gov), tmp_path)
    code_file = tmp_path / "mod.py"
    code_file.write_text("x = 1\n")
    assert _gate(client, h, "graq_write", {"file_path": str(code_file), "content": "y"})[1]["allow"] is False
    assert _gate(client, h, "graq_write", {"file_path": str(tmp_path / "new.py"), "content": "y"})[1]["allow"] is True
    assert _gate(client, h, "graq_write", {"file_path": str(code_file), "content": "y", "force_overwrite": True})[1]["allow"] is True


def test_snapshot_version_changes_with_the_graph(tmp_path):
    server = FakeServer(GOV)
    client, h = _client(server, tmp_path)
    v1 = client.post("/relay/snapshot", json={}, headers=h).json()
    assert client.post("/relay/snapshot", json={}, headers=h).json() == v1  # stable while unchanged
    server._graph_mtime = 200.0
    v2 = client.post("/relay/snapshot", json={}, headers=h).json()
    assert v2["version"] != v1["version"] and v2["node_count"] == 2
    server._graph.nodes["c"] = 3
    assert client.post("/relay/snapshot", json={}, headers=h).json()["version"] != v2["version"]
    assert len(json.dumps(v2)) < 65536


def test_hub_mode_has_no_side_channel_and_denies():
    class FakeHubObj:
        def has(self, name):
            return True

        async def dispatch(self, project, message):
            return None

    client = TestClient(create_app(hub=FakeHubObj()))
    r = client.post("/relay/gate", json={"tool": "graq_bash"}, headers={"Mcp-Session-Id": "x"})
    assert r.status_code == 403 and r.json()["allow"] is False


def test_real_dev_server_write_tools_are_all_known_to_the_gate():
    from graqle.plugins.mcp_dev_server import _WRITE_TOOLS
    from graqle.plugins.mcp_relay_routing import LOCAL_MUTATING

    assert {f"graq_{n}" for n in LOCAL_MUTATING} <= set(_WRITE_TOOLS)
