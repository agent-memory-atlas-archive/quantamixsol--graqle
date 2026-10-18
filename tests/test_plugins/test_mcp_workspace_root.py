"""CR-INFRA-02e: per-session workspace root for the shared HTTP MCP server.

Covers AC1-AC7 against a real ``KogniDevServer`` behind the real HTTP app.
AC8 (live smoke with two relays) is in scripts/smoke_cr_infra_02e_output.md.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import re
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from graqle.plugins import mcp_http_transport as t
from graqle.plugins import mcp_session_state as ss
from graqle.plugins.mcp_dev_server import KogniDevServer
from graqle.plugins.mcp_workspace import (
    WORKSPACE_HEADER,
    WorkspaceError,
    confine_arguments,
    encode_root,
    parse_allowed_roots,
)


def _server() -> KogniDevServer:
    s = KogniDevServer(config_path=None)
    s._config = SimpleNamespace(governance=SimpleNamespace(session_gate_enabled=True, plan_mandatory=True))
    return s


def _init(client: TestClient, root: Path, **kw):
    headers = {WORKSPACE_HEADER: encode_root(str(root)), **kw.pop("headers", {})}
    return client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )


def _open(client: TestClient, root: Path) -> dict[str, str]:
    r = _init(client, root)
    assert r.status_code == 200, r.text
    h = {t.SESSION_HEADER: r.headers[t.SESSION_HEADER], WORKSPACE_HEADER: encode_root(str(root))}
    _call(client, h, "graq_lifecycle", {"event": "session_start"})
    _call(client, h, "graq_plan", {"goal": "x", "dry_run": True})
    return h


def _raw_call(client: TestClient, headers: dict[str, str], name: str, args: dict) -> dict:
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}}
    return client.post("/mcp", headers=headers, json=body).json()["result"]


def _call(client: TestClient, headers: dict[str, str], name: str, args: dict) -> dict:
    text = _raw_call(client, headers, name, args)["content"][0]["text"]
    try:
        return json.loads(text)
    except ValueError:
        return {"error": text}


@pytest.fixture
def roots(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    return a.resolve(), b.resolve()


@pytest.fixture
def client(tmp_path):
    return TestClient(t.create_app(_server(), allowed_roots=[tmp_path.resolve()]))


# AC1 -----------------------------------------------------------------------
def test_two_sessions_write_only_into_their_own_root(client, roots):
    a, b = roots
    ha, hb = _open(client, a), _open(client, b)
    assert _call(client, ha, "graq_write", {"file_path": "fa.txt", "content": "A", "dry_run": False})["written"]
    assert _call(client, hb, "graq_write", {"file_path": "fb.txt", "content": "B", "dry_run": False})["written"]
    assert (a / "fa.txt").read_text() == "A" and not (a / "fb.txt").exists()
    assert (b / "fb.txt").read_text() == "B" and not (b / "fa.txt").exists()

    assert "A" in _call(client, ha, "graq_read", {"file_path": "fa.txt"})["content"]
    assert "error" in _call(client, hb, "graq_read", {"file_path": "fa.txt"}) or not _call(
        client, hb, "graq_read", {"file_path": "fa.txt"}
    ).get("content")
    seen_b = json.dumps(_call(client, hb, "graq_glob", {"pattern": "*.txt"}))
    assert "fb.txt" in seen_b and "fa.txt" not in seen_b


def test_graq_edit_lands_in_own_root(client, roots, monkeypatch):
    # graq_edit is plan-gated (team+); pin a team plan so CI (free plan) tests the root, not the licence.
    import graqle.cloud.credentials as creds_mod

    monkeypatch.setattr(creds_mod, "load_credentials", lambda *a, **k: SimpleNamespace(plan="team"))
    a, b = roots
    (a / "e.txt").write_text("one\n")
    (b / "e.txt").write_text("one\n")
    ha = _open(client, a)
    res = _call(client, ha, "graq_edit", {
        "file_path": "e.txt", "strategy": "literal", "old_content": "one", "new_content": "two",
        "dry_run": False,
    })
    assert res.get("success") is True, res
    assert (a / "e.txt").read_text() == "two\n"
    assert (b / "e.txt").read_text() == "one\n"


# AC2 -----------------------------------------------------------------------
def test_root_outside_allow_list_refused(tmp_path):
    allowed = tmp_path / "ok"
    allowed.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    c = TestClient(t.create_app(_server(), allowed_roots=[allowed.resolve()]))
    assert _init(c, other).status_code == 403
    assert _init(c, allowed).status_code == 200


def test_symlink_root_resolved_before_allow_list_check(tmp_path):
    allowed = tmp_path / "ok"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (allowed / "link").symlink_to(outside)
    c = TestClient(t.create_app(_server(), allowed_roots=[allowed.resolve()]))
    assert _init(c, allowed / "link").status_code == 403


def test_invalid_allow_list_entry_fails(tmp_path):
    with pytest.raises(WorkspaceError):
        parse_allowed_roots(str(tmp_path / "missing"))
    with pytest.raises(WorkspaceError):
        parse_allowed_roots("")
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(WorkspaceError):
        parse_allowed_roots(str(f))
    assert parse_allowed_roots(f"{tmp_path},{tmp_path}") == [tmp_path.resolve()] * 2


def test_shared_server_requires_allowed_roots():
    with pytest.raises(t.HttpTransportConfigError):
        t.create_app(_server())
    with pytest.raises(t.HttpTransportConfigError):
        t.create_app(_server(), allowed_roots=[])


def test_initialize_without_root_refused(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 403


# AC3 -----------------------------------------------------------------------
def test_escape_attempts_refused(client, roots, tmp_path):
    a, _ = roots
    secret = tmp_path / "secret.txt"
    secret.write_text("S")
    (a / "link").symlink_to(secret)
    (a / "dirlink").symlink_to(tmp_path)
    h = _open(client, a)
    for args in (
        {"file_path": "../secret.txt"},
        {"file_path": str(secret)},
        {"file_path": "link"},
        {"file_path": "dirlink/secret.txt"},
    ):
        for tool in ("graq_read", "graq_write", "graq_edit"):
            res = _raw_call(client, h, tool, {**args, "content": "x", "dry_run": False})
            assert res["isError"] is True, (tool, args)
    assert secret.read_text() == "S"
    assert _raw_call(client, h, "graq_bash", {"command": "true", "cwd": ".."})["isError"] is True
    assert _raw_call(client, h, "graq_glob", {"pattern": "*", "path": str(tmp_path)})["isError"] is True


def test_symlink_swapped_after_bind_is_caught_per_call(client, roots, tmp_path):
    a, _ = roots
    h = _open(client, a)
    target = a / "later"
    assert _call(client, h, "graq_write", {"file_path": "later", "content": "ok", "dry_run": False})["written"]
    target.unlink()
    outside = tmp_path / "outside.txt"
    outside.write_text("O")
    target.symlink_to(outside)
    assert _raw_call(client, h, "graq_read", {"file_path": "later"})["isError"] is True


def test_confine_arguments_unit(tmp_path):
    root = tmp_path.resolve()
    out = confine_arguments(root, "graq_bash", {"command": "ls"})
    assert out["cwd"] == str(root)
    assert confine_arguments(root, "graq_read", {"file_path": "x/y"})["file_path"] == str(root / "x" / "y")
    with pytest.raises(WorkspaceError):
        confine_arguments(root, "graq_read", {"file_path": 5})
    with pytest.raises(WorkspaceError):
        confine_arguments(root, "graq_test", {"test_paths": "not-a-list"})
    with pytest.raises(WorkspaceError):
        confine_arguments(root, "graq_edit", {"files": [{"path": "../x", "description": "d"}]})
    assert confine_arguments(root, "graq_read", {"file_path": "a"}) is not None


# AC4 -----------------------------------------------------------------------
def test_reinitialize_with_other_root_rejected(client, roots):
    a, b = roots
    h = _open(client, a)
    r = _init(client, b, headers={t.SESSION_HEADER: h[t.SESSION_HEADER]})
    assert r.status_code == 403
    # a later request carrying a different root is rejected too
    bad = {t.SESSION_HEADER: h[t.SESSION_HEADER], WORKSPACE_HEADER: encode_root(str(b))}
    r = client.post("/mcp", headers=bad, json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert r.status_code == 403
    # same root re-initialize is fine
    assert _init(client, a, headers={t.SESSION_HEADER: h[t.SESSION_HEADER]}).status_code == 200


def test_tool_call_before_initialize_rejected(client, roots):
    a, _ = roots
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "graq_read", "arguments": {}}}
    assert client.post("/mcp", json=body).status_code == 400
    assert client.post("/mcp", json=body, headers={t.SESSION_HEADER: "nope"}).status_code == 404


def test_unbound_session_state_fails_closed_in_http_mode():
    state = ss.SessionState(http_mode=True)  # http session without a root
    with ss.bind_session(state):
        with pytest.raises(ss.WorkspaceNotBound):
            ss.session_workspace_root()
        res = asyncio.run(
            _server()._handle_jsonrpc(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "graq_read", "arguments": {}}}
            )
        )
    assert res["result"]["isError"] is True and "not bound" in res["result"]["content"][0]["text"]


# AC5 -----------------------------------------------------------------------
def test_bash_runs_in_session_root(client, roots):
    a, b = roots
    ha = _open(client, a)
    res = _call(client, ha, "graq_bash", {"command": "pwd"})
    assert Path(res["stdout"].strip()).resolve() == a
    res = _call(client, ha, "graq_git_status", {})
    assert res.get("success") is not None


def test_graq_test_runs_in_session_root(client, roots):
    a, b = roots
    (a / "test_marker.py").write_text(
        "import os\n\ndef test_cwd():\n    assert os.path.exists('marker_a')\n"
    )
    (a / "marker_a").write_text("x")
    ha = _open(client, a)
    res = _call(client, ha, "graq_test", {"target": "test_marker.py", "dry_run": False})
    assert res["metrics"]["passed"] == 1 and res["metrics"]["exit_code"] == 0, res


# AC6 -----------------------------------------------------------------------
def test_spawned_work_keeps_or_fails_closed(roots):
    a, _ = roots
    state = ss.SessionState(workspace_root=a, http_mode=True)
    results: dict[str, object] = {}

    def worker(key: str) -> None:
        try:
            results[key] = ss.session_workspace_root()
        except ss.WorkspaceNotBound:
            results[key] = "rejected"

    ss.set_http_serving(True)
    try:
        with ss.bind_session(state):
            ctx = contextvars.copy_context()
            th1 = threading.Thread(target=lambda: ctx.run(worker, "copied"))
            th2 = threading.Thread(target=worker, args=("lost",))
            for th in (th1, th2):
                th.start()
                th.join()
        # Outside any bound call: a worker with no binding is rejected, not cwd.
        asyncio.run(asyncio.to_thread(worker, "to_thread"))
    finally:
        ss.set_http_serving(False)
    assert results["copied"] == a  # copy_context keeps the binding
    assert results["lost"] == "rejected"  # a lost binding is never the server cwd
    assert results["to_thread"] == "rejected"


def test_to_thread_inside_bound_call_keeps_root(roots):
    a, _ = roots
    state = ss.SessionState(workspace_root=a, http_mode=True)

    async def go():
        with ss.bind_session(state):
            return await asyncio.to_thread(ss.session_workspace_root)

    assert asyncio.run(go()) == a


# AC7 -----------------------------------------------------------------------
def test_stdio_mode_unchanged(tmp_path, monkeypatch):
    monkeypatch.delenv("GRAQLE_WORKTREE_ROOT", raising=False)
    monkeypatch.delenv("GRAQLE_SERVE_CWD", raising=False)
    monkeypatch.chdir(tmp_path)
    server = _server()
    assert ss.session_workspace_root() is None
    assert server._ws_root(Path("/fallback")) == Path("/fallback")
    # master precedence: graph_file parent, then cwd
    assert server._project_root_from_graph_file(str(tmp_path / "sub" / "g.json")) == (tmp_path / "sub").resolve()
    assert server._project_root_from_graph_file(None) == tmp_path.resolve()
    wt = tmp_path / "wt"
    wt.mkdir()
    monkeypatch.setenv("GRAQLE_WORKTREE_ROOT", str(wt))
    assert server._project_root_from_graph_file(str(tmp_path / "g.json")) == wt.resolve()


def test_stdio_dispatch_has_no_workspace_gate(tmp_path):
    res = asyncio.run(
        _server()._handle_jsonrpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "graq_read", "arguments": {}}}
        )
    )
    assert "not bound" not in json.dumps(res)


def test_session_root_beats_env_override(roots, monkeypatch):
    a, b = roots
    monkeypatch.setenv("GRAQLE_WORKTREE_ROOT", str(b))
    monkeypatch.setenv("GRAQLE_SERVE_CWD", str(b))
    with ss.bind_session(ss.SessionState(workspace_root=a, http_mode=True)):
        assert _server()._project_root_from_graph_file(str(b / "g.json")) == a


# Remaining direct cwd uses (grep test, spec item 5) -----------------------------
_ALLOWED_DIRECT_CWD = {
    # snippet -> reason it is not a per-session root
    "def _ws_root": "helper itself: the fallback argument is the stdio value",
    "return Path.cwd().resolve()": "resolver step 4 after the session root (step 0); stdio only",
    "self._ws_root(Path.cwd())": "fallback argument of the helper",
    "_ws_root(\n                Path(self._graph_file).parent.resolve()": "fallback argument of the helper",
    "watch_root = Path.cwd()": "server-wide background grow watcher at startup, not a tool call",
    "_os.getcwd()": "latch root: only reached after session_workspace_root() returned None (stdio)",
    "project_root = Path.cwd().resolve()": "write handler fallback behind the resolver (stdio stub only)",
    "else Path.cwd().resolve()": "fallback argument of the helper / stub",
    "working_dir = Path.cwd().resolve()": "graq_test no-graph fallback behind the session-root branch",
}


def test_remaining_direct_cwd_uses_are_listed():
    import graqle.plugins.mcp_dev_server as dev

    lines = open(dev.__file__, encoding="utf-8").read().splitlines()
    unexplained = []
    for i, line in enumerate(lines):
        if "``Path.cwd()``" in line:
            continue  # docstring
        if re.search(r"Path\.cwd\(\)|os\.getcwd\(\)|_os\.getcwd\(\)", line) and not line.strip().startswith("#"):
            window = "\n".join(lines[max(0, i - 2): i + 1])
            if not any(snippet in window for snippet in _ALLOWED_DIRECT_CWD):
                unexplained.append((i + 1, line.strip()))
    assert not unexplained, unexplained


# AC-1 (relay half) -----------------------------------------------------------
def test_relay_sends_its_root_percent_encoded(tmp_path, monkeypatch):
    from graqle.plugins.mcp_relay import Relay, RelayConfigError

    odd = tmp_path / "räum x"
    odd.mkdir()
    assert Relay("http://127.0.0.1:9", workspace_root=str(odd))._workspace_root == encode_root(str(odd.resolve()))
    monkeypatch.chdir(tmp_path)
    assert Relay("http://127.0.0.1:9")._workspace_root == encode_root(str(tmp_path.resolve()))
    with pytest.raises(RelayConfigError):
        Relay("http://127.0.0.1:9", workspace_root=str(tmp_path / "missing"))
