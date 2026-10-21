"""CR-INFRA-02 PR-b: per-session gate state over the HTTP transport (AC 2, gate half).

Uses a real ``KogniDevServer`` (no graph needed: the CG-01/CG-02 gates run before
tool dispatch) behind the real HTTP app.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from starlette.testclient import TestClient

from graqle.plugins import mcp_http_transport as t
from tests.test_plugins.ws_helpers import ws_client
from graqle.plugins.mcp_dev_server import KogniDevServer
from graqle.plugins.mcp_session_state import SessionState, bind_session


def _server() -> KogniDevServer:
    s = KogniDevServer(config_path=None)
    s._config = SimpleNamespace(
        governance=SimpleNamespace(session_gate_enabled=True, plan_mandatory=True)
    )
    return s


def _open(client: TestClient) -> dict[str, str]:
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    return {t.SESSION_HEADER: r.headers[t.SESSION_HEADER]}


def _call(client: TestClient, headers: dict[str, str], name: str, args: dict) -> dict:
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}}
    result = client.post("/mcp", headers=headers, json=body).json()["result"]
    return json.loads(result["content"][0]["text"])


def test_session_start_and_plan_do_not_unlock_other_session():
    client = ws_client(_server())
    a, b = _open(client), _open(client)

    assert _call(client, a, "graq_bash", {"command": "true"})["error"] == "CG-01_SESSION_GATE"
    _call(client, a, "graq_lifecycle", {"event": "session_start"})
    assert _call(client, a, "graq_bash", {"command": "true"})["error"] == "CG-02_PLAN_GATE"
    _call(client, a, "graq_plan", {"goal": "x", "dry_run": True})
    assert _call(client, a, "graq_bash", {"command": "true"})["success"] is True

    # B never started a session: both gates still closed for B.
    assert _call(client, b, "graq_bash", {"command": "true"})["error"] == "CG-01_SESSION_GATE"
    _call(client, b, "graq_lifecycle", {"event": "session_start"})
    assert _call(client, b, "graq_bash", {"command": "true"})["error"] == "CG-02_PLAN_GATE"


def test_new_session_starts_with_closed_gates_even_after_another_unlocked():
    client = ws_client(_server())
    a = _open(client)
    _call(client, a, "graq_lifecycle", {"event": "session_start"})
    _call(client, a, "graq_plan", {"goal": "x", "dry_run": True})
    c = _open(client)
    assert _call(client, c, "graq_bash", {"command": "true"})["error"] == "CG-01_SESSION_GATE"


def test_todos_and_cache_are_per_session():
    server = _server()
    s1, s2 = SessionState(), SessionState()
    with bind_session(s1):
        server._todos = [{"id": 1}]
        server._session_cache["k"] = "v"
        server._session_cost_usd = 1.5
    with bind_session(s2):
        assert server._todos == []
        assert "k" not in server._session_cache
        assert server._session_cost_usd == 0.0
    assert s1.todos == [{"id": 1}]


def test_unbound_state_is_instance_default_and_unaffected_by_sessions():
    """stdio path: no session bound -> the instance's own state, as before."""
    server = _server()
    assert server._session_started is False
    server._session_started = True
    with bind_session(SessionState()):
        assert server._session_started is False
    assert server._session_started is True


def test_delete_drops_session_state():
    client = ws_client(_server())
    a = _open(client)
    assert client.delete("/mcp", headers=a).status_code == 200
    r = client.post("/mcp", headers=a, json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert r.status_code == 404


def _unlock(client: TestClient, headers: dict[str, str]) -> None:
    _call(client, headers, "graq_lifecycle", {"event": "session_start"})
    _call(client, headers, "graq_plan", {"goal": "x", "dry_run": True})


def test_concurrent_sessions_read_correct_results():
    """AC 2 read clause: interleaved requests from two sessions each get a
    correct graq_inspect result while the shared graph stays untouched."""
    import threading

    from unittest.mock import MagicMock

    server = _server()
    server._graph_file = "graqle.json"
    server._graph_mtime = 9999999999.0
    server._kg_load_lock = threading.Lock()
    server._kg_loaded = threading.Event()
    server._kg_load_error = None
    server._kg_load_state = "LOADED"
    node = SimpleNamespace(
        id="n1", label="N1", entity_type="LESSON", description="d", degree=0
    )
    graph = MagicMock()
    graph.nodes = {"n1": node}

    client = ws_client(server)
    a, b = _open(client), _open(client)
    _unlock(client, a)  # B stays locked
    out_b_locked = _call(client, b, "graq_bash", {"command": "true"})
    _unlock(client, b)
    server._graph = graph  # attach after the unlock calls (lifecycle serialises graph stats)

    out_a = _call(client, a, "graq_inspect", {"orphans": True})
    out_b = _call(client, b, "graq_inspect", {"orphans": True})
    out_a2 = _call(client, a, "graq_inspect", {"orphans": True})

    assert out_a["orphan_count"] == out_b["orphan_count"] == out_a2["orphan_count"] == 1
    assert out_a["orphans"][0]["id"] == "n1"
    assert out_b_locked["error"] == "CG-01_SESSION_GATE"
    assert graph.nodes == {"n1": node}


def test_concurrent_graq_learn_is_serialised_with_no_lost_update():
    """AC 3: two sessions learn at once; the writes never overlap and each
    persists exactly once (read-modify-write with an await in the middle)."""
    import asyncio

    server = _server()
    store: list[str] = []
    state = {"active": 0, "max_active": 0}

    async def fake_outcome(args: dict) -> str:
        state["active"] += 1
        state["max_active"] = max(state["max_active"], state["active"])
        snapshot = list(store)
        await asyncio.sleep(0.01)  # yield: would lose an update without the lock
        store[:] = snapshot + [args["action"]]
        state["active"] -= 1
        return json.dumps({"recorded": True})

    server._handle_learn_outcome = fake_outcome

    async def run() -> None:
        s1, s2 = SessionState(), SessionState()

        async def learn(s: SessionState, name: str) -> None:
            with bind_session(s):
                await server._handle_learn({"action": name})

        await asyncio.gather(learn(s1, "from-a"), learn(s2, "from-b"))

    asyncio.run(run())
    assert state["max_active"] == 1
    assert sorted(store) == ["from-a", "from-b"]
