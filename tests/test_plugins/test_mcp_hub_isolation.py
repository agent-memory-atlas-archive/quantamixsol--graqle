"""CR-INFRA-02 PR-d: multi-project isolation over the real HTTP app (AC 7).

Two fixture projects, A and B, each with its own ``graqle.json``, are served by
ONE app/process through real ``KogniDevServer`` instances (no fakes).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from graqle.core.graph import Graqle
from graqle.plugins import mcp_http_transport as t
from graqle.plugins.mcp_dev_server import KogniDevServer
from graqle.plugins.mcp_project_hub import (
    HubSettings,
    ProjectHub,
    ProjectSpec,
)


def _make_project(root: Path, node: str) -> None:
    root.mkdir()
    g = Graqle()
    g.add_node_simple(node, label=node, description=f"only in {root.name}")
    g.to_json(str(root / "graqle.json"))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAQLE_DISABLE_BACKGROUND_GROW", "1")
    monkeypatch.chdir(tmp_path)
    _make_project(tmp_path / "pa", "node_of_a")
    _make_project(tmp_path / "pb", "node_of_b")
    specs = {
        n: ProjectSpec(name=n, root=(tmp_path / f"p{n}").resolve(), config=str(tmp_path / f"p{n}" / "none.yaml"))
        for n in ("a", "b")
    }
    hub = ProjectHub(HubSettings(specs), lambda s: KogniDevServer(config_path=s.config))
    # `with` keeps ONE event loop for all requests, as uvicorn does; the hub's
    # background load task must outlive the request that started it.
    with TestClient(t.create_app(hub=hub)) as c:
        yield c, tmp_path


def _open(client: TestClient, project: str | None) -> dict[str, str]:
    headers = {t.PROJECT_HEADER: project} if project else {}
    r = client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert r.status_code == 200, r.text
    return {t.SESSION_HEADER: r.headers[t.SESSION_HEADER], t.PROJECT_HEADER: project}


def _tool(client: TestClient, headers: dict[str, str], name: str, args: dict) -> dict:
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}}
    for _ in range(100):  # a first call answers PROJECT_LOADING while the graph loads
        r = client.post("/mcp", headers=headers, json=body)
        if r.status_code != 200:
            return {"http_status": r.status_code}
        text = r.json()["result"]["content"][0]["text"]
        if not text.startswith("PROJECT_LOADING"):
            try:
                return json.loads(text)
            except ValueError:
                return {"text": text}
        time.sleep(0.05)
    raise AssertionError("project never finished loading")


def _unlock(client: TestClient, headers: dict[str, str]) -> None:
    _tool(client, headers, "graq_lifecycle", {"event": "session_start"})
    _tool(client, headers, "graq_plan", {"goal": "x", "dry_run": True})


def test_session_sees_only_its_own_projects_nodes(client):
    c, _ = client
    a, b = _open(c, "a"), _open(c, "b")
    assert "node_of_a" in json.dumps(_tool(c, a, "graq_inspect", {"node_id": "node_of_a"}))
    assert "only in pb" in json.dumps(_tool(c, b, "graq_inspect", {"node_id": "node_of_b"}))
    # A's session cannot see B's node, and vice versa.
    assert "not found" in _tool(c, a, "graq_inspect", {"node_id": "node_of_b"})["error"]
    assert "not found" in _tool(c, b, "graq_inspect", {"node_id": "node_of_a"})["error"]


def test_request_naming_another_project_is_rejected(client):
    c, _ = client
    a = _open(c, "a")
    # Header naming B from a session bound to A.
    assert _tool(c, {**a, t.PROJECT_HEADER: "b"}, "graq_inspect", {})["http_status"] == 403
    # Tool argument naming B.
    assert _tool(c, a, "graq_inspect", {"project": "b"})["http_status"] == 403
    # A session cannot be created for an unknown project, or without one.
    r = c.post("/mcp", headers={t.PROJECT_HEADER: "nope"}, json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 404
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r.status_code == 400


def test_learn_from_a_never_changes_b(client):
    c, root = client
    b_file = root / "pb" / "graqle.json"
    before_b = b_file.read_bytes()
    a, b = _open(c, "a"), _open(c, "b")
    _unlock(c, a)
    _unlock(c, b)
    # The R22 session-completeness gate wants inspect + context + impact in the trace.
    _tool(c, a, "graq_inspect", {"node_id": "node_of_a"})
    _tool(c, a, "graq_context", {"task": "node_of_a"})
    _tool(c, a, "graq_impact", {"component": "node_of_a"})

    result = _tool(c, a, "graq_learn", {"mode": "entity", "entity_id": "learned_in_a", "description": "from a"})

    a_graph = json.loads((root / "pa" / "graqle.json").read_text(encoding="utf-8"))
    assert "learned_in_a" in json.dumps(a_graph), result  # learned, in A's own file
    assert b_file.read_bytes() == before_b
    assert "not found" in _tool(c, b, "graq_inspect", {"node_id": "learned_in_a"})["error"]


def test_gate_state_is_per_project_session(client):
    c, _ = client
    a, b = _open(c, "a"), _open(c, "b")
    _unlock(c, a)
    assert _tool(c, b, "graq_bash", {"command": "true"}).get("error") == "CG-01_SESSION_GATE"


def _confined(result: dict) -> bool:
    return "escapes the session workspace root" in json.dumps(result) or "'..' is not allowed" in json.dumps(result)


def test_path_arguments_cannot_escape_the_project_root(client):
    """INFRA-02g: '..', absolute paths and symlinks cannot reach another project."""
    c, root = client
    secret = root / "pb" / "secret.txt"
    secret.write_text("only-in-b", encoding="utf-8")
    (root / "pa" / "link_to_b").symlink_to(root / "pb", target_is_directory=True)
    a = _open(c, "a")
    attempts = [
        "../pb/secret.txt",
        str(secret),
        "link_to_b/secret.txt",
    ]
    for path in attempts:
        result = _tool(c, a, "graq_read", {"file_path": path})
        assert _confined(result), (path, result)
        assert "only-in-b" not in json.dumps(result), (path, result)


def test_path_inside_own_project_is_allowed(client):
    c, root = client
    (root / "pa" / "own.txt").write_text("only-in-a", encoding="utf-8")
    a = _open(c, "a")
    assert "only-in-a" in json.dumps(_tool(c, a, "graq_read", {"file_path": "own.txt"}))


def test_non_object_tool_arguments_fail_closed(client):
    c, _ = client
    a = _open(c, "a")
    assert "must be an object" in json.dumps(_tool(c, a, "graq_read", ["x"]))


def test_app_requires_exactly_one_of_server_or_hub():
    with pytest.raises(t.HttpTransportConfigError):
        t.create_app()
