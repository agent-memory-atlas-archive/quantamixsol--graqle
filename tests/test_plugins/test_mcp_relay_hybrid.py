"""CR-INFRA-02f: hybrid relay (local tools, hub gate, MIXED pipeline). ACs 1-9 and 11."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest

import graqle.plugins.mcp_relay_hybrid as hybrid
from graqle.plugins.mcp_relay import run_relay


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeHub:
    """A hub with NO file tools at all: it can only answer JSON, so it cannot touch a disk."""

    def __init__(self) -> None:
        self.gate_calls: list[dict[str, Any]] = []
        self.mcp_calls: list[dict[str, Any]] = []
        self.gate: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] = lambda body: (200, {"allow": True, "reason": "ok"})
        self.snapshots: list[Any] = []  # popped per call; an int = HTTP status error
        self.snapshot_default: Any = "v1"
        self.compute: dict[str, Any] = {"patches": []}
        self.url = ""

    def app(self):
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse, Response
        from starlette.routing import Route

        hub = self

        async def mcp(request):
            message = json.loads(await request.body())
            hub.mcp_calls.append(message)
            if message.get("method") == "initialize":
                return JSONResponse({"jsonrpc": "2.0", "id": message["id"], "result": {}}, headers={"Mcp-Session-Id": "sid1"})
            if "id" not in message:
                return Response(status_code=202)
            text = json.dumps(hub.compute)
            return JSONResponse({"jsonrpc": "2.0", "id": message["id"], "result": {"content": [{"type": "text", "text": text}]}})

        async def gate(request):
            body = json.loads(await request.body())
            hub.gate_calls.append(body)
            status, answer = hub.gate(body)
            return JSONResponse(answer, status_code=status)

        async def snapshot(request):
            item = hub.snapshots.pop(0) if hub.snapshots else hub.snapshot_default
            if isinstance(item, int):
                return JSONResponse({"error": "boom"}, status_code=item)
            return JSONResponse({"version": item})

        return Starlette(routes=[
            Route("/mcp", mcp, methods=["POST"]),
            Route("/relay/gate", gate, methods=["POST"]),
            Route("/relay/snapshot", snapshot, methods=["POST"]),
        ])


@pytest.fixture()
def hub():
    import uvicorn

    fake = FakeHub()
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(fake.app(), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    fake.url = f"http://127.0.0.1:{port}"
    yield fake
    server.should_exit = True
    thread.join(timeout=5)


def session(url: str, root: Path, *calls: tuple[str, dict[str, Any]], local_tools: bool | None = True) -> list[dict[str, Any]]:
    """Run one relay session: initialize, then each tool call; return the tool-call replies."""
    messages = [{"jsonrpc": "2.0", "id": 0, "method": "initialize"}]
    for i, (name, args) in enumerate(calls, start=1):
        messages.append({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}})
    out = io.StringIO()
    run_relay(url, stdin=io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), stdout=out,
              workspace_root=str(root), local_tools=local_tools)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    return [r for r in replies if r["id"] != 0]


def text(reply: dict[str, Any]) -> str:
    return reply["result"]["content"][0]["text"]


def is_error(reply: dict[str, Any]) -> bool:
    return bool(reply["result"].get("isError"))


# -- AC1: two machines, each in its own workspace ---------------------------------
def test_ac1_two_workspaces_each_session_works_only_in_its_own_root(hub, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    for root, tag in ((a, "A"), (b, "B")):
        replies = session(
            hub.url, root,
            ("graq_write", {"file_path": "f.txt", "content": f"hello {tag}\n", "dry_run": False}),
            ("graq_read", {"file_path": "f.txt"}),
            ("graq_grep", {"pattern": "hello"}),
            ("graq_bash", {"command": "echo ran"}),
            ("graq_bash", {"command": "git init -q && git add f.txt && git -c user.email=t@t -c user.name=t commit -qm init"}),
            ("graq_git_log", {}),
        )
        assert [is_error(r) for r in replies] == [False] * 6, [text(r) for r in replies]
        assert f"hello {tag}" in text(replies[1])
        assert "f.txt" in text(replies[2])
        assert "init" in text(replies[5])
    assert (a / "f.txt").read_text() == "hello A\n"
    assert (b / "f.txt").read_text() == "hello B\n"
    # the hub received only gate checks for the mutations, never a file tool call
    forwarded = [m for m in hub.mcp_calls if m.get("method") == "tools/call"]
    assert forwarded == []
    assert len(hub.gate_calls) >= 2


def test_ac1_git_commit_tool_commits_locally(hub, tmp_path):
    subprocess.run("git init -q && git config user.email t@t && git config user.name t", shell=True, cwd=tmp_path, check=True)
    (tmp_path / "x.txt").write_text("x")
    replies = session(hub.url, tmp_path, ("graq_git_commit", {"message": "m", "files": ["x.txt"], "dry_run": False}))
    assert not is_error(replies[0]) and json.loads(text(replies[0]))["success"] is True
    assert hub.gate_calls and hub.gate_calls[0]["tool"] == "graq_git_commit"
    log = subprocess.run("git log --oneline", shell=True, cwd=tmp_path, capture_output=True, text=True).stdout
    assert " m" in log


# -- AC2: hub unreachable -------------------------------------------------------
def test_ac2_gate_error_refuses_every_mutation_but_reads_still_work(hub, tmp_path):
    (tmp_path / "r.txt").write_text("readable\n")
    hub.gate = lambda body: (500, {"error": "down"})
    replies = session(
        hub.url, tmp_path,
        ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}),
        ("graq_bash", {"command": "touch b.txt"}),
        ("graq_git_commit", {"message": "m", "dry_run": False}),
        ("graq_test", {"target": "tests/"}),
        ("graq_read", {"file_path": "r.txt"}),
        ("graq_glob", {"pattern": "*.txt"}),
    )
    assert [is_error(r) for r in replies] == [True, True, True, True, False, False]
    assert "refused" in text(replies[0])
    assert not (tmp_path / "w.txt").exists() and not (tmp_path / "b.txt").exists()
    assert "readable" in text(replies[4])


def test_ac2_hub_not_reachable_at_all(tmp_path):
    url = f"http://127.0.0.1:{_free_port()}"
    replies = session(url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}),
                      ("graq_read", {"file_path": "nope.txt"}))
    assert is_error(replies[0]) and "refused" in text(replies[0])
    assert not (tmp_path / "w.txt").exists()
    assert "not found" in text(replies[1]).lower()  # read-only local tool still answers


def test_malformed_or_ambiguous_gate_answers_refuse(hub, tmp_path):
    for answer in ({"allow": "yes"}, {"allow": 1}, {}, {"reason": "ok"}, ["allow"]):
        hub.gate = lambda body, a=answer: (200, a)
        replies = session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}))
        assert is_error(replies[0]), answer
    assert not (tmp_path / "w.txt").exists()


# -- AC3: delayed gate ----------------------------------------------------------
def test_ac3_gate_delayed_two_seconds_waits_then_follows_the_answer(hub, tmp_path):
    def slow(body):
        time.sleep(2)
        return 200, {"allow": True, "reason": "ok"}

    hub.gate = slow
    start = time.monotonic()
    replies = session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}))
    assert time.monotonic() - start >= 2
    assert not is_error(replies[0]) and (tmp_path / "w.txt").read_text() == "x"

    def slow_deny(body):
        time.sleep(2)
        return 200, {"allow": False, "reason": "CG-02_PLAN_GATE"}

    hub.gate = slow_deny
    replies = session(hub.url, tmp_path, ("graq_write", {"file_path": "w2.txt", "content": "x", "dry_run": False}))
    assert is_error(replies[0]) and "CG-02_PLAN_GATE" in text(replies[0])
    assert not (tmp_path / "w2.txt").exists()


def test_ac3_gate_timeout_refuses(hub, tmp_path, monkeypatch):
    monkeypatch.setattr(hybrid, "GATE_TIMEOUT_S", 0.3)
    hub.gate = lambda body: (time.sleep(1.5), (200, {"allow": True}))[1]
    replies = session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}))
    assert is_error(replies[0]) and "refused" in text(replies[0])
    assert not (tmp_path / "w.txt").exists()


# -- AC4: revoked mid-session -----------------------------------------------------
def test_ac4_gate_revoked_mid_session_refuses_the_next_mutation(hub, tmp_path):
    hub.gate = lambda body: (200, {"allow": len(hub.gate_calls) <= 1, "reason": "revoked"})
    replies = session(
        hub.url, tmp_path,
        ("graq_write", {"file_path": "one.txt", "content": "1", "dry_run": False}),
        ("graq_write", {"file_path": "two.txt", "content": "2", "dry_run": False}),
    )
    assert [is_error(r) for r in replies] == [False, True]
    assert (tmp_path / "one.txt").exists() and not (tmp_path / "two.txt").exists()
    assert len(hub.gate_calls) == 2  # asked again, not cached from the first answer


# -- AC5/AC6: MIXED pipeline ------------------------------------------------------
EDIT_ARGS = {"file_path": "m.txt", "description": "change", "dry_run": False}


def _prep_mixed(tmp_path: Path) -> None:
    (tmp_path / "m.txt").write_text("one\ntwo\nthree\n")


PATCH = "--- a/m.txt\n+++ b/m.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"


def test_mixed_success_applies_patch_locally_after_recheck_and_gate(hub, tmp_path):
    _prep_mixed(tmp_path)
    hub.compute = {"patches": [{"file_path": "m.txt", "unified_diff": PATCH}]}
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert not is_error(replies[0]), text(replies[0])
    assert (tmp_path / "m.txt").read_text() == "one\nTWO\nthree\n"
    assert json.loads(text(replies[0]))["applied_locally"] == ["m.txt"]
    forwarded = [m for m in hub.mcp_calls if m.get("method") == "tools/call"][0]["params"]["arguments"]
    assert forwarded["dry_run"] is True  # the hub only computes
    assert forwarded["local_files"] == {"m.txt": "one\ntwo\nthree\n"}
    assert forwarded["file_path"] == "m.txt"  # relative: the hub anchors it at its own root
    assert hub.gate_calls  # the local write was gated on the hub


def test_ac5_hub_killed_after_context_fetch_before_write_no_partial_write(hub, tmp_path):
    _prep_mixed(tmp_path)
    hub.compute = {"patches": [{"file_path": "m.txt", "unified_diff": PATCH}]}
    hub.snapshots = ["v1", 503]  # first fetch ok, hub gone at the re-check
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and "nothing was written" in text(replies[0])
    assert (tmp_path / "m.txt").read_text() == "one\ntwo\nthree\n"


def test_ac5_hub_gone_before_first_snapshot_writes_nothing(hub, tmp_path):
    _prep_mixed(tmp_path)
    hub.compute = {"writes": [{"file_path": "new.txt", "content": "n"}]}
    hub.snapshots = [503]
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and not (tmp_path / "new.txt").exists()


def test_ac6_graph_version_change_aborts_as_stale_context(hub, tmp_path):
    _prep_mixed(tmp_path)
    hub.compute = {"patches": [{"file_path": "m.txt", "unified_diff": PATCH}]}
    hub.snapshots = ["v1", "v2"]
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and "stale context" in text(replies[0])
    assert (tmp_path / "m.txt").read_text() == "one\ntwo\nthree\n"


def test_mixed_gate_denial_writes_nothing_even_for_multi_file_results(hub, tmp_path):
    _prep_mixed(tmp_path)
    hub.compute = {"writes": [{"file_path": "a.txt", "content": "a"}, {"file_path": "b.txt", "content": "b"}]}
    hub.gate = lambda body: (200, {"allow": "b.txt" not in body["arguments"]["file_path"], "reason": "no"})
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0])
    assert not (tmp_path / "a.txt").exists() and not (tmp_path / "b.txt").exists()


def test_mixed_patch_that_does_not_match_local_file_writes_nothing(hub, tmp_path):
    (tmp_path / "m.txt").write_text("different\ncontent\nhere\n")
    hub.compute = {"patches": [{"file_path": "m.txt", "unified_diff": PATCH}]}
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and "does not match" in text(replies[0])
    assert (tmp_path / "m.txt").read_text() == "different\ncontent\nhere\n"


def test_mixed_invalid_python_result_is_refused_before_any_write(hub, tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    hub.compute = {"writes": [{"file_path": "new.txt", "content": "n"}, {"file_path": "ok.py", "content": "def broken(:\n"}]}
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and "not valid Python" in text(replies[0])
    assert not (tmp_path / "new.txt").exists() and (tmp_path / "ok.py").read_text() == "x = 1\n"


def test_mixed_failure_while_writing_restores_files_already_written(hub, tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("old-a")
    hub.compute = {"writes": [{"file_path": "a.txt", "content": "new-a"}, {"file_path": "b.txt", "content": "new-b"}]}
    real = hybrid.write_atomic

    def flaky(path, content):
        if path.name == "b.txt" and content == "new-b":
            raise OSError("disk full")
        real(path, content)

    monkeypatch.setattr(hybrid, "write_atomic", flaky)
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and "nothing was left half-done" in text(replies[0])
    assert (tmp_path / "a.txt").read_text() == "old-a" and not (tmp_path / "b.txt").exists()


def test_mixed_result_path_escaping_the_root_is_refused(hub, tmp_path):
    hub.compute = {"writes": [{"file_path": "../evil.txt", "content": "x"}]}
    replies = session(hub.url, tmp_path, ("graq_edit", EDIT_ARGS))
    assert is_error(replies[0]) and not (tmp_path.parent / "evil.txt").exists()


def test_mixed_user_dry_run_does_not_write(hub, tmp_path):
    _prep_mixed(tmp_path)
    hub.compute = {"patches": [{"file_path": "m.txt", "unified_diff": PATCH}]}
    session(hub.url, tmp_path, ("graq_edit", {**EDIT_ARGS, "dry_run": True}))
    assert (tmp_path / "m.txt").read_text() == "one\ntwo\nthree\n"


def test_mixed_read_only_tools_are_forwarded_without_local_files(hub, tmp_path):
    replies = session(hub.url, tmp_path, ("graq_review", {"file_path": "m.txt"}))
    assert not is_error(replies[0])
    forwarded = [m for m in hub.mcp_calls if m.get("method") == "tools/call"]
    assert len(forwarded) == 1 and "local_files" not in forwarded[0]["params"]["arguments"]


def test_file_lock_blocks_a_second_holder_then_times_out(tmp_path):
    path = tmp_path / ".graqle" / "relay.lock"
    with hybrid.FileLock(path, timeout=1):
        with pytest.raises(hybrid.MixedAbort):
            with hybrid.FileLock(path, timeout=0.2):
                pass
    with hybrid.FileLock(path, timeout=1):  # released
        pass


# -- AC7: no replay ---------------------------------------------------------------
def test_ac7_outage_then_reconnect_executes_nothing_that_was_refused(hub, tmp_path):
    hub.gate = lambda body: (503, {"error": "outage"})
    session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}))
    hub.gate = lambda body: (200, {"allow": True, "reason": "ok"})  # hub is back
    time.sleep(0.5)
    assert not (tmp_path / "w.txt").exists()  # nothing was queued; the client must resubmit
    session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}))
    assert (tmp_path / "w.txt").read_text() == "x"


# -- AC8: confinement ---------------------------------------------------------------
def test_ac8_dotdot_absolute_and_symlink_escapes_are_refused_at_the_relay(hub, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "flink.txt").symlink_to(outside / "secret.txt")
    calls = [
        ("graq_read", {"file_path": "../outside/secret.txt"}),
        ("graq_read", {"file_path": str(outside / "secret.txt")}),
        ("graq_read", {"file_path": "link/secret.txt"}),
        ("graq_read", {"file_path": "flink.txt"}),
        ("graq_write", {"file_path": "link/new.txt", "content": "x", "dry_run": False}),
        ("graq_write", {"file_path": "../w.txt", "content": "x", "dry_run": False}),
        ("graq_bash", {"command": "pwd", "cwd": str(outside)}),
        ("graq_grep", {"pattern": "secret", "path": "link"}),
        ("graq_test", {"target": "../outside"}),
    ]
    replies = session(hub.url, root, *calls)
    assert all(is_error(r) for r in replies), [text(r) for r in replies]
    assert not (outside / "new.txt").exists() and not (tmp_path / "w.txt").exists()
    assert hub.gate_calls == []  # refused before the hub was even asked


def test_grep_and_glob_skip_files_whose_symlink_leaves_the_root(hub, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "out.txt").write_text("needle")
    (root / "l.txt").symlink_to(tmp_path / "out.txt")
    (root / "in.txt").write_text("needle")
    replies = session(hub.url, root, ("graq_grep", {"pattern": "needle"}), ("graq_glob", {"pattern": "*.txt"}))
    assert "in.txt" in text(replies[0]) and "l.txt" not in text(replies[0])
    assert "in.txt" in text(replies[1]) and "l.txt" not in text(replies[1])


# -- AC9: routing ---------------------------------------------------------------------
def test_ac9_routing_table_covers_every_tool_exactly_once():
    from graqle.plugins import mcp_relay_routing as routing
    from graqle.plugins.mcp_dev_server import TOOL_DEFINITIONS

    names = {t["name"] for t in TOOL_DEFINITIONS if t["name"].startswith("graq_")}
    assert set(routing.ROUTES) == names, (sorted(names - set(routing.ROUTES)), sorted(set(routing.ROUTES) - names))
    assert routing.duplicates() == []
    assert set(routing.ROUTES.values()) == {routing.LOCAL, routing.HUB, routing.MIXED}
    for kogni in (t["name"] for t in TOOL_DEFINITIONS if t["name"].startswith("kogni_")):
        assert routing.route_for(kogni) == routing.route_for("graq_" + kogni[len("kogni_"):])


def test_ac9_learn_and_graph_writes_are_hub_and_unknown_tools_are_refused(hub, tmp_path):
    from graqle.plugins import mcp_relay_routing as routing

    for tool in ("graq_learn", "graq_reload", "graq_ingest", "graq_context", "graq_reason"):
        assert routing.route_for(tool) == routing.HUB
    for tool in ("graq_read", "graq_write", "graq_bash", "graq_git_commit"):
        assert routing.route_for(tool) == routing.LOCAL
    with pytest.raises(routing.UnknownToolError):
        routing.route_for("graq_totally_new")
    replies = session(hub.url, tmp_path, ("graq_totally_new", {}), ("not_graq", {}))
    assert all(is_error(r) and "routing table" in text(r) for r in replies)
    assert [m for m in hub.mcp_calls if m.get("method") == "tools/call"] == []  # not even forwarded


def test_hub_tools_are_forwarded_unchanged(hub, tmp_path):
    replies = session(hub.url, tmp_path, ("graq_learn", {"knowledge": "k"}))
    assert not is_error(replies[0])
    forwarded = [m for m in hub.mcp_calls if m.get("method") == "tools/call"]
    assert forwarded[0]["params"] == {"name": "graq_learn", "arguments": {"knowledge": "k"}}


def test_local_tool_without_executor_is_refused_not_sent_to_the_hub_disk(hub, tmp_path):
    replies = session(hub.url, tmp_path, ("graq_vendor", {}), ("graq_deps_install", {}))
    assert all(is_error(r) for r in replies)
    assert [m for m in hub.mcp_calls if m.get("method") == "tools/call"] == []


# -- AC11: flag off / defaults --------------------------------------------------------
def test_ac11_no_local_tools_forwards_everything_unchanged(hub, tmp_path):
    replies = session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}),
                      local_tools=False)
    assert not (tmp_path / "w.txt").exists() and hub.gate_calls == []
    forwarded = [m for m in hub.mcp_calls if m.get("method") == "tools/call"]
    assert forwarded[0]["params"]["name"] == "graq_write"
    assert not is_error(replies[0])


def test_ac11_default_is_off_on_loopback(hub, tmp_path):
    session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x", "dry_run": False}), local_tools=None)
    assert hub.gate_calls == [] and not (tmp_path / "w.txt").exists()


def test_default_is_on_for_a_non_loopback_server(tmp_path, monkeypatch):
    seen = {}

    class Probe:
        def __init__(self, root, forward, post_side):
            seen["root"] = root

        def handle(self, message):
            return None

    monkeypatch.setattr(hybrid, "HybridDispatcher", Probe)
    run_relay("http://hub.example.com:9", stdin=io.StringIO(""), stdout=io.StringIO(), workspace_root=str(tmp_path))
    assert seen["root"] == tmp_path.resolve()


def test_dry_run_mutations_are_not_gated_and_do_not_write(hub, tmp_path):
    replies = session(hub.url, tmp_path, ("graq_write", {"file_path": "w.txt", "content": "x"}),
                      ("graq_bash", {"command": "touch z.txt", "dry_run": True}))
    assert [is_error(r) for r in replies] == [False, False]
    assert hub.gate_calls == [] and not (tmp_path / "w.txt").exists() and not (tmp_path / "z.txt").exists()


def test_graq_test_runs_pytest_in_the_local_workspace_after_a_gate_check(hub, tmp_path):
    (tmp_path / "test_here.py").write_text("def test_ok():\n    assert True\n")
    replies = session(hub.url, tmp_path, ("graq_test", {"target": "test_here.py"}))
    body = json.loads(text(replies[0]))
    assert body["passed"] is True, body
    assert hub.gate_calls[0]["tool"] == "graq_test"


def test_blocked_bash_command_is_refused_locally(hub, tmp_path):
    replies = session(hub.url, tmp_path, ("graq_bash", {"command": "rm -rf /tmp/x"}))
    assert is_error(replies[0]) and "blocklist" in text(replies[0])


# -- unified diff -------------------------------------------------------------------------
def test_apply_unified_diff_strict():
    assert hybrid.apply_unified_diff("one\ntwo\nthree\n", PATCH) == "one\nTWO\nthree\n"
    with pytest.raises(hybrid.MixedAbort):
        hybrid.apply_unified_diff("one\nXXX\nthree\n", PATCH)
    with pytest.raises(hybrid.MixedAbort):
        hybrid.apply_unified_diff("one\ntwo\nthree\n", "no hunks here")
    added = "@@ -0,0 +1,2 @@\n+a\n+b\n"
    assert hybrid.apply_unified_diff("", added).startswith("a\nb")


# -- AC10 (import part): no ML stack in the relay process ---------------------------------------
def test_ac10_relay_with_local_tools_imports_no_ml_stack(tmp_path):
    code = (
        "import sys, io, json\n"
        "from graqle.plugins.mcp_relay import run_relay\n"
        "run_relay('http://hub.example.com:9', stdin=io.StringIO(''), stdout=io.StringIO(), "
        f"workspace_root={str(tmp_path)!r}, local_tools=True)\n"
        "bad = [m for m in ('torch', 'sentence_transformers', 'neo4j') if m in sys.modules]\n"
        "print(json.dumps(bad))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         cwd=str(Path(__file__).resolve().parents[2]))
    assert json.loads(out.stdout.strip().splitlines()[-1]) == []
