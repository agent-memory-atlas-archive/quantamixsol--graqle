"""Hybrid dispatch for ``graq mcp relay --local-tools`` (CR-INFRA-02f).

* LOCAL tools run in-process (``mcp_relay_local``) on the user's workspace.
* HUB tools are forwarded unchanged (graph reads and every graph write).
* MIXED tools run the fixed pipeline: acquire the local file lock -> fetch a
  bounded, versioned snapshot from the hub -> compute on the hub (dry run) ->
  re-check the snapshot version just before writing -> gate every write on the
  hub -> write locally -> release the lock.

Every local mutation asks the hub synchronously, with a short timeout, whether
this session's gates allow it. The answer is never cached and a refusal is
never queued: hub unreachable, timeout, error or a malformed answer means the
mutation is refused, and the client must resubmit it.

Standard library only, on purpose (relay RSS).
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from graqle.plugins.mcp_relay_local import LocalExecutor, write_atomic
from graqle.plugins.mcp_relay_routing import (
    HUB,
    LOCAL,
    LOCAL_IMPLEMENTED,
    LOCAL_MUTATING,
    MIXED,
    UnknownToolError,
    route_for,
    short_name,
)
from graqle.plugins.mcp_workspace import PATH_KEYS, PATH_LIST_KEYS, WorkspaceError, _confine

logger = logging.getLogger(__name__)

GATE_TIMEOUT_S = 5.0  # a gate answer is one in-memory check on the hub; slower means refuse
SNAPSHOT_TIMEOUT_S = 10.0
LOCK_TIMEOUT_S = 10.0
SNAPSHOT_MAX_BYTES = 65536
MAX_LOCAL_FILE_BYTES = 262144
MAX_LOCAL_FILES_BYTES = 1048576
ERR_REFUSED = -32005

# MIXED tools whose hub compute is forced to a dry run; the relay does the write.
_WRITING_MIXED = frozenset({"apply", "auto", "edit", "generate", "scaffold", "workflow"})


class HubUnavailable(RuntimeError):
    """The hub did not give a usable answer (unreachable, timeout, bad reply)."""


class MixedAbort(RuntimeError):
    """A MIXED pipeline stopped before writing anything."""


def error_reply(message: dict[str, Any], text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0", "id": message.get("id"),
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def ok_reply(message: dict[str, Any], payload: str, is_error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": payload}]}
    if is_error:
        result["isError"] = True
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": result}


# -- file lock ---------------------------------------------------------------
_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


class FileLock:
    """Cross-process advisory lock on ``<root>/.graqle/relay.lock`` (+ in-process lock)."""

    def __init__(self, path: Path, timeout: float = LOCK_TIMEOUT_S) -> None:
        self.path = path
        self.timeout = timeout
        self._fh: Any = None
        with _thread_locks_guard:
            self._tlock = _thread_locks.setdefault(str(path), threading.Lock())

    def _try_os_lock(self) -> bool:
        try:
            import fcntl
            try:
                fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            return True
        except ImportError:  # Windows
            import msvcrt
            try:
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                return False
            return True

    def __enter__(self) -> "FileLock":
        deadline = time.monotonic() + self.timeout
        if not self._tlock.acquire(timeout=self.timeout):
            raise MixedAbort("another local operation holds the file lock (timeout); nothing was written")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a+b")  # noqa: SIM115 (closed in __exit__)
            while not self._try_os_lock():
                if time.monotonic() >= deadline:
                    raise MixedAbort("another process holds the file lock (timeout); nothing was written")
                time.sleep(0.05)
        except BaseException:
            self._release()
            raise
        return self

    def _release(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()  # closing drops the OS lock
            finally:
                self._fh = None
        if self._tlock.locked():
            self._tlock.release()

    def __exit__(self, *exc: object) -> None:
        self._release()


# -- unified diff ------------------------------------------------------------
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified_diff(original: str, diff: str) -> str:
    """Apply a single-file unified diff strictly; raise ``MixedAbort`` on any mismatch."""
    src = original.split("\n")
    out: list[str] = []
    pos = 0
    lines = diff.split("\n")
    i = 0
    while i < len(lines) and not lines[i].startswith("@@"):
        i += 1  # skip ---/+++ headers
    if i >= len(lines):
        raise MixedAbort("patch has no hunks; nothing was written")
    while i < len(lines):
        m = _HUNK.match(lines[i])
        if not m:
            if lines[i] == "" and i == len(lines) - 1:
                break
            raise MixedAbort("malformed patch hunk; nothing was written")
        start = int(m.group(1)) - 1 if int(m.group(2) or 1) else int(m.group(1))
        if start < pos or start > len(src):
            raise MixedAbort("patch hunks overlap or lie outside the file; nothing was written")
        out.extend(src[pos:start])
        pos = start
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            line = lines[i]
            i += 1
            if line.startswith("\\"):
                continue
            tag, text = (line[:1], line[1:]) if line else (" ", "")
            if tag == " ":
                if pos >= len(src) or src[pos] != text:
                    raise MixedAbort("patch context does not match the local file; nothing was written")
                out.append(text)
                pos += 1
            elif tag == "-":
                if pos >= len(src) or src[pos] != text:
                    raise MixedAbort("patch removal does not match the local file; nothing was written")
                pos += 1
            elif tag == "+":
                out.append(text)
            else:
                raise MixedAbort("malformed patch line; nothing was written")
    out.extend(src[pos:])
    return "\n".join(out)


# -- the hybrid dispatcher -----------------------------------------------------
class HybridDispatcher:
    """Routes ``tools/call`` messages for one relay session."""

    def __init__(
        self,
        root: Path,
        forward: Callable[[dict[str, Any]], dict[str, Any] | None],
        post_side: Callable[[str, dict[str, Any], float], dict[str, Any]],
    ) -> None:
        self.root = Path(root).resolve()
        self.executor = LocalExecutor(self.root)
        self._forward = forward
        self._post_side = post_side

    # hub side channel (every call goes to the hub; nothing is cached)
    def gate(self, tool: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        try:
            answer = self._post_side("gate", {"tool": tool, "arguments": arguments}, GATE_TIMEOUT_S)
        except HubUnavailable as exc:
            return False, f"hub gate unreachable ({exc}); mutation refused, resubmit when the hub is back"
        if answer.get("allow") is True:
            return True, "ok"
        return False, str(answer.get("reason") or "refused by the hub gate")

    def snapshot(self) -> str:
        try:
            answer = self._post_side("snapshot", {}, SNAPSHOT_TIMEOUT_S)
        except HubUnavailable as exc:
            raise MixedAbort(f"hub snapshot unavailable ({exc}); nothing was written") from exc
        version = answer.get("version")
        if not isinstance(version, str) or not version:
            raise MixedAbort("hub snapshot has no version; nothing was written")
        return version

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return error_reply(message, "tool arguments must be an object")
        try:
            kind = route_for(name)  # unknown tools are refused, never guessed
        except UnknownToolError as exc:
            return error_reply(message, f"refused: {exc}")
        try:
            if kind == HUB:
                return self._forward(message)
            if kind == LOCAL:
                return self._local(message, name, arguments)
            return self._mixed(message, name, arguments)
        except MixedAbort as exc:
            return error_reply(message, str(exc))
        except WorkspaceError as exc:
            return error_reply(message, str(exc))
        except (OSError, ValueError, TypeError) as exc:  # fail closed
            return error_reply(message, f"local operation failed ({type(exc).__name__}); nothing was left half-done")

    # LOCAL ---------------------------------------------------------------
    @staticmethod
    def is_mutation(short: str, arguments: dict[str, Any]) -> bool:
        if short not in LOCAL_MUTATING:
            return False
        if short in ("write", "git_commit"):
            return not bool(arguments.get("dry_run", True))
        if short == "bash":
            return not bool(arguments.get("dry_run", False))
        if short == "git_branch":
            return arguments.get("action", "create_and_switch") != "list"
        return True

    def _local(self, message: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        short = short_name(name)
        if short not in LOCAL_IMPLEMENTED:
            return error_reply(message, f"refused: {name} has no local executor in this relay")
        confined = self.executor.confine(name, arguments)
        if self.is_mutation(short, confined):
            allowed, reason = self.gate(name, confined)
            if not allowed:
                return error_reply(message, f"refused by the hub gate: {reason}")
        payload = self.executor.execute(name, confined)
        try:
            is_error = "error" in json.loads(payload)
        except ValueError:
            is_error = True
        return ok_reply(message, payload, is_error)

    # MIXED ---------------------------------------------------------------
    def _read_local_files(self, arguments: dict[str, Any]) -> dict[str, str]:
        paths: list[str] = []
        for key in ("file_path", "path"):
            if isinstance(arguments.get(key), str):
                paths.append(arguments[key])
        for key in ("files", "paths"):
            for item in arguments.get(key) or []:
                paths.append(item["path"] if isinstance(item, dict) and "path" in item else item)
        out: dict[str, str] = {}
        total = 0
        for p in paths:
            if not isinstance(p, str) or not Path(p).is_file():
                continue
            fp = Path(p)
            data = fp.read_bytes()[:MAX_LOCAL_FILE_BYTES]
            total += len(data)
            if total > MAX_LOCAL_FILES_BYTES:
                break
            out[os.path.relpath(fp, self.root)] = data.decode("utf-8", errors="replace")
        return out

    def _relativise(self, value: Any) -> Any:
        """The hub anchors relative paths at its own session root."""
        if isinstance(value, str) and os.path.isabs(value):
            return os.path.relpath(value, self.root)
        if isinstance(value, list):
            return [self._relativise(v) for v in value]
        if isinstance(value, dict) and "path" in value:
            return {**value, "path": self._relativise(value["path"])}
        return value

    def _mixed(self, message: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        short = short_name(name)
        confined = self.executor.confine(name, arguments)
        user_dry_run = bool(arguments.get("dry_run", True))
        writing = short in _WRITING_MIXED
        hub_args = {k: (self._relativise(v) if k in PATH_KEYS + PATH_LIST_KEYS else v) for k, v in confined.items()}
        hub_args.pop("cwd", None)
        if writing:
            hub_args["dry_run"] = True
            hub_args["local_files"] = self._read_local_files(confined)
        hub_message = {**message, "params": {**(message.get("params") or {}), "arguments": hub_args}}
        if not writing:
            return self._forward(hub_message)

        with FileLock(self.root / ".graqle" / "relay.lock"):
            before = self.snapshot()
            reply = self._forward(hub_message)
            if reply is None:
                raise MixedAbort("hub gave no answer; nothing was written")
            result = reply.get("result")
            if not isinstance(result, dict) or result.get("isError") or "error" in reply:
                return reply  # hub refused or failed: nothing to write
            writes = self._extract_writes(result)
            if not writes or user_dry_run:
                return reply
            after = self.snapshot()  # hub killed here -> MixedAbort, nothing written
            if after != before:
                raise MixedAbort("stale context: the hub graph changed while computing; nothing was written, resubmit")
            staged = self._stage(writes)
            for rel, content in staged:
                allowed, reason = self.gate(name, {"file_path": str(self.root / rel), "content": content, "dry_run": False})
                if not allowed:
                    raise MixedAbort(f"refused by the hub gate: {reason}; nothing was written")
            applied = self._commit(staged)
        return self._annotate(reply, applied)

    def _extract_writes(self, result: dict[str, Any]) -> list[tuple[str, dict[str, str]]]:
        try:
            text = result["content"][0]["text"]
            body = json.loads(text)
        except (KeyError, IndexError, TypeError, ValueError):
            return []
        found: list[tuple[str, dict[str, str]]] = []
        if isinstance(body, dict):
            for w in body.get("writes") or []:
                if isinstance(w, dict) and isinstance(w.get("file_path"), str) and isinstance(w.get("content"), str):
                    found.append((w["file_path"], {"content": w["content"]}))
            for p in body.get("patches") or []:
                if isinstance(p, dict) and isinstance(p.get("file_path"), str) and isinstance(p.get("unified_diff"), str) and p["unified_diff"]:
                    found.append((p["file_path"], {"diff": p["unified_diff"]}))
        return found

    def _stage(self, writes: list[tuple[str, dict[str, str]]]) -> list[tuple[str, str]]:
        staged: list[tuple[str, str]] = []
        for path, spec in writes:
            real = Path(_confine(path, self.root, "file_path"))  # confinement re-checked at write time
            rel = os.path.relpath(real, self.root)
            if "content" in spec:
                new = spec["content"]
            else:
                if not real.is_file():
                    raise MixedAbort(f"patch target {rel} does not exist locally; nothing was written")
                new = apply_unified_diff(real.read_text(encoding="utf-8"), spec["diff"])
            if rel.endswith(".py"):
                try:
                    ast.parse(new)
                except (SyntaxError, ValueError) as exc:
                    raise MixedAbort(f"result for {rel} is not valid Python ({type(exc).__name__}); nothing was written") from exc
            staged.append((rel, new))
        return staged

    def _commit(self, staged: list[tuple[str, str]]) -> list[str]:
        """Write every staged file; on any failure restore the ones already written."""
        backups: list[tuple[Path, str | None]] = []
        try:
            for rel, content in staged:
                target = self.root / rel
                old = target.read_text(encoding="utf-8") if target.is_file() else None
                backups.append((target, old))
                write_atomic(target, content)
        except BaseException:
            for target, old in reversed(backups):
                try:
                    if old is None:
                        target.unlink(missing_ok=True)
                    else:
                        write_atomic(target, old)
                except OSError as exc:
                    logger.error("relay rollback failed for %s (%s); file may be inconsistent", target, type(exc).__name__)
            raise
        return [rel for rel, _ in staged]

    @staticmethod
    def _annotate(reply: dict[str, Any], applied: list[str]) -> dict[str, Any]:
        try:
            text = reply["result"]["content"][0]["text"]
            body = json.loads(text)
            body["applied_locally"] = applied
            reply["result"]["content"][0]["text"] = json.dumps(body)
        except (KeyError, IndexError, TypeError, ValueError):
            pass
        return reply


__all__ = [
    "FileLock", "HUB", "HubUnavailable", "HybridDispatcher", "LOCAL", "MIXED",
    "MixedAbort", "apply_unified_diff",
]
