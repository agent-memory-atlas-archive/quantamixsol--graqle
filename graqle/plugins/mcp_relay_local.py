"""Local executor of the hybrid relay (CR-INFRA-02f).

Runs the LOCAL tools in-process on the user's own workspace root, with the
user's own permissions. It never loads a graph and imports no ML code: standard
library only (plus ``mcp_workspace``, which is also standard library only).

Confinement is checked here, at the relay, on every call: ``..``, absolute
paths outside the root and symlinks that leave the root are refused. Mutating
tools are gated by the caller (``mcp_relay_hybrid``) before ``execute`` runs.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from graqle.plugins.mcp_relay_routing import LOCAL_IMPLEMENTED, short_name
from graqle.plugins.mcp_workspace import WorkspaceError, _confine, confine_arguments

MAX_BASH_TIMEOUT_S = 120
_BLOCKED_COMMANDS = (
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r"),
    re.compile(r"git\s+push\b.*(--force|\s-f\b)"),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\bpip3?\s+install\b"),
)


class LocalToolError(RuntimeError):
    """A local tool was refused or failed; the message is shown to the client."""


def _err(message: str, **extra: Any) -> str:
    return json.dumps({"error": message, **extra})


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


class LocalExecutor:
    """Executes LOCAL tools for one workspace root."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise LocalToolError(f"workspace root is not a directory: {self.root}")

    # -- confinement -------------------------------------------------------
    def confine(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Resolve every path argument inside the root (raises ``WorkspaceError``)."""
        out = confine_arguments(self.root, tool, arguments)
        if out.get("target") not in (None, ""):  # graq_test target is a path too
            out["target"] = _confine(out["target"], self.root, "target")
        return out

    # -- dispatch ----------------------------------------------------------
    def execute(self, tool: str, arguments: dict[str, Any]) -> str:
        """Run *tool* (already confined by :meth:`confine`); return a JSON string."""
        name = short_name(tool)
        if name not in LOCAL_IMPLEMENTED:
            return _err(
                f"{tool} has no local executor in this relay; it is not forwarded to the "
                "shared server's disk. Use a supported local tool."
            )
        return getattr(self, f"_do_{name}")(arguments)

    # -- read-only tools ---------------------------------------------------
    def _do_read(self, a: dict[str, Any]) -> str:
        file_path = a.get("file_path", "")
        if not file_path:
            return _err("Parameter 'file_path' is required.")
        offset = max(1, int(a.get("offset", 1)))
        limit = min(max(1, int(a.get("limit", 500))), 2000)
        fp = Path(file_path)
        if not fp.exists():
            return _err(f"File not found: {file_path}", exists=False)
        if fp.is_dir():
            return _err(f"Path is a directory: {file_path}")
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return _err(f"Read failed: {type(exc).__name__}")
        selected = lines[offset - 1: offset - 1 + limit]
        return json.dumps({
            "file_path": str(fp),
            "content": "\n".join(f"{offset + i:>6}\t{line}" for i, line in enumerate(selected)),
            "lines_returned": len(selected),
            "total_lines": len(lines),
            "offset": offset,
            "limit": limit,
            "truncated": (offset - 1 + limit) < len(lines),
        })

    def _files_under(self, base: Path, pattern: str | None, recursive: bool) -> list[Path]:
        if base.is_file():
            candidates = [base]
        elif pattern is None:
            candidates = [p for p in base.rglob("*") if not any(part.startswith(".") for part in p.relative_to(base).parts)]
        else:
            candidates = list(base.rglob(pattern) if recursive else base.glob(pattern))
        kept = []
        for p in candidates:
            try:
                real = Path(os.path.realpath(p))
            except OSError:
                continue
            if real.is_file() and _inside(real, self.root):  # symlinks leaving the root are skipped
                kept.append(p)
        return kept

    def _do_glob(self, a: dict[str, Any]) -> str:
        pattern = a.get("pattern", "")
        if not pattern:
            return _err("Parameter 'pattern' is required.")
        if ".." in Path(pattern).parts or Path(pattern).is_absolute():
            return _err("pattern must be relative and must not contain '..'")
        base = Path(a.get("path") or self.root)
        max_results = min(int(a.get("max_results", 100)), 1000)
        try:
            files = sorted(self._files_under(base, pattern, "**" in pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError as exc:
            return _err(f"Glob failed: {type(exc).__name__}")
        out = [str(p) for p in files][:max_results]
        return json.dumps({"pattern": pattern, "files": out, "total": len(out), "truncated": len(out) >= max_results})

    def _do_grep(self, a: dict[str, Any]) -> str:
        pattern = a.get("pattern", "")
        if not pattern:
            return _err("Parameter 'pattern' is required.")
        glob_filter = a.get("glob") or None
        if glob_filter and (".." in Path(glob_filter).parts or Path(glob_filter).is_absolute()):
            return _err("glob must be relative and must not contain '..'")
        context_lines = min(int(a.get("context_lines", 0)), 5)
        max_results = min(int(a.get("max_results", 50)), 500)
        try:
            compiled = re.compile(pattern, re.IGNORECASE if a.get("case_insensitive") else 0)
        except re.error as exc:
            return _err(f"Invalid regex: {exc}")
        base = Path(a.get("path") or self.root)
        matches: list[dict[str, Any]] = []
        try:
            files = sorted(self._files_under(base, glob_filter, True))[:1000]
        except OSError as exc:
            return _err(f"Grep failed: {type(exc).__name__}")
        for fp in files:
            if len(matches) >= max_results:
                break
            try:
                file_lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(file_lines):
                if compiled.search(line):
                    matches.append({
                        "file": str(fp), "line_number": i + 1, "line": line,
                        "context_before": file_lines[max(0, i - context_lines):i],
                        "context_after": file_lines[i + 1:i + 1 + context_lines],
                    })
                    if len(matches) >= max_results:
                        break
        return json.dumps({
            "pattern": pattern, "matches": matches, "total_matches": len(matches),
            "truncated": len(matches) >= max_results,
        })

    # -- git ---------------------------------------------------------------
    def _git(self, cwd: str, *argv: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 (fixed argv, no shell)
            ["git", *argv], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
        )

    def _git_result(self, proc: subprocess.CompletedProcess[str], **extra: Any) -> str:
        return json.dumps({
            "stdout": proc.stdout[:8000], "stderr": proc.stderr[:1000],
            "exit_code": proc.returncode, "success": proc.returncode == 0, **extra,
        })

    def _do_git_status(self, a: dict[str, Any]) -> str:
        return self._git_result(self._git(a["cwd"], "status", "--short", "--branch"))

    def _do_git_diff(self, a: dict[str, Any]) -> str:
        argv = ["diff"]
        if a.get("staged"):
            argv.append("--staged")
        base_ref = str(a.get("base_ref") or "")
        if base_ref:
            if base_ref.startswith("-"):
                return _err("base_ref must not start with '-'")
            argv.append(base_ref)
        if a.get("file_path"):
            argv += ["--", a["file_path"]]
        return self._git_result(self._git(a["cwd"], *argv))

    def _do_git_log(self, a: dict[str, Any]) -> str:
        n = min(max(1, int(a.get("n", 10))), 50)
        argv = ["log", f"-{n}", "--oneline"]
        if a.get("file_path"):
            argv += ["--", a["file_path"]]
        return self._git_result(self._git(a["cwd"], *argv))

    def _do_git_commit(self, a: dict[str, Any]) -> str:
        message = str(a.get("message", "")).strip()
        if not message:
            return _err("Parameter 'message' is required.")
        files = a.get("files") or []
        if not isinstance(files, list):
            return _err("'files' must be a list of paths")
        if bool(a.get("dry_run", True)):
            return json.dumps({"dry_run": True, "message": message, "files": files})
        if files:  # explicit paths only, never `git add -A`
            proc = self._git(a["cwd"], "add", "--", *files)
            if proc.returncode != 0:
                return self._git_result(proc, step="add")
        return self._git_result(self._git(a["cwd"], "commit", "-m", message), step="commit")

    def _do_git_branch(self, a: dict[str, Any]) -> str:
        action = a.get("action", "create_and_switch")
        name = str(a.get("name", "")).strip()
        if action == "list":
            return self._git_result(self._git(a["cwd"], "branch", "--list"))
        if not name or name.startswith("-"):
            return _err("Parameter 'name' is required and must not start with '-'.")
        if action == "create_and_switch":
            return self._git_result(self._git(a["cwd"], "switch", "-c", name))
        if action == "switch":
            return self._git_result(self._git(a["cwd"], "switch", name))
        return _err(f"unsupported action {action!r}")

    # -- mutating tools ----------------------------------------------------
    def _do_write(self, a: dict[str, Any]) -> str:
        file_path = a.get("file_path") or a.get("path") or ""
        content = a.get("content")
        if not file_path:
            return _err("Parameter 'file_path' is required.")
        if not isinstance(content, str):
            return _err("Parameter 'content' is required.")
        if bool(a.get("dry_run", True)):
            return json.dumps({"dry_run": True, "file_path": file_path, "bytes": len(content.encode("utf-8"))})
        write_atomic(Path(file_path), content)
        return json.dumps({"file_path": file_path, "written": True, "bytes": len(content.encode("utf-8"))})

    def _do_bash(self, a: dict[str, Any]) -> str:
        command = str(a.get("command", "")).strip()
        if not command:
            return _err("Parameter 'command' is required.")
        if bool(a.get("dry_run", False)):
            return json.dumps({"dry_run": True, "command": command})
        for rule in _BLOCKED_COMMANDS:
            if rule.search(command):
                return _err("command blocked by the relay's local blocklist", command=command)
        timeout = min(max(1, int(a.get("timeout", 30))), MAX_BASH_TIMEOUT_S)
        try:
            proc = subprocess.run(  # noqa: S602 (shell is the tool's purpose; gated on the hub)
                command, shell=True, capture_output=True, text=True, timeout=timeout,
                cwd=a.get("cwd") or str(self.root), check=False,
            )
        except subprocess.TimeoutExpired:
            return _err(f"Command timed out after {timeout}s", command=command)
        stdout = proc.stdout or ""
        extra: dict[str, Any] = {}
        if a.get("stdout_path"):
            write_atomic(Path(a["stdout_path"]), stdout)
            extra = {"stdout_path": a["stdout_path"], "stdout_bytes_written": len(stdout.encode("utf-8", "replace"))}
        return json.dumps({
            "command": command, "stdout": stdout[:4000], "stderr": (proc.stderr or "")[:1000],
            "exit_code": proc.returncode, "success": proc.returncode == 0,
            "truncated": len(stdout) > 4000, **extra,
        })

    def _do_test(self, a: dict[str, Any]) -> str:
        target = str(a.get("target") or "tests/").strip() or "tests/"
        interpreter = shutil.which("python") or sys.executable
        argv = [interpreter, "-m", "pytest", target, "-q"]
        if a.get("fail_fast"):
            argv.append("-x")
        try:
            proc = subprocess.run(  # noqa: S603 (fixed argv)
                argv, capture_output=True, text=True, timeout=MAX_BASH_TIMEOUT_S * 5,
                cwd=a.get("cwd") or str(self.root), check=False,
            )
        except subprocess.TimeoutExpired:
            return _err("tests timed out")
        except OSError as exc:
            return _err(f"could not start tests: {type(exc).__name__}")
        return json.dumps({
            "target": target, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-1000:],
            "exit_code": proc.returncode, "passed": proc.returncode == 0,
        })


def write_atomic(path: Path, content: str) -> None:
    """Write *content* to *path* through a temp file in the same directory + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


__all__ = ["LocalExecutor", "LocalToolError", "WorkspaceError", "write_atomic"]
