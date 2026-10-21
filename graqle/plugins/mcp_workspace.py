"""Per-session workspace root for the shared HTTP MCP server (CR-INFRA-02e).

The relay sends its workspace root on every request in the
``X-Graqle-Workspace-Root`` header (percent-encoded). The server binds it once
at ``initialize`` (see ``mcp_http_transport``), checks it against the
``--allowed-roots`` allow-list and confines every path argument of a tool call
to it.

Threat model: sessions are our own builders under one OS user, so the goal is
"no mix-ups", not hostile-tenant isolation. ``graq_bash`` keeps its stdio
guarantees (cwd + existing gates) and is not sandboxed here.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

WORKSPACE_HEADER = "x-graqle-workspace-root"

# Single-path arguments of file tools; relative values are anchored at the root.
PATH_KEYS = (
    "file_path", "path", "stdout_path", "output_dir", "file", "memory_dir", "directory",
)
# List-of-path arguments.
PATH_LIST_KEYS = ("paths", "test_paths", "files")
# Tools that run a subprocess or tests: ``cwd`` defaults to the session root.
CWD_TOOLS = frozenset({
    "bash", "test", "git_status", "git_diff", "git_log", "git_commit", "git_branch",
    "github_diff",
})


DEFAULT_TO_ROOT = {"path": frozenset({"glob", "grep"}), "output_dir": frozenset({"scaffold"})}


class WorkspaceError(ValueError):
    """A workspace root or path argument was refused."""


def encode_root(root: str) -> str:
    """Header-safe encoding of a root path (headers are latin-1 only)."""
    return quote(root, safe="/:")


def parse_allowed_roots(spec: str | list[str]) -> list[Path]:
    """Resolve and existence-check an allow-list; raise ``WorkspaceError`` if invalid."""
    entries = spec.split(",") if isinstance(spec, str) else list(spec)
    entries = [e.strip() for e in entries if e and e.strip()]
    if not entries:
        raise WorkspaceError("--allowed-roots needs at least one directory")
    roots: list[Path] = []
    for entry in entries:
        try:
            resolved = Path(entry).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise WorkspaceError(f"invalid allowed root {entry!r}: {type(exc).__name__}") from exc
        if not resolved.is_dir():
            raise WorkspaceError(f"invalid allowed root {entry!r}: not a directory")
        roots.append(resolved)
    return roots


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def bind_root(header_value: str, allowed: list[Path]) -> Path:
    """Resolve the requested root (symlinks resolved) and check the allow-list."""
    raw = unquote(header_value or "").strip()
    if not raw:
        raise WorkspaceError("missing workspace root: send the X-Graqle-Workspace-Root header")
    try:
        root = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise WorkspaceError("workspace root does not exist") from exc
    if not root.is_dir():
        raise WorkspaceError("workspace root is not a directory")
    if not any(_inside(root, a) for a in allowed):
        raise WorkspaceError("workspace root is outside the allowed roots")
    return root


def _confine(value: Any, root: Path, key: str) -> str:
    if not isinstance(value, str):
        raise WorkspaceError(f"argument {key!r} must be a string path")
    candidate = Path(value)
    if ".." in candidate.parts:
        raise WorkspaceError(f"argument {key!r}: '..' is not allowed")
    if not candidate.is_absolute():
        candidate = root / candidate
    real = Path(os.path.realpath(candidate))  # resolves symlinks, also for new files
    if not _inside(real, root):
        raise WorkspaceError(f"argument {key!r} escapes the session workspace root")
    return str(real)


def _confine_item(item: Any, root: Path, key: str) -> Any:
    """A list entry is a path string, or a ``{"path": ...}`` object (batch edit)."""
    if isinstance(item, dict):
        if "path" in item:
            item["path"] = _confine(item["path"], root, key)
        return item
    return _confine(item, root, key)


def confine_arguments(root: Path, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *arguments* with every path resolved inside *root*.

    Raises ``WorkspaceError`` for ``..``, absolute paths outside the root and
    symlinks pointing outside. Called on every tool call, not only at bind time.
    """
    name = tool.split("_", 1)[1] if tool.startswith(("graq_", "kogni_")) else tool
    out = copy.deepcopy(arguments)
    for key in PATH_KEYS:
        if key in out and out[key] not in (None, ""):
            out[key] = _confine(out[key], root, key)
    for key in PATH_LIST_KEYS:
        if key in out and out[key] not in (None, ""):
            values = out[key]
            if not isinstance(values, list):
                raise WorkspaceError(f"argument {key!r} must be a list of paths")
            out[key] = [_confine_item(v, root, key) for v in values]
    if out.get("cwd") not in (None, ""):
        out["cwd"] = _confine(out["cwd"], root, "cwd")
    elif name in CWD_TOOLS:
        out["cwd"] = str(root)
    # Tools whose handler defaults a path to "." (the process cwd): default to the root.
    for key, tools in DEFAULT_TO_ROOT.items():
        if name in tools and out.get(key) in (None, ""):
            out[key] = str(root)
    return out
