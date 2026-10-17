"""Multi-project hub for the shared GraQle MCP HTTP server (CR-INFRA-02 PR-d).

One server process hosts several project graphs. Each project gets its OWN
``KogniDevServer`` (own config, own graph, own caches, own cost counters); graphs
are never merged and a session is bound to exactly one project at connect time.

Lifecycle of a project's graph:
  * lazy load   - nothing is loaded until the first ``tools/call`` for the project;
                  while the load runs, requests answer with a clear "loading"
                  tool error (never a partial graph);
  * idle unload - a graph unused for ``idle_seconds`` is dropped (``sweep``);
  * LRU budget  - when the measured memory of loaded graphs exceeds
                  ``memory_budget_mb``, least-recently-used idle graphs are
                  dropped first (never one with a request in flight).

Known limitation (documented, not hidden): the working directory is process
global and the dev server resolves some paths against it, so the hub holds one
dispatch lock and ``chdir`` into the project root around every load and every
tool call. Requests across projects are therefore serialised.

Fail closed: a bad projects file, an unknown project, an unmeasurable memory
budget or a failed load is an explicit error, never a fallback to another graph.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

logger = logging.getLogger("graqle.mcp_project_hub")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

ERR_LOADING = "PROJECT_LOADING"
ERR_LOAD_FAILED = "PROJECT_LOAD_FAILED"


class HubConfigError(RuntimeError):
    """Raised when the projects file or hub settings are invalid."""


@dataclass(frozen=True)
class ProjectSpec:
    name: str
    root: Path
    config: str = "graqle.yaml"


@dataclass(frozen=True)
class HubSettings:
    projects: dict[str, ProjectSpec]
    idle_seconds: float | None = None
    memory_budget_mb: float | None = None


def _positive(value: Any, key: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise HubConfigError(f"{key} must be a positive number, got {value!r}")
    return float(value)


def load_projects_file(path: str | os.PathLike[str]) -> HubSettings:
    """Parse ``projects.yaml``; raise ``HubConfigError`` on anything unsafe."""
    import yaml

    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise HubConfigError(f"cannot read projects file {path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("projects"), dict) or not raw["projects"]:
        raise HubConfigError("projects file needs a non-empty 'projects' mapping")
    base = Path(path).resolve().parent
    projects: dict[str, ProjectSpec] = {}
    for name, entry in raw["projects"].items():
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise HubConfigError(f"invalid project name {name!r} (use letters, digits, _ . -)")
        if not isinstance(entry, dict) or not isinstance(entry.get("root"), str):
            raise HubConfigError(f"project {name!r} needs a 'root' directory")
        root = Path(entry["root"])
        root = (root if root.is_absolute() else base / root).resolve()
        if not root.is_dir():
            raise HubConfigError(f"project {name!r}: root {root} is not a directory")
        config = entry.get("config", "graqle.yaml")
        if not isinstance(config, str):
            raise HubConfigError(f"project {name!r}: 'config' must be a path string")
        config_path = Path(config)
        if not config_path.is_absolute():
            config_path = root / config_path
        projects[name] = ProjectSpec(name=name, root=root, config=str(config_path))
    return HubSettings(
        projects=projects,
        idle_seconds=_positive(raw.get("idle_seconds"), "idle_seconds"),
        memory_budget_mb=_positive(raw.get("memory_budget_mb"), "memory_budget_mb"),
    )


def process_rss_mb() -> float:
    """Resident set size of this process in MB; raises if it cannot be measured."""
    try:
        import psutil

        return psutil.Process().memory_info().rss / (1024 * 1024)
    except ImportError:
        pass
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            pages = int(fh.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except (OSError, ValueError, IndexError, AttributeError) as exc:
        raise HubConfigError(
            "cannot measure process memory for memory_budget_mb; install psutil"
        ) from exc


@contextmanager
def _in_directory(path: Path) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


@dataclass
class _Entry:
    spec: ProjectSpec
    server: Any = None
    state: str = "unloaded"  # unloaded | loading | loaded
    mb: float = 0.0
    last_used: float = 0.0
    in_flight: int = 0
    task: asyncio.Task | None = field(default=None, repr=False)
    error: str | None = None


def _tool_error(message: dict[str, Any], code: str, text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "result": {"content": [{"type": "text", "text": f"{code}: {text}"}], "isError": True},
    }


class ProjectHub:
    """Owns one lazily loaded ``KogniDevServer`` per project."""

    def __init__(
        self,
        settings: HubSettings,
        server_factory: Callable[[ProjectSpec], Any],
        clock: Callable[[], float] = time.monotonic,
        memory_probe: Callable[[], float] = process_rss_mb,
    ) -> None:
        self.settings = settings
        self._factory = server_factory
        self._clock = clock
        self._probe = memory_probe
        self._entries = {n: _Entry(spec=s) for n, s in settings.projects.items()}
        self._lock: asyncio.Lock | None = None  # bound to the running loop on first use
        if settings.memory_budget_mb is not None:
            self._probe()  # fail at start-up, not at the first load, if unmeasurable

    # -- introspection -------------------------------------------------
    def has(self, name: str) -> bool:
        return name in self._entries

    def status(self, name: str) -> str:
        return self._entries[name].state

    def loaded_names(self) -> list[str]:
        return [n for n, e in self._entries.items() if e.state == "loaded"]

    def _dispatch_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    # -- unload / eviction ---------------------------------------------
    def _unload(self, entry: _Entry) -> None:
        watcher = getattr(entry.server, "_bg_grow_watcher", None)
        if watcher is not None:
            try:
                watcher.stop()
            except Exception as exc:  # noqa: BLE001 - unload must still release the graph
                logger.warning("project %s: watcher stop failed: %s", entry.spec.name, exc)
        entry.server = None
        entry.state = "unloaded"
        entry.mb = 0.0
        gc.collect()
        logger.info("project %s: graph unloaded", entry.spec.name)

    def sweep(self) -> list[str]:
        """Unload loaded graphs idle longer than ``idle_seconds``; return their names."""
        limit = self.settings.idle_seconds
        if limit is None:
            return []
        now = self._clock()
        dropped = []
        for name, entry in self._entries.items():
            if entry.state == "loaded" and entry.in_flight == 0 and now - entry.last_used > limit:
                self._unload(entry)
                dropped.append(name)
        return dropped

    def _evict_to_budget(self, keep: _Entry) -> list[str]:
        budget = self.settings.memory_budget_mb
        if budget is None:
            return []
        dropped = []
        while sum(e.mb for e in self._entries.values() if e.state == "loaded") > budget:
            victims = [
                e for e in self._entries.values()
                if e.state == "loaded" and e is not keep and e.in_flight == 0
            ]
            if not victims:
                logger.warning("memory budget %.0f MB exceeded and nothing is evictable", budget)
                break
            victim = min(victims, key=lambda e: e.last_used)
            self._unload(victim)
            dropped.append(victim.spec.name)
        return dropped

    # -- loading -------------------------------------------------------
    def _load_blocking(self, entry: _Entry) -> None:
        before = self._probe() if self.settings.memory_budget_mb is not None else 0.0
        with _in_directory(entry.spec.root):
            graph = entry.server._load_graph()
        if graph is None:
            raise RuntimeError("graph could not be loaded from the project's own source")
        if self.settings.memory_budget_mb is not None:
            entry.mb = max(self._probe() - before, 0.0)

    async def _load(self, entry: _Entry) -> None:
        try:
            async with self._dispatch_lock():
                await asyncio.to_thread(self._load_blocking, entry)
            entry.state = "loaded"
            entry.error = None
            self._evict_to_budget(keep=entry)
        except Exception as exc:  # noqa: BLE001 - fail closed: record, never serve a partial graph
            logger.error("project %s: load failed: %s", entry.spec.name, exc)
            entry.error = f"{type(exc).__name__}: {exc}"
            entry.server = None
            entry.state = "unloaded"
            entry.mb = 0.0

    def _ensure_server(self, entry: _Entry) -> Any:
        if entry.server is None:
            server = self._factory(entry.spec)
            # The server's own `initialize` handler would start a background graph
            # load from the process cwd (not the project root). Any state other
            # than IDLE makes it skip that; the hub loads the graph itself, under
            # the project root, via `_load_graph` (which loads synchronously here).
            server._kg_load_state = "HUB_MANAGED"
            entry.server = server
        return entry.server

    # -- request dispatch ----------------------------------------------
    async def dispatch(self, name: str, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC *message* for project *name* (must exist)."""
        entry = self._entries[name]
        self.sweep()
        entry.last_used = self._clock()

        if message.get("method") == "tools/call":
            if entry.state == "unloaded":
                if entry.error is not None:  # report a failed load once; the next call retries
                    text = f"project {name!r} failed to load: {entry.error}"
                    entry.error = None
                    return _tool_error(message, ERR_LOAD_FAILED, text)
                self._ensure_server(entry)
                entry.state = "loading"
                entry.task = asyncio.ensure_future(self._load(entry))
            if entry.state == "loading":
                return _tool_error(
                    message, ERR_LOADING, f"project {name!r} is loading its graph; retry shortly"
                )

        server = self._ensure_server(entry)
        entry.in_flight += 1
        try:
            async with self._dispatch_lock():
                with _in_directory(entry.spec.root):
                    return await server._handle_jsonrpc(message)
        finally:
            entry.in_flight -= 1
            entry.last_used = self._clock()
