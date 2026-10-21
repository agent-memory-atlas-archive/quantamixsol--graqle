"""CR-INFRA-02 PR-d: lazy load / idle unload / memory-budget LRU eviction (AC 8).

Clock and process memory are mocked; the servers are fakes that record loads,
so every assertion is about the hub's lifecycle decisions.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from graqle.plugins import mcp_project_hub as hub_mod
from graqle.plugins.mcp_project_hub import (
    HubConfigError,
    HubSettings,
    ProjectHub,
    ProjectSpec,
    load_projects_file,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class World:
    """Mocked process memory plus a log of graph loads."""

    def __init__(self, sizes: dict[str, float]) -> None:
        self.rss = 100.0
        self.sizes = sizes
        self.loads: list[str] = []
        self.gate: threading.Event | None = None
        self.fail: set[str] = set()

    def probe(self) -> float:
        return self.rss


class FakeServer:
    def __init__(self, world: World, spec: ProjectSpec) -> None:
        self.world = world
        self.spec = spec
        self._bg_grow_watcher = None
        self.loaded = False

    def _load_graph(self):
        if self.world.gate is not None:
            self.world.gate.wait(5)
        if self.spec.name in self.world.fail:
            return None
        self.world.loads.append(self.spec.name)
        self.world.rss += self.world.sizes[self.spec.name]
        self.loaded = True
        return object()

    async def _handle_jsonrpc(self, message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"project": self.spec.name}}


def _hub(tmp_path: Path, names: list[str], sizes=None, idle=None, budget=None):
    world = World(sizes or {n: 10.0 for n in names})
    clock = Clock()
    specs = {}
    for n in names:
        (tmp_path / n).mkdir(exist_ok=True)
        specs[n] = ProjectSpec(name=n, root=tmp_path / n)
    hub = ProjectHub(
        HubSettings(specs, idle_seconds=idle, memory_budget_mb=budget),
        lambda spec: FakeServer(world, spec),
        clock=clock,
        memory_probe=world.probe,
    )
    return hub, world, clock


def _call(i: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "graq_inspect", "arguments": {}}}


async def _use(hub: ProjectHub, name: str) -> dict:
    """First tools/call triggers the load; wait for it, then call again."""
    reply = await hub.dispatch(name, _call())
    task = hub._entries[name].task
    if task is not None:
        await task
        reply = await hub.dispatch(name, _call())
    return reply


def test_lazy_load_nothing_loaded_until_first_tool_call(tmp_path):
    hub, world, _ = _hub(tmp_path, ["a", "b"])

    async def run():
        init = await hub.dispatch("a", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        listing = await hub.dispatch("a", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert init["result"]["project"] == "a" and listing["result"]["project"] == "a"
        assert world.loads == [] and hub.loaded_names() == []

        reply = await _use(hub, "a")
        assert reply["result"] == {"project": "a"}
        assert world.loads == ["a"]
        assert hub.loaded_names() == ["a"]  # b was never touched, never loaded

    asyncio.run(run())


def test_loading_status_is_explicit_and_no_partial_graph_served(tmp_path):
    hub, world, _ = _hub(tmp_path, ["a"])
    world.gate = threading.Event()

    async def run():
        first = await hub.dispatch("a", _call(1))
        assert first["result"]["isError"] is True
        assert first["result"]["content"][0]["text"].startswith("PROJECT_LOADING")
        assert hub.status("a") == "loading"
        second = await hub.dispatch("a", _call(2))  # still loading: same answer, no second load
        assert second["result"]["content"][0]["text"].startswith("PROJECT_LOADING")

        world.gate.set()
        await hub._entries["a"].task
        assert hub.status("a") == "loaded"
        assert (await hub.dispatch("a", _call(3)))["result"] == {"project": "a"}
        assert world.loads == ["a"]

    asyncio.run(run())


def test_failed_load_is_reported_then_retried_never_served(tmp_path):
    hub, world, _ = _hub(tmp_path, ["a"])
    world.fail.add("a")

    async def run():
        await hub.dispatch("a", _call())
        await hub._entries["a"].task
        assert hub.status("a") == "unloaded"
        reply = await hub.dispatch("a", _call())
        assert reply["result"]["isError"] is True
        assert reply["result"]["content"][0]["text"].startswith("PROJECT_LOAD_FAILED")
        world.fail.clear()
        assert (await _use(hub, "a"))["result"] == {"project": "a"}  # retry succeeds

    asyncio.run(run())


def test_idle_unload_after_configured_time_and_reload_on_next_use(tmp_path):
    hub, world, clock = _hub(tmp_path, ["a", "b"], idle=300)

    async def run():
        await _use(hub, "a")
        await _use(hub, "b")
        clock.now += 200
        await _use(hub, "b")  # b stays fresh
        assert hub.sweep() == []  # nobody idle longer than 300 yet
        clock.now += 150  # a idle 350 > 300, b idle 150
        assert hub.sweep() == ["a"]
        assert hub.loaded_names() == ["b"]
        assert hub._entries["a"].server is None  # graph memory released
        await _use(hub, "a")
        assert world.loads == ["a", "b", "a"]

    asyncio.run(run())


def test_idle_unload_never_drops_a_project_with_a_request_in_flight(tmp_path):
    hub, _, clock = _hub(tmp_path, ["a"], idle=10)

    async def run():
        await _use(hub, "a")
        hub._entries["a"].in_flight = 1
        clock.now += 1000
        assert hub.sweep() == []
        hub._entries["a"].in_flight = 0
        assert hub.sweep() == ["a"]

    asyncio.run(run())


def test_idle_unload_disabled_when_not_configured(tmp_path):
    hub, _, clock = _hub(tmp_path, ["a"])

    async def run():
        await _use(hub, "a")
        clock.now += 10**6
        assert hub.sweep() == []
        assert hub.loaded_names() == ["a"]

    asyncio.run(run())


def test_budget_evicts_least_recently_used_first(tmp_path):
    hub, world, clock = _hub(
        tmp_path, ["a", "b", "c"], sizes={"a": 40.0, "b": 40.0, "c": 40.0}, budget=100
    )

    async def run():
        await _use(hub, "a")
        clock.now += 1
        await _use(hub, "b")
        clock.now += 1
        await _use(hub, "a")  # a is now more recent than b
        clock.now += 1
        await _use(hub, "c")  # 120 MB > 100: evict LRU = b
        assert sorted(hub.loaded_names()) == ["a", "c"]
        assert hub._entries["b"].server is None

    asyncio.run(run())


def test_budget_never_evicts_in_flight_or_the_project_just_loaded(tmp_path):
    hub, _, clock = _hub(tmp_path, ["a", "b"], sizes={"a": 80.0, "b": 80.0}, budget=100)

    async def run():
        await _use(hub, "a")
        hub._entries["a"].in_flight = 1
        clock.now += 1
        await _use(hub, "b")
        assert sorted(hub.loaded_names()) == ["a", "b"]  # over budget, nothing evictable
        hub._entries["a"].in_flight = 0

    asyncio.run(run())


def test_unmeasurable_memory_with_budget_refuses_to_start(tmp_path):
    def broken() -> float:
        raise HubConfigError("cannot measure")

    (tmp_path / "a").mkdir()
    settings = HubSettings({"a": ProjectSpec("a", tmp_path / "a")}, memory_budget_mb=100)
    with pytest.raises(HubConfigError):
        ProjectHub(settings, lambda s: None, memory_probe=broken)


def test_process_rss_probe_reads_a_positive_number_on_this_platform():
    assert hub_mod.process_rss_mb() > 0


def test_projects_file_valid_and_invalid(tmp_path):
    (tmp_path / "pa").mkdir()
    good = tmp_path / "projects.yaml"
    good.write_text(
        "idle_seconds: 60\nmemory_budget_mb: 2048\nprojects:\n  alpha:\n    root: pa\n", encoding="utf-8"
    )
    settings = load_projects_file(good)
    assert settings.idle_seconds == 60 and settings.memory_budget_mb == 2048
    assert settings.projects["alpha"].root == (tmp_path / "pa").resolve()
    assert settings.projects["alpha"].config == str((tmp_path / "pa").resolve() / "graqle.yaml")

    bad_cases = [
        "projects: {}\n",
        "projects:\n  'bad name!':\n    root: pa\n",
        "projects:\n  alpha:\n    root: missing_dir\n",
        "idle_seconds: -5\nprojects:\n  alpha:\n    root: pa\n",
        "memory_budget_mb: true\nprojects:\n  alpha:\n    root: pa\n",
        "not: a projects file\n",
    ]
    for text in bad_cases:
        bad = tmp_path / "bad.yaml"
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(HubConfigError):
            load_projects_file(bad)
    with pytest.raises(HubConfigError):
        load_projects_file(tmp_path / "does_not_exist.yaml")
