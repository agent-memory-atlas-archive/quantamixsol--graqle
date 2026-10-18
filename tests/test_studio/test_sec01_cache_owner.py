"""SEC-01 finding 1: project graph cache is keyed on (owner, project) and a
cache hit never skips owner verification."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import types
from types import SimpleNamespace

import pytest

from graqle.studio.routes import api


def _fake_boto3(graphs_by_owner: dict[str, str]):
    """boto3 stub: the S3 key's owner segment selects the stored graph."""
    calls: list[str] = []

    class _S3:
        def get_object(self, Bucket, Key):  # noqa: N803
            calls.append(Key)
            owner = Key.split("/")[1]
            graph = {"nodes": [{"id": graphs_by_owner[owner], "label": graphs_by_owner[owner]}], "links": []}
            return {"Body": io.BytesIO(json.dumps(graph).encode())}

    mod = types.ModuleType("boto3")
    mod.client = lambda *a, **k: _S3()
    return mod, calls


def _request():
    state = {"graph": None, "config": None}
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(studio_state=state)))


@pytest.fixture(autouse=True)
def _clear_cache():
    api._project_graph_cache.clear()
    yield
    api._project_graph_cache.clear()


def _run(coro):
    return asyncio.run(coro)


def test_two_owners_same_project_get_distinct_entries(monkeypatch):
    mod, _calls = _fake_boto3({"owner-a": "node-of-a", "owner-b": "node-of-b"})
    monkeypatch.setitem(sys.modules, "boto3", mod)
    current = {"owner": "owner-a"}
    monkeypatch.setattr(
        "graqle.studio.auth.resolve_graph_owner_prefix", lambda req: current["owner"]
    )
    req = _request()

    g_a = _run(api._load_project_graph(req, "default"))
    current["owner"] = "owner-b"
    g_b = _run(api._load_project_graph(req, "default"))

    assert g_a is not g_b
    assert "node-of-a" in g_a.nodes and "node-of-a" not in g_b.nodes
    assert "node-of-b" in g_b.nodes
    assert set(api._project_graph_cache) == {("owner-a", "default"), ("owner-b", "default")}


def test_cache_hit_still_verifies_owner(monkeypatch):
    mod, calls = _fake_boto3({"owner-a": "node-of-a"})
    monkeypatch.setitem(sys.modules, "boto3", mod)
    verifications = []
    identity = {"owner": "owner-a"}

    def _resolve(req):
        verifications.append(1)
        return identity["owner"]

    monkeypatch.setattr("graqle.studio.auth.resolve_graph_owner_prefix", _resolve)
    req = _request()

    assert _run(api._load_project_graph(req, "default")) is not None
    assert len(calls) == 1
    # second call is a cache hit (no new S3 read) but MUST still verify
    assert _run(api._load_project_graph(req, "default")) is not None
    assert len(calls) == 1
    assert len(verifications) == 2

    # revoked / invalid token: verification yields no owner -> rejected on a cache hit
    identity["owner"] = None
    assert _run(api._load_project_graph(req, "default")) is None
