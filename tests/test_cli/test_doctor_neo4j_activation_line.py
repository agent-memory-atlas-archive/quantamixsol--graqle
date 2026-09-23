"""CR-012 PR-012d (ruling N7) — the ``graq doctor`` activation line.

On a neo4j-first project, ``graq doctor`` must report whether semantic
activation can actually run: vector-index state plus chunk-embedding coverage.
Before this, a substrate with no index (or zero embeddings) produced a doctor
report that looked entirely healthy while every retrieval-dependent answer came
from a graph that could not activate.

These tests assert OBSERVABLE CLI BEHAVIOUR — the rendered report and the
check status — never source strings. The line must appear ONLY for neo4j-first
projects (review checklist item 4).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from graqle.cli.commands import doctor as doctor_mod


def _neo4j_yaml(tmp_path: Path) -> Path:
    cfg = tmp_path / "graqle.yaml"
    cfg.write_text(
        "graph:\n"
        "  connector: neo4j\n"
        "  uri: bolt://localhost:7687\n"
        "  username: neo4j\n"
        "  password: secret\n"
        "  database: research\n",
        encoding="utf-8",
    )
    return cfg


def _json_yaml(tmp_path: Path) -> Path:
    cfg = tmp_path / "graqle.yaml"
    cfg.write_text("graph:\n  connector: networkx\n", encoding="utf-8")
    return cfg


class _FakeConnector:
    """Stands in for Neo4jConnector; records that close() is honoured."""

    instances: list[_FakeConnector] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.closed = False
        self.probe: dict[str, Any] = {}
        _FakeConnector.instances.append(self)

    def probe_vector_index(self) -> dict[str, Any]:
        return dict(self.probe)

    def close(self) -> None:
        self.closed = True


def _install_fake(monkeypatch: pytest.MonkeyPatch, probe: dict[str, Any]) -> None:
    """Patch Neo4jConnector, tolerating a CI env with no `neo4j` driver.

    `graqle.connectors.neo4j` imports the optional driver at module load, and
    CI installs only the [dev] extra. Insert a stub module when the real one
    cannot import, so these tests exercise the doctor logic rather than the
    availability of an optional dependency.
    """
    _FakeConnector.instances.clear()

    def _factory(**kwargs: Any) -> _FakeConnector:
        conn = _FakeConnector(**kwargs)
        conn.probe = probe
        return conn

    try:
        import graqle.connectors.neo4j as neo4j_mod
    except ImportError:  # pragma: no cover - only on a driver-less install
        import sys
        import types

        neo4j_mod = types.ModuleType("graqle.connectors.neo4j")
        monkeypatch.setitem(sys.modules, "graqle.connectors.neo4j", neo4j_mod)

    monkeypatch.setattr(neo4j_mod, "Neo4jConnector", _factory, raising=False)


def _activation_rows(results: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    return [r for r in results if r[1] == "Neo4j: activation"]


_UNUSABLE = {
    "index_name": "cogni_chunk_embedding_index",
    "database": "research",
    "index_state": "NOT_FOUND",
    "chunks_total": 3722,
    "chunks_embedded": 0,
    "usable": False,
}
_USABLE = {**_UNUSABLE, "index_state": "ONLINE", "chunks_embedded": 3722, "usable": True}


class TestNeo4jFirstProjects:
    def test_unusable_substrate_is_reported_as_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _neo4j_yaml(tmp_path)
        _install_fake(monkeypatch, _UNUSABLE)

        rows = _activation_rows(doctor_mod._check_neo4j_backend())
        assert rows, "neo4j-first project must get an activation line"
        status, _, detail = rows[0]
        assert status == doctor_mod.FAIL
        assert "0/3722" in detail
        assert "NOT_FOUND" in detail

    def test_healthy_substrate_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _neo4j_yaml(tmp_path)
        _install_fake(monkeypatch, _USABLE)

        rows = _activation_rows(doctor_mod._check_neo4j_backend())
        assert rows
        status, _, detail = rows[0]
        assert status == doctor_mod.PASS
        assert "3722/3722" in detail

    def test_zero_embeddings_with_online_index_still_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The D1 shape: index exists and is ONLINE, but nothing is embedded,
        # so it can never match. Must NOT read as healthy.
        monkeypatch.chdir(tmp_path)
        _neo4j_yaml(tmp_path)
        _install_fake(monkeypatch, {**_UNUSABLE, "index_state": "ONLINE"})

        rows = _activation_rows(doctor_mod._check_neo4j_backend())
        assert rows and rows[0][0] == doctor_mod.FAIL

    def test_connector_is_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _neo4j_yaml(tmp_path)
        _install_fake(monkeypatch, _USABLE)

        doctor_mod._check_neo4j_backend()
        assert _FakeConnector.instances, "connector should have been constructed"
        assert all(c.closed for c in _FakeConnector.instances)

    def test_probe_failure_degrades_to_warning_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _neo4j_yaml(tmp_path)

        def _boom(**kwargs: Any) -> Any:
            raise RuntimeError("connection refused")

        import graqle.connectors.neo4j as neo4j_mod

        monkeypatch.setattr(neo4j_mod, "Neo4jConnector", _boom, raising=True)

        rows = _activation_rows(doctor_mod._check_neo4j_backend())
        # doctor must never crash; it reports the probe failure instead.
        assert not rows or rows[0][0] == doctor_mod.WARN


class TestNonNeo4jProjects:
    def test_no_activation_line_on_json_backend(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Review checklist (4): the line exists ONLY for neo4j-first projects.
        monkeypatch.chdir(tmp_path)
        _json_yaml(tmp_path)

        assert _activation_rows(doctor_mod._check_neo4j_backend()) == []

    def test_no_activation_line_without_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert _activation_rows(doctor_mod._check_neo4j_backend()) == []


class TestDriverAbsent:
    """CI installs only [dev], so the optional neo4j driver is missing there.

    The activation line previously lived inside a try block headed by
    `from neo4j import GraphDatabase`; on a driver-less install that raised and
    skipped the whole block, so the check silently vanished — the exact class
    of invisible gap ruling N7 exists to close. A missing driver is itself a
    reportable answer.
    """

    def test_missing_driver_is_reported_not_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def _no_connector(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "graqle.connectors.neo4j":
                raise ImportError("No module named neo4j")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _no_connector)

        rows = _activation_rows(doctor_mod._check_neo4j_activation({"graph": {}}))
        assert rows, "a missing driver must still produce an activation row"
        assert rows[0][0] == doctor_mod.FAIL
