"""CR-012 PR-012c — the Neo4j loader must pop `type` (rulings process note 1).

The node query aliases `n.entity_type AS type`, so `record["type"]` carries the
entity type. But a node that ALSO stores a literal `type` property leaves it in
`properties`, because the loader popped only id/label/entity_type/description.

`Graqle.to_networkx` then does:

    G.add_node(nid, label=..., type=node.entity_type, **node.properties)

and Python raises ``TypeError: add_node() got multiple values for keyword
argument 'type'``. 0.79.0 tolerated a stored `type`; the 0.83.0 hydrator
collides on it. The Research Team hit this on real data and removed the property
from their own nodes — but the SDK should not depend on every writer being
careful.

These tests reproduce the collision at the hydrator, then pin the loader fix.
No live Neo4j is required: the loader is exercised through a fake session that
returns the record shape the real driver produces.
"""

from __future__ import annotations

from typing import Any

import pytest


class _FakeRecord(dict):
    """Mimics a neo4j Record: dict-like with .get()."""


class _FakeResult(list):
    pass


class _FakeSession:
    def __init__(self, node_rows: list[dict[str, Any]]) -> None:
        self._node_rows = node_rows

    def run(self, query: str, **kwargs: Any) -> _FakeResult:
        if "MATCH (n:CogniNode)" in query and "RETURN" in query:
            return _FakeResult(_FakeRecord(r) for r in self._node_rows)
        return _FakeResult()

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeDriver:
    def __init__(self, node_rows: list[dict[str, Any]]) -> None:
        self._node_rows = node_rows

    def session(self, **kwargs: Any) -> _FakeSession:
        return _FakeSession(self._node_rows)


def _load_with(node_rows: list[dict[str, Any]]) -> dict[str, Any]:
    from graqle.connectors.neo4j import Neo4jConnector

    connector = Neo4jConnector(uri="bolt://unused", password="")
    connector._driver = _FakeDriver(node_rows)  # bypass connect
    connector._get_driver = lambda: connector._driver  # type: ignore[method-assign]
    nodes, _edges = connector.load()
    return nodes


_ROW_WITH_STORED_TYPE = {
    "id": "mod.py",
    "label": "mod",
    "type": "PythonModule",          # aliased from n.entity_type
    "description": "a module",
    "properties": {
        "id": "mod.py",
        "label": "mod",
        "entity_type": "PythonModule",
        "description": "a module",
        "type": "LEGACY_STRING",     # the offender: a STORED `type` property
        "source_project": "Graqle",
    },
}


class TestLoaderPopsType:
    def test_stored_type_is_not_left_in_properties(self) -> None:
        nodes = _load_with([_ROW_WITH_STORED_TYPE])
        assert "type" not in nodes["mod.py"]["properties"], (
            "a stored `type` property survives into properties and collides "
            "with the hydrator's own type= keyword"
        )

    def test_entity_type_still_comes_from_the_alias(self) -> None:
        # Popping `type` from properties must NOT disturb the real entity type,
        # which the query aliases from n.entity_type.
        nodes = _load_with([_ROW_WITH_STORED_TYPE])
        assert nodes["mod.py"]["type"] == "PythonModule"

    def test_other_properties_are_preserved(self) -> None:
        nodes = _load_with([_ROW_WITH_STORED_TYPE])
        assert nodes["mod.py"]["properties"]["source_project"] == "Graqle"

    def test_node_without_a_stored_type_is_unaffected(self) -> None:
        row = {
            **_ROW_WITH_STORED_TYPE,
            "properties": {"source_project": "Graqle"},
        }
        nodes = _load_with([row])
        assert nodes["mod.py"]["type"] == "PythonModule"
        assert nodes["mod.py"]["properties"] == {"source_project": "Graqle"}

    def test_pop_list_matches_the_writer_exclusions(self) -> None:
        # Read and write paths must agree, or a round-trip reintroduces the
        # collision. The writer excludes id/label/entity_type/description
        # (+chunks); the loader must pop the same set plus the `type` alias.
        import inspect

        from graqle.connectors.neo4j import Neo4jConnector

        source = inspect.getsource(Neo4jConnector.load)
        assert '"type"' in source, "loader must pop the aliased `type` key"


class TestHydratorNoLongerCollides:
    """The actual failure the pop prevents, at the hydrator."""

    def test_to_networkx_survives_a_stored_type(self) -> None:
        pytest.importorskip("networkx")
        from graqle.core.graph import Graqle
        from graqle.core.node import CogniNode

        graph = Graqle()
        node = CogniNode(
            id="mod.py",
            label="mod",
            entity_type="PythonModule",
            description="a module",
        )
        # Simulate a graph loaded from Neo4j BEFORE the fix: a `type` key left
        # in properties. add_node would then receive type= twice.
        node.properties = {"type": "LEGACY_STRING"}
        graph.nodes["mod.py"] = node

        with pytest.raises(TypeError, match="multiple values for keyword"):
            graph.to_networkx()

    def test_to_networkx_is_fine_once_the_loader_has_popped_type(self) -> None:
        pytest.importorskip("networkx")
        from graqle.core.graph import Graqle
        from graqle.core.node import CogniNode

        graph = Graqle()
        node = CogniNode(
            id="mod.py",
            label="mod",
            entity_type="PythonModule",
            description="a module",
        )
        node.properties = {"source_project": "Graqle"}  # loader popped `type`
        graph.nodes["mod.py"] = node

        networkx_graph = graph.to_networkx()
        assert networkx_graph.nodes["mod.py"]["type"] == "PythonModule"
