"""Shared fixtures for the CR-016 PR-016b write-path tests (test substitutes only)."""

from __future__ import annotations

import json
from typing import Any

from graqle.ontology.assurance import EdgeKind, edge_id
from graqle.ontology.assurance_integrity import IntegrityKeyring
from graqle.ontology.assurance_ops import AssuranceOp

#: Test substitute salt (handoff §4); never a deployment value.
SALT = "test-substitute-salt-0123456789abcdef-XYZ"
SALT_NEXT = "test-substitute-salt-NEXT-0123456789abcdef"
SCOPE = "scope-substitute"
KEYRING = IntegrityKeyring.from_salts(("v1", SALT))


def claim(
    node_id: str, canonical_id: str | None, valid_from: str, asserted_at: str, **extra: Any
) -> dict[str, Any]:
    node: dict[str, Any] = {
        "id": node_id,
        "assurance_type": "Claim",
        "lifecycle_status": "ACTIVE",
        "valid_from": valid_from,
        "asserted_at": asserted_at,
        "scope_key": SCOPE,
        "claim_id": node_id,
        "subject": "s",
        "predicate": "p",
        "object": "o",
        "confidence_vector_json": "{}",
        "confidence_vector_version": "cv-test",
        "valid_time": f"{valid_from}/",
        "status": "ACTIVE",
        "prov_event_id": "pev_test",
        **extra,
    }
    if canonical_id is not None:
        node["canonical_id"] = canonical_id
    return node


def claim_op(
    node_id: str, canonical_id: str | None, valid_from: str, asserted_at: str
) -> AssuranceOp:
    return AssuranceOp.create_node(claim(node_id, canonical_id, valid_from, asserted_at))


def edge_op(
    source: str, target: str, kind: EdgeKind, asserted_at: str = "2026-09-30T12:00:00Z"
) -> AssuranceOp:
    return AssuranceOp.create_edge(
        {
            "id": edge_id(source, target, kind, SCOPE),
            "source_id": source,
            "target_id": target,
            "kind": kind,
            "scope_key": SCOPE,
            "asserted_at": asserted_at,
            "prov_event_id": "pev_test",
        }
    )


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self._rows = rows or []

    def single(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class FakeSession:
    def __init__(self, calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.calls = calls

    def run(self, query: str, **params: Any) -> FakeResult:
        self.calls.append((query, params))
        return FakeResult()

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class FakeDriver:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def session(self, **_: Any) -> FakeSession:
        return FakeSession(self.calls)


def calls_digest(calls: list[tuple[str, dict[str, Any]]]) -> str:
    import hashlib

    return hashlib.sha256(json.dumps(calls, sort_keys=True, default=str).encode()).hexdigest()


#: A substrate graph with NO assurance data: what every existing caller saves.
SUBSTRATE_NODES: dict[str, Any] = {
    "a.py": {
        "label": "a.py",
        "type": "PythonModule",
        "description": "A",
        "properties": {"loc": 10, "lang": "py"},
    },
    "b.py": {"label": "b.py", "type": "PythonModule", "description": "B", "properties": {"loc": 3}},
}
SUBSTRATE_EDGES: dict[str, Any] = {
    "e1": {"source": "a.py", "target": "b.py", "relationship": "IMPORTS", "weight": 1.0},
    "e2": {"source": "b.py", "target": "a.py", "relationship": "RELATES_TO", "weight": 0.5},
    "e3": {"source": "a.py", "target": "b.py", "relationship": "calls-x", "weight": 2.0},
}
