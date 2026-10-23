"""In-memory graph, read session and queue for the CR-017 PR-017b tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from graqle.assurance.conflicts import RecomputeTask

from ._conflict_fakes import FakeReader, node

# Non-inferential substitutes: deliberately not the real private values.
SUBST_DEPTH = 2
SUBST_ATTEMPTS = 2
SUBST_BATCH = 5


class FakeGraph:
    """``edges`` are ``(x, y, kind)``: x depends on y (the edge points x -> y)."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[tuple[str, str, str]] = []
        self.queries: list[str] = []
        self.fail = False

    def add(self, nid: str, cls: str = "Claim", status: str = "ACTIVE", seq: int = 0) -> None:
        self.nodes[nid] = {"cls": cls, "status": status, "seq": seq}

    def depend(self, x: str, y: str, kind: str = "DERIVED_FROM") -> None:
        self.edges.append((x, y, kind))

    def dependents(self, y: str) -> list[dict[str, Any]]:
        rows = []
        for x, target, kind in self.edges:
            if target == y and kind in ("DERIVED_FROM", "SUPPORTED_BY"):
                n = self.nodes[x]
                rows.append({"xid": x, "via": kind, "seq": n["seq"], "st": n["status"], "cls": n["cls"]})
        return rows


class FakeSession:
    def __init__(self, graph: FakeGraph) -> None:
        self._g = graph

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self._g.queries.append(query)
        if self._g.fail:
            raise RuntimeError("driver down")
        return self._g.dependents(params["id"])


class FakeSource:
    def __init__(self, graph: FakeGraph) -> None:
        self.graph = graph

    @contextmanager
    def read_session(self) -> Iterator[FakeSession]:
        yield FakeSession(self.graph)


class RecomputeFakeReader(FakeReader):
    def __init__(self) -> None:
        super().__init__()
        self.bad_upstream: dict[str, int] = {}

    def invalidated_upstream_count(self, node_id: str) -> int:
        return self.bad_upstream.get(node_id, 0)

    def add(self, nid: str, *, cls: str = "Claim", status: str = "PENDING_RECOMPUTE", seq: int = 3) -> None:
        n = node(nid, status=status, seq=seq)
        n["assurance_type"] = cls
        self.nodes[nid] = n


class FakeQueue:
    def __init__(self, tasks: list[RecomputeTask]) -> None:
        self.tasks = {t.task_id: t for t in tasks}
        self.state = {t.task_id: ("QUEUED", t.attempts) for t in tasks}
        self.history: list[tuple[str, str, int, str | None]] = []

    def claim(self, batch: int) -> list[RecomputeTask]:
        out = [t for t in self.tasks.values() if self.state[t.task_id][0] == "QUEUED"][:batch]
        for t in out:
            self.state[t.task_id] = ("RUNNING", self.state[t.task_id][1])
        return [t.model_copy(update={"state": "RUNNING", "attempts": self.state[t.task_id][1]}) for t in out]

    def set_state(self, task: RecomputeTask, state: str, attempts: int, error: str | None = None) -> None:
        self.state[task.task_id] = (state, attempts)
        self.history.append((task.task_id, state, attempts, error))
