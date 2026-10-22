"""CR-017 PR-017b: AC-7 (atomic, collision-safe mutation) and AC-8 (replay) on a scripted fake driver."""

from __future__ import annotations

from typing import Any

import pytest

from graqle.assurance.conflicts import (
    AssuranceMutation,
    ConflictError,
    EdgeWrite,
    MutationReceipt,
    NodeWrite,
    RecomputeTask,
    system_event,
)
from graqle.assurance.propagation import ReceiptingPersister
from graqle.connectors.neo4j import Neo4jConnector
from graqle.governance.tamper_evidence.kg_persist import (
    KgPersistError,
    Neo4jBatchPersister,
    WriteCollisionError,
)

from ._conflict_fakes import NOW, make_cfg, node


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def single(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def consume(self) -> None:
        return None

    def __iter__(self):
        return iter(self._rows)


class ScriptedDriver:
    """Answers each Cypher statement by a keyword; records statements and rollbacks."""

    def __init__(self, script: dict[str, list[list[dict[str, Any]]]]) -> None:
        self.script = {k: list(v) for k, v in script.items()}
        self.statements: list[str] = []
        self.rollbacks = 0
        self.commits = 0
        self.sessions = 0

    def session(self, **_: Any) -> "ScriptedDriver":
        self.sessions += 1
        return self

    def __enter__(self) -> "ScriptedDriver":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def execute_write(self, fn):
        before = len(self.statements)
        try:
            out = fn(self)
        except BaseException:
            self.rollbacks += 1
            raise
        assert len(self.statements) > before
        self.commits += 1
        return out

    def run(self, query: str, **_: Any) -> _Result:
        self.statements.append(query)
        for key, answers in self.script.items():
            if key in query:
                return _Result(answers.pop(0) if len(answers) > 1 else answers[0])
        raise AssertionError(f"unscripted statement: {query[:60]}")


def _mutation(*, nodes: int = 2, edges: int = 1, tasks: int = 1) -> AssuranceMutation:
    ev = system_event(
        "INVALIDATION", node("seed", seq=1), actor="t", code="DAG-PV-INVALIDATED", text="x",
        decisive=["d"], cfg=make_cfg(), rule_id="CR017.invalidate", now=NOW,
    )
    return AssuranceMutation(
        mutation_id=ev.event_id,
        event=ev,
        node_writes=[NodeWrite(node_id=f"n{i}", expected_seq=i, set_props={"dirty": True}) for i in range(nodes)],
        edge_writes=[
            EdgeWrite(edge_id=f"e{i}", source_id=ev.event_id, target_id="n0", kind="INVALIDATES", props={"strength": 1.0})
            for i in range(edges)
        ],
        tasks=[RecomputeTask.for_node(f"n{i}", reason="DERIVED_FROM", ev=ev) for i in range(tasks)],
        inputs_hash=ev.inputs_hash,
    )


def _connector(driver: ScriptedDriver) -> Neo4jConnector:
    c = Neo4jConnector(uri="bolt://unused:1")
    c._driver = driver
    return c


def _script(**extra: list[list[dict[str, Any]]]) -> dict[str, list[list[dict[str, Any]]]]:
    base: dict[str, list[list[dict[str, Any]]]] = {
        "MERGE (e:CogniNode": [[{"fresh": True}]],
        "UNWIND $ids AS nid MATCH (n:CogniNode {id: nid}) SET": [[]],
        "RETURN n.id AS id": [[{"id": "n0", "act": 0}, {"id": "n1", "act": 1}]],  # matches the planned seqs
        "RETURN count(n) AS written": [[{"written": 2}]],
        "RETURN count(r) AS n": [[{"n": 1}]],
        "RETURN count(t) AS n": [[{"n": 1}]],
    }
    base.update(extra)
    return base


def test_single_transaction_commits_event_nodes_edges_and_tasks_together():
    driver = ScriptedDriver(_script())
    receipt = _connector(driver).persist_assurance_mutation(_mutation())
    assert receipt == {
        "mutation_id": _mutation().mutation_id, "replayed": False,
        "nodes_written": 2, "edges_written": 1, "tasks_written": 1,
    }
    assert driver.sessions == 1 and driver.commits == 1 and driver.rollbacks == 0


def test_ac7_sequence_bump_aborts_the_whole_mutation_and_names_the_node():
    script = _script(**{"RETURN n.id AS id": [[{"id": "n0", "act": 0}, {"id": "n1", "act": 99}]]})  # n1 was bumped
    driver = ScriptedDriver(script)
    with pytest.raises(WriteCollisionError) as exc:
        _connector(driver).persist_assurance_mutation(_mutation())
    assert exc.value.node_id == "n1" and exc.value.expected == 1 and exc.value.actual == 99
    assert exc.value.code == "DAG-PV-WRITE-COLLISION"
    assert driver.rollbacks == 1 and driver.commits == 0
    # nothing after the failed sequence check was attempted: no node update, edge or task statement ran
    assert not any("count(n) AS written" in s or "RELATES_TO" in s or "RecomputeTask" in s for s in driver.statements)


def test_the_stale_node_is_named_even_when_an_earlier_planned_node_is_current():
    """Regression: the diagnostic must not run after the update has already bumped a current node."""
    script = _script(**{"RETURN n.id AS id": [[{"id": "n0", "act": 0}, {"id": "n1", "act": 4}]]})
    with pytest.raises(WriteCollisionError) as exc:
        _connector(ScriptedDriver(script)).persist_assurance_mutation(_mutation())
    assert exc.value.node_id == "n1"


def test_a_write_count_mismatch_after_a_clean_check_aborts():
    driver = ScriptedDriver(_script(**{"RETURN count(n) AS written": [[{"written": 1}]]}))
    with pytest.raises(KgPersistError, match="count mismatch"):
        _connector(driver).persist_assurance_mutation(_mutation())
    assert driver.rollbacks == 1 and driver.commits == 0


def test_ac7_missing_planned_node_is_a_refusal_not_a_collision():
    driver = ScriptedDriver(_script(**{"RETURN n.id AS id": [[{"id": "n0", "act": 0}]]}))
    with pytest.raises(KgPersistError) as exc:
        _connector(driver).persist_assurance_mutation(_mutation())
    assert not isinstance(exc.value, WriteCollisionError)
    assert driver.rollbacks == 1


def test_missing_edge_endpoint_rolls_back():
    driver = ScriptedDriver(_script(**{"RETURN count(r) AS n": [[{"n": 0}]]}))
    with pytest.raises(KgPersistError, match="edge endpoint"):
        _connector(driver).persist_assurance_mutation(_mutation())
    assert driver.rollbacks == 1 and driver.commits == 0


def test_missing_task_target_rolls_back():
    driver = ScriptedDriver(_script(**{"RETURN count(t) AS n": [[{"n": 0}]]}))
    with pytest.raises(KgPersistError, match="task target"):
        _connector(driver).persist_assurance_mutation(_mutation())
    assert driver.rollbacks == 1


def test_event_write_returning_nothing_is_a_failure():
    driver = ScriptedDriver(_script(**{"MERGE (e:CogniNode": [[]]}))
    with pytest.raises(KgPersistError):
        _connector(driver).persist_assurance_mutation(_mutation())
    assert driver.rollbacks == 1


def test_duplicate_node_writes_are_refused_before_any_statement():
    m = _mutation()
    m.node_writes.append(NodeWrite(node_id="n0", expected_seq=0, set_props={}))
    driver = ScriptedDriver(_script())
    with pytest.raises(KgPersistError, match="at most once"):
        _connector(driver).persist_assurance_mutation(m)
    assert driver.statements == [] and driver.sessions == 0


def test_ac8_replay_returns_replayed_and_issues_no_further_write():
    driver = ScriptedDriver(_script(**{"MERGE (e:CogniNode": [[{"fresh": False}]]}))
    receipt = _connector(driver).persist_assurance_mutation(_mutation())
    assert receipt["replayed"] is True
    assert len(driver.statements) == 1  # only the event MERGE; zero node, edge or task writes
    assert driver.commits == 1


def test_locks_are_taken_in_sorted_node_order():
    m = _mutation()
    m.node_writes.reverse()
    driver = ScriptedDriver(_script())
    seen: list[list[str]] = []
    real_run = driver.run

    def spy(query: str, **params: Any):
        if "ids" in params and "SET n.assurance_seq" in query:
            seen.append(params["ids"])
        return real_run(query, **params)

    driver.run = spy  # type: ignore[method-assign]
    _connector(driver).persist_assurance_mutation(m)
    assert seen == [["n0", "n1"]]


# -- persister: retry with replanner (AC-7) and fail-closed paths -------------------


class _Connector:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = list(outcomes)
        self.seen: list[AssuranceMutation] = []

    def persist_assurance_mutation(self, m: AssuranceMutation) -> Any:
        self.seen.append(m)
        out = self.outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        return out


def _ok(m: AssuranceMutation) -> dict[str, Any]:
    return {"mutation_id": m.mutation_id, "replayed": False, "nodes_written": 2}


def test_ac7_retry_with_replanner_succeeds_after_a_collision():
    first, second = _mutation(), _mutation(nodes=1)
    conn = _Connector([WriteCollisionError("n1", 1, 99), _ok(second)])
    persister = Neo4jBatchPersister(conn, write_collision_retries=2)  # type: ignore[arg-type]
    replanned: list[AssuranceMutation] = []

    def replanner(m: AssuranceMutation) -> AssuranceMutation:
        replanned.append(m)
        return second

    out = persister.persist_assurance_mutation(first, replanner)
    assert out["replayed"] is False
    assert conn.seen == [first, second] and replanned == [first]


def test_collision_without_a_replanner_is_raised_not_retried():
    conn = _Connector([WriteCollisionError("n1", 1, 99), _ok(_mutation())])
    persister = Neo4jBatchPersister(conn, write_collision_retries=3)  # type: ignore[arg-type]
    with pytest.raises(WriteCollisionError):
        persister.persist_assurance_mutation(_mutation())
    assert len(conn.seen) == 1


def test_replanner_returning_none_gives_up_with_the_collision():
    conn = _Connector([WriteCollisionError("n1", 1, 99)])
    persister = Neo4jBatchPersister(conn, write_collision_retries=3)  # type: ignore[arg-type]
    with pytest.raises(WriteCollisionError):
        persister.persist_assurance_mutation(_mutation(), lambda m: None)


def test_retry_budget_exhausted_raises_the_last_collision():
    conn = _Connector([WriteCollisionError("n1", 1, 5), WriteCollisionError("n1", 1, 6)])
    persister = Neo4jBatchPersister(conn, write_collision_retries=2)  # type: ignore[arg-type]
    with pytest.raises(WriteCollisionError) as exc:
        persister.persist_assurance_mutation(_mutation(), lambda m: m)
    assert exc.value.actual == 6 and len(conn.seen) == 2


def test_other_failures_are_wrapped_and_never_retried():
    conn = _Connector([RuntimeError("boom"), _ok(_mutation())])
    persister = Neo4jBatchPersister(conn, write_collision_retries=3)  # type: ignore[arg-type]
    with pytest.raises(KgPersistError, match="boom"):
        persister.persist_assurance_mutation(_mutation(), lambda m: m)
    assert len(conn.seen) == 1


@pytest.mark.parametrize("retries", [None, 0, -1, True])
def test_retry_count_must_be_configured(retries):
    conn = _Connector([_ok(_mutation())])
    persister = Neo4jBatchPersister(conn, write_collision_retries=retries)  # type: ignore[arg-type]
    with pytest.raises(KgPersistError, match="write_collision_retries"):
        persister.persist_assurance_mutation(_mutation())
    assert conn.seen == []


# -- adapter ------------------------------------------------------------------------


def test_receipting_persister_turns_the_plain_receipt_into_a_model_and_passes_the_replanner():
    m = _mutation()
    conn = _Connector([WriteCollisionError("n1", 1, 2), _ok(m)])
    inner = Neo4jBatchPersister(conn, write_collision_retries=2)  # type: ignore[arg-type]
    receipt = ReceiptingPersister(inner, replanner=lambda old: old).persist_assurance_mutation(m)
    assert isinstance(receipt, MutationReceipt) and receipt.nodes_written == 2


def test_receipting_persister_refuses_an_unusable_receipt():
    class Bad:
        def persist_assurance_mutation(self, m, replanner=None):
            return "ok"

    with pytest.raises(ConflictError):
        ReceiptingPersister(Bad()).persist_assurance_mutation(_mutation())
