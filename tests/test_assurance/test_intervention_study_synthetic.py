"""CR-015 PR-015d: E7 intervention-study runner on synthetic tasks (AC-24)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from graqle.assurance import intervention_study as ivs
from graqle.assurance.outcomes import GateOutcome


def _params(**over):
    base = dict(
        seed=7,
        max_retry_budget=3,
        bootstrap_resamples=50,
        bootstrap_alpha=0.1,
        guess_hit_probability=0.0,
        informed_apply_probability=1.0,
        human_resolve_probability=1.0,
        human_latency_max_seconds=10.0,
        sla_seconds=20.0,
        cost_per_attempt_usd=1.0,
        cost_per_human_review_usd=5.0,
    )
    base.update(over)
    return ivs.StudyParams(**base)


def _run(tmp_path: Path, params=None, factory=None, per_family=4, run_id="t1"):
    tasks = tmp_path / "tasks.jsonl"
    ivs.write_tasks(ivs.generate_tasks(per_family, seed=3), tasks)
    p = params or _params()
    out = tmp_path / "out"
    path = ivs.run_intervention_study(tasks, out, p, run_id, factory or ivs.StubReplanController)
    return path, json.loads(path.read_text())


def test_four_arms_present_with_required_metrics(tmp_path):
    _, rep = _run(tmp_path)
    assert set(rep["arms"]) == set(ivs.ARMS)
    for arm in rep["arms"].values():
        for key in (
            "success_rate",
            "safe_success_rate",
            "retry_count_distribution",
            "mean_cost_usd",
            "explanation_faithfulness",
            "unchanged_reason_rate",
            "loops_prevented",
            "escalation_sla_adherence",
        ):
            assert key in arm
    assert rep["schema"] == "e7-report-1"


def test_stub_controller_run_is_labelled_and_filed_apart(tmp_path):
    path, rep = _run(tmp_path)
    assert rep["result_status"] == ivs.STATUS_STUB
    assert rep["controller"]["real"] is False
    assert path.name == "e7-stub-report-t1.json"
    assert (path.parent / "e7-stub-report-t1.runlog").exists()
    assert not (path.parent / "e7-report-t1.json").exists()


def test_real_controller_detector_requires_module_and_name():
    class ReplanController:  # same name, wrong module
        pass

    assert ivs.is_real_controller(ReplanController()) is False
    ReplanController.__module__ = "graqle.assurance.replan"
    assert (
        ivs.is_real_controller(ReplanController()) is False
    )  # a local class keeps its <locals> qualname
    ReplanController.__qualname__ = "ReplanController"
    assert ivs.is_real_controller(ReplanController()) is True
    assert ivs.is_real_controller(ivs.StubReplanController(1)) is False


def test_real_labelled_run_uses_e7_names(tmp_path):
    class ReplanController(ivs.StubReplanController):
        pass

    ReplanController.__module__ = "graqle.assurance.replan"
    ReplanController.__qualname__ = "ReplanController"
    path, rep = _run(tmp_path, factory=ReplanController)
    assert rep["result_status"] == ivs.STATUS_RESULT
    assert path.name == "e7-report-t1.json"


def test_budget_value_never_in_report(tmp_path):
    _, rep = _run(tmp_path, params=_params(max_retry_budget=7))
    assert "max_retry_budget" not in rep["synthetic_model"]
    assert "max_retry_budget" not in json.dumps(rep)


def test_blind_retry_trips_circuit_breaker_graph_arm_does_not(tmp_path):
    _, rep = _run(tmp_path)
    blind, graph = rep["arms"][ivs.ARM_PROMPT_RETRY], rep["arms"][ivs.ARM_GRAPH_REPLAN]
    assert blind["loops_prevented"] > 0
    assert blind["unchanged_reason_rate"]["point"] > 0.0
    assert graph["loops_prevented"] == 0
    assert graph["success_rate"]["point"] == 1.0
    assert graph["explanation_faithfulness"]["point"] == 1.0
    assert blind["explanation_faithfulness"]["point"] < 1.0


def test_hold_never_succeeds_and_escalate_hits_human(tmp_path):
    _, rep = _run(tmp_path)
    assert rep["arms"][ivs.ARM_HOLD]["success_rate"]["point"] == 0.0
    esc = rep["arms"][ivs.ARM_ESCALATE]
    assert esc["escalations"] == rep["n_tasks"]
    assert esc["escalation_sla_adherence"]["point"] == 1.0


def test_poisoned_executes_are_not_safe_successes(tmp_path):
    # Blind guesses always hit a node from the pool, so poisoned nodes can be executed.
    _, rep = _run(tmp_path, params=_params(guess_hit_probability=1.0), per_family=30)
    blind = rep["arms"][ivs.ARM_PROMPT_RETRY]
    assert blind["safe_success_rate"]["point"] <= blind["success_rate"]["point"]


def test_run_is_deterministic(tmp_path):
    a, _ = _run(tmp_path / "a")
    b, _ = _run(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


class _Raises:
    def __init__(self, budget):
        pass

    def on_replan(self, verdict, ctx):
        raise RuntimeError("boom")


class _NeverStops:
    def __init__(self, budget):
        pass

    def on_replan(self, verdict, ctx):
        return ivs.StubReplanController(10**6).on_replan(
            verdict, ivs.StudyContext(replan_state=ivs.StubReplanState(root_candidate_id="x"))
        )


class _ReturnsExecute:
    def __init__(self, budget):
        pass

    def on_replan(self, verdict, ctx):
        return verdict.downgraded(GateOutcome.EXECUTE, rule="x", codes=())


@pytest.mark.parametrize("factory", [_Raises, _NeverStops, _ReturnsExecute])
def test_misbehaving_controller_fails_closed(tmp_path, factory):
    # No planner ever fixes the task, so only the controller can end the loop.
    _, rep = _run(tmp_path, params=_params(informed_apply_probability=0.0), factory=factory)
    for arm in (ivs.ARM_PROMPT_RETRY, ivs.ARM_GRAPH_REPLAN):
        a = rep["arms"][arm]
        assert a["controller_failures"] == rep["n_tasks"]
        assert a["escalations"] == rep["n_tasks"]
    assert all(
        r["final_outcome"] != "EXECUTE"
        for r in rep["records"]
        if r["arm"] in (ivs.ARM_PROMPT_RETRY, ivs.ARM_GRAPH_REPLAN)
    )


def test_malformed_task_file_refused(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"task_id": "a"}\n')
    with pytest.raises(ivs.DatasetError):
        ivs.load_tasks(bad)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    with pytest.raises(ivs.DatasetError):
        ivs.load_tasks(empty)


def test_duplicate_ids_and_unknown_family_refused(tmp_path):
    t = ivs.generate_tasks(1, seed=1)
    dup = tmp_path / "dup.jsonl"
    ivs.write_tasks([t[0], t[0]], dup)
    with pytest.raises(ivs.DatasetError):
        ivs.load_tasks(dup)
    row = t[0].model_dump()
    row["family"] = "other"
    unk = tmp_path / "unk.jsonl"
    unk.write_text(json.dumps(row) + "\n")
    with pytest.raises(ivs.DatasetError):
        ivs.load_tasks(unk)


def test_params_have_no_defaults_and_validate():
    with pytest.raises(Exception):
        ivs.StudyParams()  # type: ignore[call-arg]
    with pytest.raises(Exception):
        _params(max_retry_budget=0)
    with pytest.raises(Exception):
        _params(guess_hit_probability=1.5)


def test_bad_run_id_refused(tmp_path):
    tasks = tmp_path / "t.jsonl"
    ivs.write_tasks(ivs.generate_tasks(1, seed=1), tasks)
    with pytest.raises(ValueError):
        ivs.run_intervention_study(tasks, tmp_path, _params(), "../x", ivs.StubReplanController)
