"""CR-015 PR-015d: every number in an E7 report traces to an artefact (AC-24, ALWAYS cond. 8)."""

from __future__ import annotations

import hashlib
import json

from graqle.assurance import intervention_study as ivs


def _params():
    return ivs.StudyParams(
        seed=11,
        max_retry_budget=3,
        bootstrap_resamples=40,
        bootstrap_alpha=0.1,
        guess_hit_probability=0.3,
        informed_apply_probability=0.9,
        human_resolve_probability=0.8,
        human_latency_max_seconds=10.0,
        sla_seconds=6.0,
        cost_per_attempt_usd=1.0,
        cost_per_human_review_usd=4.0,
    )


def _study(tmp_path):
    tasks = tmp_path / "tasks.jsonl"
    ivs.write_tasks(ivs.generate_tasks(10, seed=5), tasks)
    path = ivs.run_intervention_study(
        tasks, tmp_path / "o", _params(), "r1", ivs.StubReplanController
    )
    return tasks, path


def test_runlog_hashes_match_artefacts(tmp_path):
    tasks, path = _study(tmp_path)
    log = dict(
        line.split("=", 1) for line in path.with_suffix(".runlog").read_text().splitlines() if line
    )
    rep = json.loads(path.read_text())
    assert (
        log["dataset_hash"] == rep["dataset_hash"] == hashlib.sha256(tasks.read_bytes()).hexdigest()
    )
    assert log["results_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert log["result_status"] == rep["result_status"]


def test_write_tasks_hash_is_file_hash(tmp_path):
    p = tmp_path / "t.jsonl"
    h = ivs.write_tasks(ivs.generate_tasks(2, seed=1), p)
    assert h == hashlib.sha256(p.read_bytes()).hexdigest()


def test_reported_points_recompute_from_records(tmp_path):
    _, path = _study(tmp_path)
    rep = json.loads(path.read_text())
    for arm, agg in rep["arms"].items():
        recs = [r for r in rep["records"] if r["arm"] == arm]
        assert len(recs) == agg["n_tasks"]
        assert agg["success_rate"]["point"] == sum(r["success"] for r in recs) / len(recs)
        assert agg["safe_success_rate"]["point"] == sum(r["safe_success"] for r in recs) / len(recs)
        assert agg["mean_cost_usd"]["point"] == sum(r["cost_usd"] for r in recs) / len(recs)
        assert agg["loops_prevented"] == sum(r["loops_prevented"] for r in recs)
        dist = {}
        for r in recs:
            dist[str(r["retries"])] = dist.get(str(r["retries"]), 0) + 1
        assert agg["retry_count_distribution"] == dict(sorted(dist.items()))
        replans = sum(r["replan_verdicts"] for r in recs)
        if replans:
            assert (
                agg["unchanged_reason_rate"]["point"]
                == sum(r["unchanged_events"] for r in recs) / replans
            )


def test_bootstrap_is_grouped_by_task_family(tmp_path):
    _, path = _study(tmp_path)
    rep = json.loads(path.read_text())
    assert rep["bootstrap"]["group_by"] == "task_family"
    assert rep["arms"]["hold"]["success_rate"]["n_groups"] == len(ivs.FAMILIES)
