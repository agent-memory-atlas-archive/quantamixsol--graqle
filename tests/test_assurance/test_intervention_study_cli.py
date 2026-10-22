"""CR-015 PR-015d: `graq assurance intervention-study` (flag gate, exit codes, stub labelling)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from graqle.assurance import intervention_study as ivs
from graqle.cli.commands.assurance import assurance_app

_PARAMS = dict(
    seed=1,
    max_retry_budget=2,
    bootstrap_resamples=20,
    bootstrap_alpha=0.1,
    guess_hit_probability=0.0,
    informed_apply_probability=1.0,
    human_resolve_probability=1.0,
    human_latency_max_seconds=1.0,
    sla_seconds=2.0,
    cost_per_attempt_usd=1.0,
    cost_per_human_review_usd=2.0,
)


def _inputs(tmp_path: Path) -> list[str]:
    tasks = tmp_path / "t.jsonl"
    ivs.write_tasks(ivs.generate_tasks(2, seed=1), tasks)
    params = tmp_path / "p.json"
    params.write_text(json.dumps(_PARAMS))
    return [
        "intervention-study",
        "--tasks",
        str(tasks),
        "--params",
        str(params),
        "--out",
        str(tmp_path / "o"),
    ]


def test_flag_off_exits_3_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    result = CliRunner().invoke(assurance_app, _inputs(tmp_path))
    assert result.exit_code == 3
    assert not (tmp_path / "o").exists()


def test_flag_on_uses_real_controller_and_writes_report(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    result = CliRunner().invoke(assurance_app, [*_inputs(tmp_path), "--run-id", "c1"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "o" / "e7-report-c1.json").is_file()
    assert not (tmp_path / "o" / "e7-stub-report-c1.json").exists()


def test_bad_params_exit_2(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    args = _inputs(tmp_path)
    Path(args[4]).write_text(json.dumps({"seed": 1}))
    assert CliRunner().invoke(assurance_app, args).exit_code == 2


def test_bad_tasks_exit_2(tmp_path, monkeypatch):
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    args = _inputs(tmp_path)
    Path(args[2]).write_text("{not json}\n")
    assert CliRunner().invoke(assurance_app, args).exit_code == 2
