"""CR-015 PR-015c: `graq assurance escalations list|ack|resolve` (flag-guarded, fail closed)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from graqle.assurance.escalation import JsonlEscalationQueue, ReviewPackage
from graqle.assurance.gate import ImpactTier
from graqle.cli.commands.assurance import assurance_app

runner = CliRunner()

# Symbolic test deadlines; not deployment values.
_SLA = {"LOW": "11", "MEDIUM": "12", "HIGH": "13", "CRITICAL": "14"}


def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, flag: bool = True, queue: str = "jsonl") -> None:
    if flag:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", "1")
    else:
        monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    for tier, secs in _SLA.items():
        monkeypatch.setenv(f"GRAQLE_DAG_ESCALATION_SLA_{tier}_SECONDS", secs)
    monkeypatch.setenv("GRAQLE_DAG_ESCALATION_QUEUE", queue)
    monkeypatch.setenv("GRAQLE_DAG_ESCALATION_QUEUE_PATH", str(tmp_path))


def _package(package_id: str = "pkg-1", role: str = "senior") -> ReviewPackage:
    return ReviewPackage(
        package_id=package_id, verdict_id="v", candidate_id="c", session_id="s",
        created_unix=1.0, deadline_unix=2.0, sla_seconds=1, impact_tier=ImpactTier.LOW,
        route_to_role=role, eligible_actor_ids=("sam",), evidence=(), alternatives=(),
        risks=(), requested_decision="reject", reason_codes=(),
    )


def _seed(tmp_path: Path) -> JsonlEscalationQueue:
    queue = JsonlEscalationQueue(tmp_path)
    queue.enqueue(_package())
    queue.enqueue(_package("pkg-2", role="lead"))
    return queue


def test_flag_off_exits_3_for_every_subcommand(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path, flag=False)
    _seed(tmp_path)
    for args in (
        ["escalations", "list"],
        ["escalations", "ack", "pkg-1", "--actor", "sam"],
        ["escalations", "resolve", "pkg-1", "--actor", "sam", "--decision", "reject", "--justification", "x"],
    ):
        assert runner.invoke(assurance_app, args).exit_code == 3
    assert [p.status for p in JsonlEscalationQueue(tmp_path).list_open()] == ["OPEN", "OPEN"]


def test_missing_sla_config_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path)
    monkeypatch.delenv("GRAQLE_DAG_ESCALATION_SLA_LOW_SECONDS")
    assert runner.invoke(assurance_app, ["escalations", "list"]).exit_code == 2


def test_memory_queue_refused_exit_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path, queue="memory")
    assert runner.invoke(assurance_app, ["escalations", "list"]).exit_code == 2


def test_list_filters_by_role(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path)
    _seed(tmp_path)
    everything = runner.invoke(assurance_app, ["escalations", "list"])
    assert everything.exit_code == 0 and "pkg-1" in everything.output and "pkg-2" in everything.output
    lead = runner.invoke(assurance_app, ["escalations", "list", "--role", "lead"])
    assert lead.exit_code == 0 and "pkg-2" in lead.output and "pkg-1" not in lead.output


def test_ack_then_resolve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path)
    _seed(tmp_path)
    assert runner.invoke(assurance_app, ["escalations", "ack", "pkg-1", "--actor", "sam"]).exit_code == 0
    done = runner.invoke(
        assurance_app,
        ["escalations", "resolve", "pkg-1", "--actor", "sam", "--decision", "reject", "--justification", "unsafe"],
    )
    assert done.exit_code == 0
    assert [p.package_id for p in JsonlEscalationQueue(tmp_path).list_open()] == ["pkg-2"]


def test_ineligible_actor_and_unknown_package_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _env(monkeypatch, tmp_path)
    _seed(tmp_path)
    assert runner.invoke(assurance_app, ["escalations", "ack", "pkg-1", "--actor", "mallory"]).exit_code == 1
    assert runner.invoke(assurance_app, ["escalations", "ack", "nope", "--actor", "sam"]).exit_code == 1
    assert [p.status for p in JsonlEscalationQueue(tmp_path).list_open()] == ["OPEN", "OPEN"]


def test_resolve_refuses_bad_decision_and_empty_justification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _env(monkeypatch, tmp_path)
    _seed(tmp_path)
    base = ["escalations", "resolve", "pkg-1", "--actor", "sam"]
    assert runner.invoke(assurance_app, [*base, "--decision", "bogus", "--justification", "x"]).exit_code == 1
    assert runner.invoke(assurance_app, [*base, "--decision", "reject", "--justification", "  "]).exit_code == 1
    assert [p.status for p in JsonlEscalationQueue(tmp_path).list_open()] == ["OPEN", "OPEN"]
