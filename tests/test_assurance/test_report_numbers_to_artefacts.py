"""Numbers-to-artefacts: dataset hash + run log + results triplet, and no policy values leak."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from graqle.assurance.settings import reset_dag_settings_cache
from graqle.assurance.threshold_study import run_threshold_study
from graqle.cli.commands.assurance import assurance_app

from ._proj_fakes import cv_env, settings
from ._study_fakes import synthetic_rows, write_jsonl


def _run(tmp_path: Path, run_id: str = "t1", sub: str = "o"):
    data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(150))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    out = tmp_path / sub
    return data, out, run_threshold_study(data, out, s, run_id)


def _log(out: Path, run_id: str = "t1") -> dict[str, str]:
    text = (out / f"e2-report-{run_id}.runlog").read_text()
    return dict(line.split("=", 1) for line in text.splitlines() if line)


def test_runlog_hashes_match_the_artefacts(tmp_path: Path) -> None:
    data, out, report = _run(tmp_path)
    log = _log(out)
    assert log["dataset_hash"] == hashlib.sha256(data.read_bytes()).hexdigest()
    assert log["results_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
    assert json.loads(report.read_text())["dataset_hash"] == log["dataset_hash"]


def test_edited_results_no_longer_match_the_runlog(tmp_path: Path) -> None:
    _, out, report = _run(tmp_path)
    report.write_text(report.read_text().replace('"ece"', '"ecx"', 1))
    assert _log(out)["results_sha256"] != hashlib.sha256(report.read_bytes()).hexdigest()


def test_run_is_reproducible_byte_for_byte(tmp_path: Path) -> None:
    _, _, first = _run(tmp_path, sub="a")
    _, _, second = _run(tmp_path, sub="b")
    assert first.read_bytes() == second.read_bytes()


def test_no_policy_values_or_symbols_in_artefacts(tmp_path: Path) -> None:
    _, out, report = _run(tmp_path)
    text = (report.read_text() + (out / "e2-report-t1.runlog").read_text()).lower()
    forbidden_words = (
        "weights",
        "penalt",
        "half_life",
        "policy_threshold",
        "max_divergence",
        "ttl",
    )
    for forbidden in forbidden_words:
        assert forbidden not in text


def test_report_bands_are_public_tenths(tmp_path: Path) -> None:
    _, _, report = _run(tmp_path)
    bands = json.loads(report.read_text())["arms"]["baseline_article14_placeholder"]["entity"][
        "band_error_rates"
    ]
    assert [b["lo"] for b in bands] == [i / 10 for i in range(10)]


# Substitute values for the DAG foundation settings -- deliberately NOT the real ones.
_DAG_SUBSTITUTES = {
    "GRAQLE_DAG_CONFIG_SALT": "test-substitute-salt-0123456789abcdef-XYZ",
    "GRAQLE_DAG_CAP_VALUE": "0.31",
    "GRAQLE_DAG_HG05_POISONING_THRESHOLD": "0.61",
    "GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD": "0.51",
    "GRAQLE_DAG_CALIBRATOR_VERSION": "cal-test-v0",
    "GRAQLE_DAG_TRAJECTORY_ESTIMATOR": "causal_baseline",
    "GRAQLE_DAG_MAX_RETRY_BUDGET": "3",
    "GRAQLE_DAG_CIRCUIT_BREAKER_WINDOW": "5",
    "GRAQLE_DAG_SIGNING_KEY_ID": "kid-test-2026",
    "GRAQLE_DAG_SIGNING_KEY_VERSION": "1",
    "GRAQLE_DAG_SCOPE_KEY_FIELDS_REF": "scope_fields_test",
    "GRAQLE_DAG_MERGE_PRIORITY_REF": "sdk_default",
}


@pytest.fixture(autouse=True)
def _fresh_dag_cache():
    reset_dag_settings_cache()
    yield
    reset_dag_settings_cache()


class TestCli:
    def test_flag_off_exits_3_and_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
        data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(3))
        result = CliRunner().invoke(
            assurance_app, ["threshold-study", "--dataset", str(data), "--out", str(tmp_path / "o")]
        )
        assert result.exit_code == 3
        assert not (tmp_path / "o").exists()

    def test_flag_on_writes_the_report(self, tmp_path: Path, monkeypatch) -> None:
        cv = cv_env(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
        for k, v in {**_DAG_SUBSTITUTES, **cv}.items():
            monkeypatch.setenv(k, v)
        data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(120))
        result = CliRunner().invoke(
            assurance_app,
            [
                "threshold-study",
                "--dataset",
                str(data),
                "--out",
                str(tmp_path / "o"),
                "--run-id",
                "cli1",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "o" / "e2-report-cli1.json").is_file()
        assert (tmp_path / "o" / "e2-report-cli1.runlog").is_file()

    def test_malformed_dataset_exits_2(self, tmp_path: Path, monkeypatch) -> None:
        for k, v in {**_DAG_SUBSTITUTES, **cv_env(str(tmp_path))}.items():
            monkeypatch.setenv(k, v)
        bad = tmp_path / "r.jsonl"
        bad.write_text("{not json}\n")
        result = CliRunner().invoke(
            assurance_app, ["threshold-study", "--dataset", str(bad), "--out", str(tmp_path / "o")]
        )
        assert result.exit_code == 2

    def test_invalid_configuration_exits_2(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")  # required vars absent
        data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(3))
        result = CliRunner().invoke(
            assurance_app, ["threshold-study", "--dataset", str(data), "--out", str(tmp_path / "o")]
        )
        assert result.exit_code == 2
