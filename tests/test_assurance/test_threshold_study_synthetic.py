"""AC-21: the runner emits the report and run log, with CIs per class, on a 4 x 2,000 dataset."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from graqle.assurance.confidence_vector import EntityClass
from graqle.assurance.threshold_study import (
    ARM_ARTICLE14,
    ARM_CAUSAL,
    ARM_DRACE,
    ARM_GOVERNANCE,
    ARM_SCALAR,
    ARM_TRAJECTORY,
    DatasetError,
    load_labelled_rows,
    run_threshold_study,
)

from ._proj_fakes import settings
from ._study_fakes import ROWS_PER_CLASS, synthetic_rows, write_jsonl

METRICS = ("ece", "brier", "auroc", "auprc")
CLASSES = {c.value for c in EntityClass}


@pytest.fixture(scope="module")
def study(tmp_path_factory):
    base = tmp_path_factory.mktemp("study")
    data = write_jsonl(base / "rows.jsonl", synthetic_rows())
    s = settings(str(base), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="30")
    out = base / "out"
    path = run_threshold_study(data, out, s, "synthetic-1")
    return data, out, path, json.loads(path.read_text())


def test_files_and_schema(study) -> None:
    data, out, path, report = study
    assert path == out / "e2-report-synthetic-1.json"
    assert (out / "e2-report-synthetic-1.runlog").is_file()
    assert report["schema"] == "e2-report-1"
    assert report["dataset_hash"] == hashlib.sha256(data.read_bytes()).hexdigest()
    assert report["n_rows"] == 4 * ROWS_PER_CLASS


def test_three_baseline_arms_present_with_all_classes(study) -> None:
    arms = study[3]["arms"]
    for arm in (ARM_GOVERNANCE, ARM_ARTICLE14, ARM_DRACE):
        assert set(arms[arm]) == CLASSES
        for cell in arms[arm].values():
            assert "skipped" not in cell and cell["n"] == ROWS_PER_CLASS


def test_every_metric_has_ci_and_seed(study) -> None:
    report = study[3]
    for arm in (ARM_GOVERNANCE, ARM_ARTICLE14, ARM_DRACE):
        for cell in report["arms"][arm].values():
            for name in METRICS:
                m = cell[name]
                assert m["ci_low"] <= m["ci_high"]  # ECE is biased, so the point may sit outside
                assert m["seed"] == report["seed"]
                assert m["n_valid"] > 0
            assert cell["tc_ece"]["buckets"]
            assert cell["risk_coverage"]["e_aurc"] >= 0.0


def test_cross_class_finding_fires_on_injected_miscalibration(study) -> None:
    findings = study[3]["cross_class_threshold_finding"]
    assert findings
    assert any(
        f["arm"] == ARM_ARTICLE14 and "decision" in f["error_rate_by_class"] for f in findings
    )


def test_arms_with_missing_inputs_are_skipped_with_a_note_not_zero_filled(study) -> None:
    report = study[3]
    for arm in (ARM_TRAJECTORY, ARM_SCALAR, ARM_CAUSAL):
        assert all("skipped" in cell for cell in report["arms"][arm].values())
        assert "skipped" in report["arm_notes"][arm]


def test_missing_drace_feature_skips_the_arm(tmp_path: Path) -> None:
    data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(120, with_drace=False))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(run_threshold_study(data, tmp_path / "o", s, "r1").read_text())
    cells = report["arms"][ARM_DRACE].values()
    assert all(c == {"skipped": "insufficient_rows", "n": 0} for c in cells)
    assert "skipped" in report["arm_notes"][ARM_DRACE]


def test_vector_arm_counts_gate_failures_and_never_scores_them(tmp_path: Path) -> None:
    data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(300, with_vector=True))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(run_threshold_study(data, tmp_path / "o", s, "v1").read_text())
    arm = "confidence_vector_" + s.projection_strategy.value
    for cell in report["arms"][arm].values():
        assert cell["n"] == 270  # the 30 rows with a failed hard gate are excluded
    assert "excluded" in report["arm_notes"][arm]


def test_single_class_labels_skip_rather_than_report(tmp_path: Path) -> None:
    rows = synthetic_rows(150)
    for r in rows:
        r["label"] = 1
    data = write_jsonl(tmp_path / "r.jsonl", rows)
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(run_threshold_study(data, tmp_path / "o", s, "u1").read_text())
    cell = report["arms"][ARM_ARTICLE14]["entity"]
    assert cell["skipped"] == "metric_undefined"


class TestMalformedInputFailsClosed:
    @pytest.mark.parametrize(
        "patch",
        [
            {"label": 2},
            {"label": True},
            {"confidence_scalar": 1.5},
            {"position": 0.5},
            {"position": -1},
            {"extra": 1},
        ],
    )
    def test_bad_row_rejects_the_dataset(self, tmp_path: Path, patch: dict) -> None:
        rows = synthetic_rows(3)
        rows[0].update(patch)
        with pytest.raises(DatasetError):
            load_labelled_rows(write_jsonl(tmp_path / "r.jsonl", rows))

    def test_duplicate_trace_id_rejected(self, tmp_path: Path) -> None:
        rows = synthetic_rows(3)
        rows[1]["trace_id"] = rows[0]["trace_id"]
        with pytest.raises(DatasetError):
            load_labelled_rows(write_jsonl(tmp_path / "r.jsonl", rows))

    def test_empty_dataset_rejected(self, tmp_path: Path) -> None:
        empty = tmp_path / "r.jsonl"
        empty.write_text("\n")
        with pytest.raises(DatasetError):
            load_labelled_rows(empty)

    @pytest.mark.parametrize("run_id", ["", "../x", "a/b", ".hidden", "a" * 65])
    def test_unsafe_run_id_rejected(self, tmp_path: Path, run_id: str) -> None:
        data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(3))
        with pytest.raises(ValueError):
            run_threshold_study(data, tmp_path / "o", settings(str(tmp_path)), run_id)
        assert not (tmp_path / "o").exists()
