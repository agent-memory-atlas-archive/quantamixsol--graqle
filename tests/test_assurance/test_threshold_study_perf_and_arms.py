"""AC-23 runner benchmark (non-gating, reported) and scoring paths of the optional arms.

The causal parameters here are TEST SUBSTITUTES, not deployed values.
"""

from __future__ import annotations

import json
import time
import warnings
from pathlib import Path

import pytest

from graqle.assurance import causal_baselines as cb
from graqle.assurance.settings import DagSettings
from graqle.assurance.threshold_study import (
    ARM_CAUSAL,
    ARM_SCALAR,
    run_threshold_study,
)

from ._proj_fakes import settings
from ._study_fakes import synthetic_rows, write_jsonl

BENCH_ROWS_PER_CLASS = 2000  # 4 classes -> 8,000 rows
BENCH_RESAMPLES = 200
BENCH_BUDGET_SECONDS = 60.0  # AC-23 target: reported, never a hard failure

SALT = "test-substitute-salt-0123456789abcdef-XYZ"
_DOWN = cb.MonotoneMap(knots_x=(0.0, 3.0, 9.0), knots_y=(1.0, 0.6, 0.2))
_UP = cb.MonotoneMap(knots_x=(0.0, 1.0), knots_y=(0.3, 1.0))
_FAIL_DOWN = cb.MonotoneMap(knots_x=(0.0, 1.0), knots_y=(1.0, 0.1))


def _causal_params() -> cb.CausalBaselineParams:
    maps = {
        "steps": _DOWN,
        "retry": _DOWN,
        "contra": _DOWN,
        "fresh": _UP,
        "tool": _FAIL_DOWN,
    }
    return cb.CausalBaselineParams(maps=maps, exponents={n: 1.0 for n in cb.BASELINE_NAMES})


def test_runner_benchmark_is_reported_not_gating(tmp_path: Path, record_property) -> None:
    data = write_jsonl(tmp_path / "rows.jsonl", synthetic_rows(BENCH_ROWS_PER_CLASS))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES=str(BENCH_RESAMPLES))
    started = time.perf_counter()
    run_threshold_study(data, tmp_path / "out", s, "bench-1")
    seconds = time.perf_counter() - started

    result = {
        "ac": "AC-23",
        "rows": 4 * BENCH_ROWS_PER_CLASS,
        "resamples": BENCH_RESAMPLES,
        "seconds": round(seconds, 3),
        "budget_seconds": BENCH_BUDGET_SECONDS,
        "within_budget": seconds <= BENCH_BUDGET_SECONDS,
    }
    # Reported through three channels so the figure traces to a CI run log:
    # stdout (-s / failure output), junit properties, and a results file.
    print("AC23_BENCHMARK " + json.dumps(result, sort_keys=True))
    record_property("ac23_benchmark", json.dumps(result, sort_keys=True))
    (tmp_path / "ac23-benchmark.json").write_text(json.dumps(result, sort_keys=True))
    if seconds > BENCH_BUDGET_SECONDS:
        warnings.warn(f"AC-23 runner exceeded its non-gating budget: {result}", stacklevel=1)
    assert seconds > 0.0  # the run happened; the budget is informational only


def test_scalar_calibrator_arm_is_scored_when_supplied(tmp_path: Path) -> None:
    data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(150))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(
        run_threshold_study(
            data, tmp_path / "o", s, "sc1", scalar_calibrator=lambda x: x * x
        ).read_text()
    )
    for cell in report["arms"][ARM_SCALAR].values():
        assert "skipped" not in cell and cell["n"] == 150
    assert ARM_SCALAR not in report["arm_notes"]


def test_scalar_calibrator_out_of_range_output_is_dropped_not_clipped(tmp_path: Path) -> None:
    data = write_jsonl(tmp_path / "r.jsonl", synthetic_rows(150))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(
        run_threshold_study(
            data, tmp_path / "o", s, "sc2", scalar_calibrator=lambda x: x + 5.0
        ).read_text()
    )
    assert all(c == {"skipped": "insufficient_rows", "n": 0} for c in report["arms"][ARM_SCALAR].values())
    assert "skipped" in report["arm_notes"][ARM_SCALAR]


def _with_causal(rows: list[dict], *, valid: bool) -> list[dict]:
    for i, r in enumerate(rows):
        r["arm_features"]["causal"] = (
            {
                "elapsed_steps": i % 6,
                "retry_count": i % 3,
                "unresolved_contradictions": 0,
                "evidence_freshness": 0.8,
                "tool_failure_history": 0.1,
            }
            if valid
            else {"elapsed_steps": -1}
        )
    return rows


def test_causal_arm_is_scored_when_params_supplied(tmp_path: Path) -> None:
    data = write_jsonl(tmp_path / "r.jsonl", _with_causal(synthetic_rows(150), valid=True))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(
        run_threshold_study(
            data,
            tmp_path / "o",
            s,
            "ca1",
            causal_params=_causal_params(),
            dag_settings=DagSettings(config_salt=SALT),
        ).read_text()
    )
    for cell in report["arms"][ARM_CAUSAL].values():
        assert "skipped" not in cell and cell["n"] == 150
    assert ARM_CAUSAL not in report["arm_notes"]


@pytest.mark.parametrize("valid", [False])
def test_causal_arm_invalid_inputs_are_skipped_not_zero_filled(tmp_path: Path, valid: bool) -> None:
    data = write_jsonl(tmp_path / "r.jsonl", _with_causal(synthetic_rows(150), valid=valid))
    s = settings(str(tmp_path), GRAQLE_DAG_CV_BOOTSTRAP_RESAMPLES="10")
    report = json.loads(
        run_threshold_study(
            data,
            tmp_path / "o",
            s,
            "ca2",
            causal_params=_causal_params(),
            dag_settings=DagSettings(config_salt=SALT),
        ).read_text()
    )
    assert all(c == {"skipped": "insufficient_rows", "n": 0} for c in report["arms"][ARM_CAUSAL].values())
