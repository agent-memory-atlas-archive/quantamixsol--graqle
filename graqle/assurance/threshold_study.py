"""E2 baseline-arm threshold study (DAG-2026 CR-014, PR-014d).

Reads a labelled JSONL dataset, scores every comparison arm per entity class,
and writes ``e2-report-<run_id>.json`` plus ``e2-report-<run_id>.runlog``.
The report schema is ``e2-report-1`` (see ``docs/assurance/e2-report-schema.md``).

Numbers-to-artefacts: the run log carries ``dataset_hash`` and the hash of the
exact results file, so every reported figure traces to a dataset and a run.

Report bands are public equal-width tenths. Policy thresholds never appear
here: the vector arm only calls :func:`project`, which emits symbolic
references. The run log carries hashes, counts and versions, never settings
values.

An arm whose inputs are missing is skipped with a note. Missing inputs are
never zero-filled and never assumed to pass.
"""

# -- graqle:intelligence --
# module: graqle.assurance.threshold_study
# risk: LOW (impact radius: 1 module -- reached from cli/commands/assurance.py only)
# dependencies: numpy, pydantic, graqle.calibration.metrics, graqle.assurance.projection
# constraints: read-only on the dataset; writes only the two report files
# -- /graqle:intelligence --

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError, field_validator

from graqle.assurance.causal_baselines import (
    CausalBaselineInput,
    CausalBaselineParams,
    baseline_scores,
)
from graqle.assurance.confidence_vector import ConfidenceVector, EntityClass
from graqle.assurance.cv_settings import ConfidenceVectorSettings
from graqle.assurance.projection import (
    HardGateSummary,
    PenaltyInputs,
    build_strategy,
    project,
)
from graqle.assurance.settings import DagSettings
from graqle.calibration.metrics import (
    compute_auprc,
    compute_auroc,
    compute_brier_score,
    compute_ece,
    grouped_bootstrap,
    risk_coverage_curve,
    tc_ece,
)
from graqle.config.exceptions import ConfigurationError

REPORT_SCHEMA = "e2-report-1"

#: Public report bands: equal-width tenths of [0, 1]. Not policy thresholds.
_N_REPORT_BANDS = 10
#: Reporting-method constants (recorded in the report), not policy values.


class _StudyDefaults(BaseModel):
    """Typed home of the reporting-method minimum rows per entity class."""

    model_config = ConfigDict(frozen=True)

    min_rows_per_class: int = Field(default=100)


DEFAULT_MIN_ROWS_PER_CLASS = _StudyDefaults().min_rows_per_class
_MIN_BAND_ROWS = 30
_MATERIAL_BAND_GAP = 0.10

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

ARM_GOVERNANCE = "baseline_governance_tiers"
ARM_ARTICLE14 = "baseline_article14_placeholder"
ARM_DRACE = "baseline_drace_grade"
ARM_SCALAR = "calibrated_scalar"
ARM_VECTOR_PREFIX = "confidence_vector_"
ARM_TRAJECTORY = "trajectory_monitor"
ARM_CAUSAL = "causal_baseline_combined"


class DatasetError(ValueError):
    """The labelled dataset is unreadable or malformed. The study never runs on it."""


class LabelledRow(BaseModel):
    """One labelled decision. ``label`` 1 means the decision was correct."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: str = Field(min_length=1)
    entity_class: EntityClass
    domain: str
    confidence_scalar: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    label: Literal[0, 1]
    group_id: str = Field(min_length=1)
    position: StrictInt = Field(ge=0)
    cv: ConfidenceVector | None = None
    arm_features: dict[str, Any] = Field(default_factory=dict)

    @field_validator("label", mode="before")
    @classmethod
    def _strict_label(cls, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("label must be the integer 0 or 1")
        return value


def load_labelled_rows(path: Path) -> list[LabelledRow]:
    """Parse a JSONL dataset. Any malformed row, or a duplicate trace id, rejects the file."""
    rows: list[LabelledRow] = []
    seen: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetError(f"cannot read dataset: {type(exc).__name__}") from None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = LabelledRow.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise DatasetError(f"line {lineno}: {type(exc).__name__}") from None
        if row.trace_id in seen:
            raise DatasetError(f"line {lineno}: duplicate trace_id")
        seen.add(row.trace_id)
        rows.append(row)
    if not rows:
        raise DatasetError("dataset has no rows")
    return rows


@dataclass(frozen=True)
class _Cap:
    """The recorded critical-failure cap, in the shape :func:`project` reads."""

    cap_applied: bool
    output_value: float


ArmFn = Callable[[LabelledRow], "float | None"]


def _finite_unit(value: Any) -> float | None:
    """A usable score in [0, 1], else ``None`` (never coerced)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    v = float(value)
    return v if math.isfinite(v) and 0.0 <= v <= 1.0 else None


def _danger_to_confidence(row: LabelledRow) -> float | None:
    """1 minus the recorded governance gate score (higher gate score = more dangerous)."""
    gate = _finite_unit(row.arm_features.get("governance_gate_score"))
    return None if gate is None else 1.0 - gate


def _vector_arm(s: ConfidenceVectorSettings, tally: dict[str, int]) -> ArmFn:
    """Score by :func:`project`. Needs recorded gate, cap and penalty inputs."""
    strategy = build_strategy(s)

    def fn(row: LabelledRow) -> float | None:
        f = row.arm_features
        failed = f.get("hard_gates_failed")
        cap = f.get("cap")
        pen = f.get("penalty_inputs")
        if (
            row.cv is None
            or not isinstance(failed, list)
            or not isinstance(cap, dict)
            or not isinstance(pen, dict)
        ):
            return None
        try:
            hg = (
                HardGateSummary(all_passed=True)
                if not failed
                else HardGateSummary(all_passed=False, failed_gate_ids=tuple(map(str, failed)))
            )
            cap_like = _Cap(bool(cap["applied"]), float(cap["value"]))
            result = project(row.cv, hg, cap_like, s, strategy, PenaltyInputs.model_validate(pen))
        except (KeyError, TypeError, ValueError):
            return None
        if result.decision_score is None:
            tally["bottom"] += 1  # counted, never zero-filled
            return None
        return result.decision_score

    return fn


def _causal_arm(params: CausalBaselineParams, dag: DagSettings) -> ArmFn:
    def fn(row: LabelledRow) -> float | None:
        raw = row.arm_features.get("causal")
        if not isinstance(raw, dict):
            return None
        try:
            return baseline_scores(
                CausalBaselineInput.model_validate(raw), params=params, settings=dag
            ).b_combined
        except ValidationError:
            return None

    return fn


def _band_error_rates(scores: np.ndarray, labels: np.ndarray) -> list[dict[str, Any]]:
    """Error rate (1 - mean label) per public tenth band; empty bands report ``None``."""
    idx = np.minimum((scores * _N_REPORT_BANDS).astype(int), _N_REPORT_BANDS - 1)
    bands: list[dict[str, Any]] = []
    for b in range(_N_REPORT_BANDS):
        mask = idx == b
        n = int(mask.sum())
        bands.append(
            {
                "lo": b / _N_REPORT_BANDS,
                "hi": (b + 1) / _N_REPORT_BANDS,
                "n": n,
                "error_rate": None if n == 0 else float(1.0 - labels[mask].mean()),
            }
        )
    return bands


def _class_metrics(
    sc: np.ndarray,
    y: np.ndarray,
    g: np.ndarray,
    t: np.ndarray,
    s: ConfidenceVectorSettings,
) -> dict[str, Any]:
    b = s.bootstrap

    def boot(fn: Callable[..., float]) -> dict:
        return grouped_bootstrap(
            fn, {"scores": sc, "labels": y}, g, b.resamples, b.alpha, b.seed
        )

    return {
        "n": int(sc.size),
        "band_error_rates": _band_error_rates(sc, y),
        "ece": boot(lambda scores, labels: compute_ece(scores, labels)[0]),
        "brier": boot(lambda scores, labels: compute_brier_score(scores, labels)),
        "auroc": boot(lambda scores, labels: compute_auroc(scores, labels)[0]),
        "auprc": boot(lambda scores, labels: compute_auprc(scores, labels)[0]),
        "risk_coverage": risk_coverage_curve(sc, y).summary(),
        "tc_ece": _tc_ece(sc, y, t, s),
    }


def _tc_ece(sc: np.ndarray, y: np.ndarray, t: np.ndarray, s: ConfidenceVectorSettings) -> dict:
    total, buckets = tc_ece(sc, y, t, s.tc_ece_position_edges)
    # Per-bucket reliability tables are left out of the report: the band error rates
    # already carry the public reliability view and the tables would dominate its size.
    return {
        "total": total,
        "buckets": [
            {k: v for k, v in bucket.items() if k != "reliability"} for bucket in buckets
        ],
    }


def _score_arm(
    rows: list[LabelledRow],
    fn: ArmFn,
    s: ConfidenceVectorSettings,
    min_rows: int,
) -> dict[str, Any]:
    per_class: dict[str, Any] = {}
    scored = [(r, fn(r)) for r in rows]
    for cls in EntityClass:
        sub = [(r, v) for r, v in scored if r.entity_class is cls and v is not None]
        if len(sub) < min_rows:
            per_class[cls.value] = {"skipped": "insufficient_rows", "n": len(sub)}
            continue
        sc = np.array([v for _, v in sub], dtype=np.float64)
        y = np.array([r.label for r, _ in sub], dtype=np.float64)
        g = np.array([r.group_id for r, _ in sub])
        t = np.array([r.position for r, _ in sub], dtype=np.int64)
        try:
            per_class[cls.value] = _class_metrics(sc, y, g, t, s)
        except ValueError as exc:  # e.g. a single-class label set: skip, never report a CI
            per_class[cls.value] = {
                "skipped": "metric_undefined",
                "n": len(sub),
                "detail": str(exc),
            }
    return per_class


def _compare_bands_across_classes(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag arm/band cells where classes show materially different error rates."""
    findings: list[dict[str, Any]] = []
    for arm in sorted(report["arms"]):
        per_class = report["arms"][arm]
        for b in range(_N_REPORT_BANDS):
            rates = {
                cls: cell["band_error_rates"][b]["error_rate"]
                for cls, cell in per_class.items()
                if "band_error_rates" in cell
                and cell["band_error_rates"][b]["n"] >= _MIN_BAND_ROWS
            }
            if len(rates) < 2:
                continue
            gap = max(rates.values()) - min(rates.values())
            if gap >= _MATERIAL_BAND_GAP:
                findings.append(
                    {
                        "arm": arm,
                        "band_lo": b / _N_REPORT_BANDS,
                        "band_hi": (b + 1) / _N_REPORT_BANDS,
                        "error_rate_by_class": rates,
                        "gap": gap,
                    }
                )
    return findings


def _sdk_version() -> str:
    from graqle.__version__ import __version__

    return __version__


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def run_threshold_study(
    dataset_path: Path,
    out_dir: Path,
    s: ConfidenceVectorSettings,
    run_id: str,
    *,
    scalar_calibrator: Callable[[float], float] | None = None,
    causal_params: CausalBaselineParams | None = None,
    dag_settings: DagSettings | None = None,
    min_rows_per_class: int = DEFAULT_MIN_ROWS_PER_CLASS,
) -> Path:
    """Run the E2 baseline arms and write the report and run log. Returns the report path."""
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must be 1-64 characters of [A-Za-z0-9._-], starting alphanumeric")
    if min_rows_per_class < 1:
        raise ValueError("min_rows_per_class must be at least 1")

    dataset_bytes = dataset_path.read_bytes()
    dataset_hash = hashlib.sha256(dataset_bytes).hexdigest()
    rows = load_labelled_rows(dataset_path)

    tally = {"bottom": 0}
    arm_notes: dict[str, str] = {}
    arms: dict[str, ArmFn | None] = {
        ARM_GOVERNANCE: _danger_to_confidence,
        ARM_ARTICLE14: lambda r: r.confidence_scalar,
        ARM_DRACE: lambda r: _finite_unit(r.arm_features.get("drace_total")),
    }
    arm_notes[ARM_ARTICLE14] = "placeholder: no calibrated Article 14 threshold exists yet"

    if scalar_calibrator is None:
        arms[ARM_SCALAR] = None
        arm_notes[ARM_SCALAR] = "skipped: no scalar calibrator supplied"
    else:
        calibrator = scalar_calibrator
        arms[ARM_SCALAR] = lambda r: _finite_unit(calibrator(r.confidence_scalar))

    vector_arm = ARM_VECTOR_PREFIX + s.projection_strategy.value
    try:
        arms[vector_arm] = _vector_arm(s, tally)
    except ConfigurationError:
        arms[vector_arm] = None
        arm_notes[vector_arm] = "skipped: projection strategy could not be built"

    arms[ARM_TRAJECTORY] = lambda r: _finite_unit(r.arm_features.get("trajectory_reliability"))
    if causal_params is None or dag_settings is None:
        arms[ARM_CAUSAL] = None
        arm_notes[ARM_CAUSAL] = "skipped: no causal baseline parameters supplied"
    else:
        arms[ARM_CAUSAL] = _causal_arm(causal_params, dag_settings)

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "run_id": run_id,
        "dataset_hash": dataset_hash,
        "sdk_version": _sdk_version(),
        "config_version": s.config_version,
        "seed": s.bootstrap.seed,
        "method": {
            "bands": "equal-width tenths",
            "bootstrap_resamples": s.bootstrap.resamples,
            "bootstrap_alpha": s.bootstrap.alpha,
            "min_rows_per_class": min_rows_per_class,
            "min_band_rows": _MIN_BAND_ROWS,
            "material_band_gap": _MATERIAL_BAND_GAP,
        },
        "n_rows": len(rows),
        "arms": {},
        "arm_notes": arm_notes,
    }
    for arm, fn in arms.items():
        if fn is None:
            report["arms"][arm] = {
                cls.value: {"skipped": "arm_unavailable", "n": 0} for cls in EntityClass
            }
            continue
        per_class = _score_arm(rows, fn, s, min_rows_per_class)
        report["arms"][arm] = per_class
        if all("skipped" in cell for cell in per_class.values()):
            arm_notes.setdefault(arm, "skipped: inputs missing or too few rows in every class")
    if tally["bottom"]:
        arm_notes[vector_arm] = (
            f"{tally['bottom']} rows excluded: projection returned no score (not admitted)"
        )
    report["cross_class_threshold_finding"] = _compare_bands_across_classes(report)

    out_dir.mkdir(parents=True, exist_ok=True)
    results_text = json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
    results_path = out_dir / f"e2-report-{run_id}.json"
    _atomic_write(results_path, results_text)
    run_log = "\n".join(
        [
            f"schema={REPORT_SCHEMA}",
            f"run_id={run_id}",
            f"dataset_hash={dataset_hash}",
            f"results_sha256={hashlib.sha256(results_text.encode('utf-8')).hexdigest()}",
            f"sdk_version={report['sdk_version']}",
            f"config_version={s.config_version}",
            f"seed={s.bootstrap.seed}",
            f"n_rows={len(rows)}",
            "arms_run=" + ",".join(a for a, fn in arms.items() if fn is not None),
            "arms_skipped=" + ",".join(a for a, fn in arms.items() if fn is None),
            "",
        ]
    )
    _atomic_write(out_dir / f"e2-report-{run_id}.runlog", run_log)
    return results_path
