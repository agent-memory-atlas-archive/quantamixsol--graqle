"""CR-014 AC-6 and ruling N1 — one CalibrationModel, honouring the diagram's contract.

PR-014a decision (N1): the single ``CalibrationModel`` stays in the private
``graqle/governance/calibration.py`` (excluded from the Community wheel). No
public projection is shipped; on the Community wheel ``reliability_diagram``
keeps raising ``CalibrationUnavailableError`` (covered by
``test_reliability_diagram_import.py``).
"""

from __future__ import annotations

import ast
import pathlib
import warnings

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
calibration = pytest.importorskip("graqle.governance.calibration")

#: Every attribute ``reliability_diagram.generate_svg`` dereferences.
MODEL_FIELDS = {
    "version",
    "method",
    "status",
    "n_samples",
    "ece",
    "target_ece",
    "ece_passed",
    "bins",
}
BIN_FIELDS = {"avg_pred", "avg_actual", "count", "ci_low", "ci_high"}


def _model(status: str) -> object:
    bins = [
        calibration.BinStats(
            index=i,
            lower=i / 4,
            upper=(i + 1) / 4,
            count=5 + i,
            avg_pred=(i + 0.5) / 4,
            avg_actual=(i + 0.4) / 4,
            ci_low=i / 4,
            ci_high=(i + 1) / 4,
        )
        for i in range(4)
    ]
    return calibration.CalibrationModel(
        method="platt", status=status, n_samples=26, ece=0.03, ece_passed=True, bins=bins
    )


def test_model_carries_every_field_the_diagram_reads() -> None:
    assert MODEL_FIELDS <= set(calibration.CalibrationModel.model_fields)
    assert BIN_FIELDS <= set(calibration.BinStats.model_fields)


def test_exactly_one_calibration_model_class_exists() -> None:
    hits = []
    for path in (ROOT / "graqle").rglob("*.py"):
        with warnings.catch_warnings():  # unrelated files may hold invalid escapes
            warnings.simplefilter("ignore")
            tree = ast.parse(path.read_text(encoding="utf-8"))
        hits += [
            str(path.relative_to(ROOT))
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "CalibrationModel"
        ]
    assert hits == [str(pathlib.Path("graqle/governance/calibration.py"))]


def test_bins_render_only_for_calibrated_status() -> None:  # AC-6
    from graqle.governance.reliability_diagram import generate_svg

    calibrated = generate_svg(_model("calibrated"))
    uncalibrated = generate_svg(_model("uncalibrated"))
    assert calibrated.count("<circle") == 4
    assert uncalibrated.count("<circle") == 0
    assert "Status: uncalibrated" in uncalibrated
