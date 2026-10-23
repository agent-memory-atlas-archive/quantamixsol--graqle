"""CR-014 PR-014a — additive calibrator version / fitted-at stamp."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from graqle.calibration.methods import (
    BaseCalibrator,
    CalibratorVersionMixin,
    PlattScaling,
    TemperatureScaling,
)


def test_every_calibrator_carries_the_mixin() -> None:
    assert issubclass(BaseCalibrator, CalibratorVersionMixin)


@pytest.mark.parametrize("cls", [TemperatureScaling, PlattScaling])
def test_defaults_mean_never_stamped(cls) -> None:  # type: ignore[no-untyped-def]
    c = cls()
    assert c.calibrator_version == "uncalibrated"
    assert c.fitted_at_unix is None


@pytest.mark.parametrize("cls", [TemperatureScaling, PlattScaling])
def test_stamp_round_trips_through_save_and_load(cls, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    c = cls()
    c._fitted = True
    c.stamp("cal-test-v1", 1_790_000_000.5)
    path = tmp_path / "cal.json"
    c.save(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["calibrator_version"] == "cal-test-v1"
    loaded = cls.load(str(path))
    assert loaded.calibrator_version == "cal-test-v1"
    assert loaded.fitted_at_unix == 1_790_000_000.5


def test_stamping_does_not_leak_between_instances() -> None:
    a, b = TemperatureScaling(), TemperatureScaling()
    a.stamp("cal-a", None)
    assert b.calibrator_version == "uncalibrated"


@pytest.mark.parametrize(
    ("cls", "legacy"),
    [(TemperatureScaling, {"temperature": 1.5}), (PlattScaling, {"a": 1.2, "b": -0.1})],
)
def test_files_written_before_the_change_still_load(cls, legacy, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    loaded = cls.load(str(path))
    assert loaded.fitted
    assert loaded.calibrator_version == "uncalibrated"
    assert loaded.fitted_at_unix is None


@pytest.mark.parametrize(
    ("version", "at"), [("", None), ("   ", None), ("v1", float("nan")), ("v1", float("inf"))]
)
def test_stamp_rejects_bad_values(version: str, at: float | None) -> None:
    with pytest.raises(ValueError):
        TemperatureScaling().stamp(version, at)
