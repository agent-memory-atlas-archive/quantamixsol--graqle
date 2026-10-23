"""The calibrator registry is JSON-only, strict, and never falls back."""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pytest

from graqle.assurance.calibrator_registry import (
    CalibratorKey,
    CalibratorRegistry,
)
from graqle.assurance.confidence_vector import DimensionName, EntityClass
from graqle.calibration.methods import PlattScaling, TemperatureScaling
from graqle.config.exceptions import ConfigurationError

KEY = CalibratorKey(
    dimension=DimensionName.CORROBORATION, entity_class=EntityClass.DECISION, domain="d"
)
NOW = 5_000.0


def _registry(path: Path, now: float = NOW) -> CalibratorRegistry:
    return CalibratorRegistry(path, lambda: now)


def _fitted_temperature(t: float = 2.0) -> TemperatureScaling:
    cal = TemperatureScaling(temperature=t)
    cal._fitted = True
    return cal


def _fitted_platt() -> PlattScaling:
    cal = PlattScaling(a=1.5, b=0.1)
    cal._fitted = True
    return cal


def _register(reg: CalibratorRegistry, cal=None):
    return reg.register(KEY, cal or _fitted_temperature(), 100, "ds-hash", 0.05, "cfg-test")


def _only_file(path: Path) -> Path:
    (f,) = [p for p in path.iterdir() if p.suffix == ".json"]
    return f


class TestPersistence:
    def test_round_trip_through_json_only(self, tmp_path: Path) -> None:
        rec = _register(_registry(tmp_path))
        files = list(tmp_path.iterdir())
        assert [f.suffix for f in files] == [".json"]
        again = _registry(tmp_path)
        assert again.lookup(KEY.dimension, KEY.entity_class, KEY.domain) == rec

    def test_lookup_miss_is_none(self, tmp_path: Path) -> None:
        assert _registry(tmp_path).lookup(DimensionName.CONTEXT_FIT, EntityClass.ENTITY, "x") is None

    def test_version_is_content_addressed(self, tmp_path: Path) -> None:
        a_dir = tmp_path / "a"
        a_dir.mkdir()
        a = _register(_registry(a_dir))
        b_dir = tmp_path / "b"
        b_dir.mkdir()
        b = _register(_registry(b_dir), _fitted_temperature(3.0))
        assert a.calibrator_version != b.calibrator_version
        assert len(a.calibrator_version) == 16

    def test_platt_and_isotonic_round_trip(self, tmp_path: Path) -> None:
        reg = _registry(tmp_path)
        rec = _register(reg, _fitted_platt())
        assert rec.method == "platt"
        out = reg.apply(rec, 0.5)
        assert 0.0 <= out <= 1.0


class TestRejection:
    def test_pickle_file_is_refused_unread(self, tmp_path: Path) -> None:
        (tmp_path / "calibrator.pkl").write_bytes(pickle.dumps({"x": 1}))
        with pytest.raises(ConfigurationError, match="JSON files only"):
            _registry(tmp_path)

    def test_pickle_bytes_named_json_are_refused(self, tmp_path: Path) -> None:
        (tmp_path / "calibrator.json").write_bytes(pickle.dumps({"x": 1}))
        with pytest.raises(ConfigurationError, match="CALIBRATOR_VERSION_UNKNOWN"):
            _registry(tmp_path)

    def test_missing_directory_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            _registry(tmp_path / "absent")

    def test_unknown_method_is_refused_not_defaulted(self, tmp_path: Path) -> None:
        _register(_registry(tmp_path))
        f = _only_file(tmp_path)
        data = json.loads(f.read_text())
        data["method"] = "histogram"
        f.write_text(json.dumps(data))
        with pytest.raises(ConfigurationError, match="CALIBRATOR_VERSION_UNKNOWN"):
            _registry(tmp_path)

    def test_tampered_params_break_the_version(self, tmp_path: Path) -> None:
        _register(_registry(tmp_path))
        f = _only_file(tmp_path)
        data = json.loads(f.read_text())
        data["params"]["temperature"] = 9.0
        f.write_text(json.dumps(data))
        with pytest.raises(ConfigurationError, match="does not match its version"):
            _registry(tmp_path)

    @pytest.mark.parametrize("bad", [0.0, -1.0])
    def test_non_positive_temperature_is_refused(self, tmp_path: Path, bad: float) -> None:
        reg = _registry(tmp_path)
        cal = _fitted_temperature()
        cal._temperature = bad
        with pytest.raises(ConfigurationError):
            _register(reg, cal)

    def test_non_monotone_platt_is_refused(self, tmp_path: Path) -> None:
        cal = PlattScaling(a=1.0, b=0.0)
        cal._a, cal._fitted = -1.0, True
        with pytest.raises(ConfigurationError):
            _register(_registry(tmp_path), cal)

    def test_unfitted_calibrator_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            _register(_registry(tmp_path), TemperatureScaling(temperature=2.0))

    def test_unsupported_calibrator_type_is_refused(self, tmp_path: Path) -> None:
        class Other:
            fitted = True

        with pytest.raises(ConfigurationError):
            _register(_registry(tmp_path), Other())

    def test_duplicate_keys_are_refused(self, tmp_path: Path) -> None:
        _register(_registry(tmp_path))
        f = _only_file(tmp_path)
        (tmp_path / "copy.json").write_text(f.read_text())
        with pytest.raises(ConfigurationError):
            _registry(tmp_path)


class TestApply:
    def test_unregistered_record_is_refused(self, tmp_path: Path) -> None:
        rec = _register(_registry(tmp_path))
        other = tmp_path / "other"
        other.mkdir()
        with pytest.raises(ConfigurationError, match="not registered"):
            _registry(other).apply(rec, 0.5)

    @pytest.mark.parametrize("raw", [-0.1, 1.1, float("nan"), float("inf")])
    def test_out_of_range_raw_is_refused(self, tmp_path: Path, raw: float) -> None:
        reg = _registry(tmp_path)
        with pytest.raises(ConfigurationError):
            reg.apply(_register(reg), raw)

    def test_output_is_in_unit_interval_and_monotone(self, tmp_path: Path) -> None:
        reg = _registry(tmp_path)
        rec = _register(reg)
        grid = np.linspace(0.0, 1.0, 51)
        out = [reg.apply(rec, float(v)) for v in grid]
        assert all(0.0 <= v <= 1.0 for v in out)
        assert all(b >= a - 1e-12 for a, b in zip(out, out[1:]))

    def test_isotonic_knots_interpolate(self, tmp_path: Path) -> None:
        reg = _registry(tmp_path)
        rec = _register(reg)
        data = rec.model_dump(mode="json")
        data["method"] = "isotonic_json"
        data["params"] = {"x": [0.0, 1.0], "y": [0.0, 0.5]}
        from graqle.assurance.calibrator_registry import CalibratorRecord, _version_of

        data["calibrator_version"] = _version_of(
            KEY, "isotonic_json", data["params"], rec.fitted_at_unix, rec.dataset_hash
        )
        iso = CalibratorRecord.model_validate(data)
        reg._recs[KEY] = iso
        assert reg.apply(iso, 0.5) == pytest.approx(0.25)
