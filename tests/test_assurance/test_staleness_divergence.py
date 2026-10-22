"""Calibrator staleness (time-to-live) and the divergence guard, with an injected clock."""

from __future__ import annotations

from pathlib import Path

import pytest

from graqle.assurance.calibrator_registry import CalibratorKey, CalibratorRegistry
from graqle.assurance.confidence_vector import (
    Availability,
    ConfidenceVectorBuilder,
    DimensionName,
    EntityClass,
    ProviderSignal,
)
from graqle.calibration.methods import TemperatureScaling

from ._cv_fakes import FakeConfig, candidate, context, providers
from ._proj_fakes import settings

D = DimensionName
RAW = 0.9
TTL = 100  # matches the placeholder environment in _proj_fakes
FITTED_AT = 1_000.0


class FixedProvider:
    def compute(self, cand, ctx) -> ProviderSignal:
        return ProviderSignal(availability=Availability.AVAILABLE, raw=RAW)


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _calibrator(t: float) -> TemperatureScaling:
    cal = TemperatureScaling(temperature=t)
    cal._fitted = True
    return cal


def _build(tmp_path: Path, *, t: float, now: float, max_divergence: str = "0.4"):
    clock = Clock(FITTED_AT)
    reg = CalibratorRegistry(tmp_path, clock)
    key = CalibratorKey(dimension=D.CORROBORATION, entity_class=EntityClass.ENTITY, domain="d")
    reg.register(key, _calibrator(t), 10, "ds", 0.05, "cfg-test")
    s = settings(str(tmp_path / "unused"), GRAQLE_DAG_CV_MAX_DIVERGENCE=max_divergence)
    clock.now = now
    provs = providers(FakeConfig())
    provs[D.CORROBORATION] = FixedProvider()
    cv = ConfidenceVectorBuilder(s, provs, clock, reg).build(candidate(), context())
    return cv, cv.dims[D.CORROBORATION]


class TestStaleness:
    def test_fresh_record_is_not_stale(self, tmp_path: Path) -> None:
        cv, d = _build(tmp_path, t=1.0, now=FITTED_AT + TTL)
        assert d.calibration_stale is False
        assert cv.calibration_stale is False
        assert d.calibrated == pytest.approx(RAW)

    def test_older_than_ttl_is_stale_on_dimension_and_vector(self, tmp_path: Path) -> None:
        cv, d = _build(tmp_path, t=1.0, now=FITTED_AT + TTL + 1)
        assert d.calibration_stale is True
        assert cv.calibration_stale is True
        assert "DAG-CV-002-CALIBRATION_STALE" in d.reason_codes

    def test_future_dated_record_is_stale(self, tmp_path: Path) -> None:
        _, d = _build(tmp_path, t=1.0, now=FITTED_AT - 1)
        assert d.calibration_stale is True

    def test_registry_is_stale_helper_agrees(self, tmp_path: Path) -> None:
        reg = CalibratorRegistry(tmp_path, Clock(FITTED_AT))
        key = CalibratorKey(dimension=D.CORROBORATION, entity_class=EntityClass.ENTITY, domain="d")
        rec = reg.register(key, _calibrator(1.0), 10, "ds", 0.05, "cfg-test")
        reg._clock = Clock(FITTED_AT + TTL)
        assert reg.is_stale(rec, TTL) is False
        reg._clock = Clock(FITTED_AT + TTL + 1)
        assert reg.is_stale(rec, TTL) is True
        reg._clock = Clock(FITTED_AT - 1)
        assert reg.is_stale(rec, TTL) is True


class TestDivergence:
    def test_within_bound_keeps_the_calibrated_value(self, tmp_path: Path) -> None:
        _, d = _build(tmp_path, t=1.0, now=FITTED_AT)
        assert d.divergence_exceeded is False
        assert d.calibrated is not None

    def test_beyond_bound_nulls_calibrated_and_emits_code(self, tmp_path: Path) -> None:
        _, d = _build(tmp_path, t=10.0, now=FITTED_AT, max_divergence="0.1")
        assert d.divergence_exceeded is True
        assert d.calibrated is None
        assert d.raw == pytest.approx(RAW)
        assert "DAG-CV-003-DIVERGENCE_EXCEEDED" in d.reason_codes

    def test_unknown_record_stays_uncalibrated(self, tmp_path: Path) -> None:
        reg = CalibratorRegistry(tmp_path, Clock(FITTED_AT))
        s = settings(str(tmp_path / "unused"))
        provs = providers(FakeConfig())
        provs[D.CORROBORATION] = FixedProvider()
        cv = ConfidenceVectorBuilder(s, provs, Clock(FITTED_AT), reg).build(candidate(), context())
        d = cv.dims[D.CORROBORATION]
        assert d.calibrated is None and d.calibrator_version == "uncalibrated"
