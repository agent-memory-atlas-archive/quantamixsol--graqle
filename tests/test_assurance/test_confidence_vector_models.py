"""CR-014 PR-014b AC-8, AC-20 and the NOT_AVAILABLE / provider-error semantics (AC-10)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from graqle.assurance.confidence_vector import (
    Availability,
    ConfidenceVector,
    Dimension,
    DimensionName,
    ProviderSignal,
)
from graqle.assurance.reason_codes import REGISTRY
from tests.test_assurance._cv_fakes import FakeConfig, builder, candidate, context, evidence


def _dim(**kw):
    base = dict(
        name=DimensionName.CORROBORATION,
        availability=Availability.AVAILABLE,
        raw=0.5,
        rule_version="1",
        config_version="c",
    )
    base.update(kw)
    return Dimension(**base)


class TestInvariants:
    def test_unavailable_dimension_cannot_carry_values(self) -> None:
        with pytest.raises(ValidationError):
            _dim(availability=Availability.NOT_AVAILABLE)

    def test_available_requires_raw(self) -> None:
        with pytest.raises(ValidationError):
            _dim(raw=None)

    def test_probabilistic_requires_variance(self) -> None:
        with pytest.raises(ValidationError):
            _dim(probabilistic=True)

    def test_calibrated_requires_version(self) -> None:
        with pytest.raises(ValidationError):
            _dim(calibrated=0.4)

    def test_unregistered_reason_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _dim(reason_codes=("DAG-CV-999-NOPE",))

    def test_out_of_range_raw_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _dim(raw=1.5)

    def test_vector_requires_seven_dimensions(self) -> None:
        cv = builder().build(candidate(), context())
        assert len(cv.dims) == 7
        partial = {k: v for k, v in cv.dims.items() if k is not DimensionName.CONTEXT_FIT}
        with pytest.raises(ValidationError):
            ConfidenceVector(**{**cv.model_dump(), "dims": partial})

    def test_new_codes_are_registered(self) -> None:
        for n in ("001-DIM_NOT_AVAILABLE", "007-PROVIDER_ERROR", "008-CONFIG_INVALID"):
            assert f"DAG-CV-{n}" in REGISTRY


class TestNotAvailable:
    def test_unwired_dimensions_are_not_available(self) -> None:
        cv = builder().build(candidate(), context())
        for name in (DimensionName.SOURCE_RELIABILITY, DimensionName.CONTEXT_FIT):
            d = cv.dims[name]
            assert d.availability is Availability.NOT_AVAILABLE
            assert d.raw is None and d.calibrated is None
            assert "DAG-CV-001-DIM_NOT_AVAILABLE" in d.reason_codes
        assert cv.any_not_available is True

    def test_provider_exception_is_provider_error_without_message(self) -> None:
        class Boom:
            def compute(self, c, ctx):
                raise RuntimeError("secret-threshold-0.123")

        cv = builder(overrides={DimensionName.EXTRACTION_RELIABILITY: Boom()}).build(
            candidate(), context()
        )
        d = cv.dims[DimensionName.EXTRACTION_RELIABILITY]
        assert d.availability is Availability.PROVIDER_ERROR
        assert d.raw is None
        assert d.reason_codes == ("DAG-CV-007-PROVIDER_ERROR",)
        assert "secret" not in json.dumps(cv.public_view())
        assert cv.any_provider_error is True

    def test_out_of_range_provider_value_fails_closed(self) -> None:
        class Bad:
            def compute(self, c, ctx):
                return ProviderSignal(raw=2.0)

        cv = builder(overrides={DimensionName.EXTRACTION_RELIABILITY: Bad()}).build(
            candidate(), context()
        )
        assert cv.dims[DimensionName.EXTRACTION_RELIABILITY].availability is Availability.PROVIDER_ERROR

    def test_probabilistic_without_variance_fails_closed(self) -> None:
        cv = builder().build(
            candidate(), context(activation_confidence=0.5, activation_variance=None)
        )
        assert cv.dims[DimensionName.REASONING_SUPPORT].availability is Availability.PROVIDER_ERROR

    def test_probabilistic_with_variance_is_available(self) -> None:
        cv = builder().build(
            candidate(), context(activation_confidence=0.5, activation_variance=0.01)
        )
        d = cv.dims[DimensionName.REASONING_SUPPORT]
        assert d.availability is Availability.AVAILABLE and d.probabilistic and d.variance == 0.01

    def test_builder_requires_one_provider_per_dimension(self) -> None:
        from graqle.assurance.confidence_vector import ConfidenceVectorBuilder
        from graqle.config.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError):
            ConfidenceVectorBuilder(FakeConfig(), {}, lambda: 0.0)


class TestCalibrationHook:
    def _cal(self, shift: float, fitted_at: float):
        rec = SimpleNamespace(calibrator_version="v-test", fitted_at_unix=fitted_at)
        return SimpleNamespace(
            lookup=lambda d, e, dom: rec,
            apply=lambda r, raw: min(1.0, raw + shift),
        )

    def test_stale_record_flags_dimension_and_vector(self) -> None:
        cv = builder(calibrators=self._cal(0.0, fitted_at=0.0)).build(candidate(), context())
        d = cv.dims[DimensionName.EXTRACTION_RELIABILITY]
        assert d.calibration_stale and cv.calibration_stale
        assert "DAG-CV-002-CALIBRATION_STALE" in d.reason_codes
        assert d.raw is not None and d.calibrated is not None  # I-CV-4

    def test_future_fitted_at_is_treated_as_stale(self) -> None:
        cv = builder(calibrators=self._cal(0.0, fitted_at=2_000_000.0)).build(candidate(), context())
        assert cv.dims[DimensionName.EXTRACTION_RELIABILITY].calibration_stale

    def test_stale_and_diverged_together(self) -> None:
        cv = builder(
            FakeConfig(max_divergence=0.4), calibrators=self._cal(0.9, fitted_at=0.0)
        ).build(candidate(), context())
        d = cv.dims[DimensionName.EXTRACTION_RELIABILITY]
        assert d.calibration_stale and d.divergence_exceeded and d.calibrated is None

    def test_divergence_withholds_calibrated_value(self) -> None:
        cv = builder(
            FakeConfig(max_divergence=0.4), calibrators=self._cal(0.9, fitted_at=1_000_000.0)
        ).build(candidate(), context())
        d = cv.dims[DimensionName.EXTRACTION_RELIABILITY]
        assert d.divergence_exceeded and d.calibrated is None and d.raw is not None
        assert "DAG-CV-003-DIVERGENCE_EXCEEDED" in d.reason_codes

    def test_calibrator_exception_fails_dimension_closed(self) -> None:
        def boom(r, raw):
            raise ValueError("version mismatch")

        cal = SimpleNamespace(
            lookup=lambda d, e, dom: SimpleNamespace(calibrator_version="v", fitted_at_unix=NOW_),
            apply=boom,
        )
        NOW_ = 1_000_000.0
        cv = builder(calibrators=cal).build(candidate(), context())
        assert cv.dims[DimensionName.EXTRACTION_RELIABILITY].availability is Availability.PROVIDER_ERROR


class TestFlagOffIsolation:
    """AC-22: nothing outside graqle.assurance imports the new modules."""

    def test_no_outside_importer(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[2] / "graqle"
        needles = (
            "graqle.assurance.confidence_vector",
            "graqle.assurance.providers",
            "graqle.assurance.source_identity",
        )
        offenders = [
            str(p)
            for p in root.rglob("*.py")
            if "assurance" not in p.relative_to(root).parts[:1]
            and any(n in p.read_text(encoding="utf-8") for n in needles)
        ]
        assert offenders == []

    def test_importing_assurance_package_does_not_load_vector(self) -> None:
        import subprocess
        import sys

        out = subprocess.run(
            [sys.executable, "-c",
             "import sys, graqle.assurance; print(any(m.startswith('graqle.assurance.confidence_vector') for m in sys.modules))"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert out == "False"


class TestPublicView:
    def test_no_private_keys_anywhere(self) -> None:
        cfg = FakeConfig(config_provenance={"weights": "SAFE_DEFAULT", "ttl": "ENV"})
        cv = builder(cfg).build(candidate(), context(evidence=(evidence(1),)))
        text = json.dumps(cv.public_view()).lower()
        for key in ("weights", "penalties", "half_life", "policy_threshold", "max_divergence", "ttl"):
            assert f'"{key}"' not in text

    def test_private_text_in_conditions_is_dropped(self) -> None:
        class Leaky:
            def compute(self, c, ctx):
                return ProviderSignal(raw=0.5, decisive_conditions=("half_life=7", "ok=1"))

        cv = builder(overrides={DimensionName.EXTRACTION_RELIABILITY: Leaky()}).build(
            candidate(), context()
        )
        view = cv.public_view()["dims"]["extraction_reliability"]
        assert view["decisive_conditions"] == ["ok=1"]
