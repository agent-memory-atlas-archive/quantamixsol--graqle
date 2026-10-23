"""CR-013 AC-5 — HG-05 poisoning: ≥ boundary, missing severity, monotonicity."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st
from pydantic import ValidationError

from graqle.assurance.hard_gates import HG05Poisoning

from ._builders import HG05_SUB, make_ctx, make_settings

GATE = HG05Poisoning()
S = make_settings()


def _passed(severity: float | None) -> bool:
    return GATE.evaluate(make_ctx(poisoning_severity=severity), S).passed


def test_at_threshold_fails() -> None:  # P-BOUND, ≥ semantics
    r = GATE.evaluate(make_ctx(poisoning_severity=HG05_SUB), S)
    assert not r.passed
    assert r.decisive_conditions == ("poisoning_detected",)
    assert r.reason_codes == ("DAG-HG05-POISONING_DETECTED",)


def test_just_below_threshold_passes() -> None:
    assert _passed(HG05_SUB - 1e-9)


def test_missing_severity_fails() -> None:  # P-MISS
    r = GATE.evaluate(make_ctx(poisoning_severity=None), S)
    assert not r.passed and r.decisive_conditions == ("severity_unknown",)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.1, 1.1])
def test_malformed_severity_is_rejected_at_the_model(bad: float) -> None:
    with pytest.raises(ValidationError):
        make_ctx(poisoning_severity=bad)


@h_settings(max_examples=200, deadline=None)
@given(a=st.floats(0.0, 1.0), b=st.floats(0.0, 1.0))
def test_monotone_in_severity(a: float, b: float) -> None:  # P-MONO (larger is worse)
    lo, hi = sorted((a, b))
    if not _passed(lo):
        assert not _passed(hi)
