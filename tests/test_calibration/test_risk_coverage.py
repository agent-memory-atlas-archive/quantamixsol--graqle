"""CR-014 AC-3 — risk-coverage curve: oracle ordering monotone, E-AURC ≥ 0."""

from __future__ import annotations

import numpy as np
import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st

from graqle.calibration.metrics import risk_coverage_curve

_rows = st.lists(st.tuples(st.floats(0.0, 1.0), st.integers(0, 1)), min_size=1, max_size=200)


@h_settings(max_examples=300, deadline=None)
@given(rows=_rows)
def test_e_aurc_is_never_negative(rows) -> None:  # type: ignore[no-untyped-def]
    s = np.array([r[0] for r in rows])
    y = np.array([r[1] for r in rows])
    rc = risk_coverage_curve(s, y)
    assert rc.e_aurc >= 0.0
    assert rc.n == len(rows)
    assert np.all((rc.risk >= 0.0) & (rc.risk <= 1.0))


@h_settings(max_examples=200, deadline=None)
@given(labels=st.lists(st.integers(0, 1), min_size=1, max_size=200))
def test_oracle_ordering_is_monotone_and_optimal(labels) -> None:  # type: ignore[no-untyped-def]
    y = np.array(labels)
    s = y + np.linspace(0.0, 0.5, y.size)[::-1] * 0.5  # every correct row ranked first
    s = s / s.max() if s.max() > 0 else s
    rc = risk_coverage_curve(s, y)
    assert np.all(np.diff(rc.risk) >= -1e-12)
    assert rc.e_aurc == pytest.approx(0.0, abs=1e-12)


def test_coverage_grid_and_summary() -> None:
    rc = risk_coverage_curve(np.array([0.9, 0.5, 0.1, 0.3]), np.array([1, 0, 1, 1]))
    assert list(rc.coverage) == [0.25, 0.5, 0.75, 1.0]
    assert set(rc.summary()) == {"aurc", "e_aurc", "n"}


def test_rejects_non_binary_labels() -> None:
    with pytest.raises(ValueError, match="binary"):
        risk_coverage_curve(np.array([0.1, 0.2]), np.array([0.5, 1.0]))
