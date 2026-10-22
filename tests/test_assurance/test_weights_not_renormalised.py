"""A missing compensatory dimension is dropped; the remaining weights are not renormalised."""

from __future__ import annotations

from pathlib import Path

import pytest

from graqle.assurance.confidence_vector import Availability, DimensionName
from graqle.assurance.projection import LinearProjection, project

from ._proj_fakes import FakeCap, dim, no_penalty, passed, settings, vector

D = DimensionName
COMPENSATORY = D.CONTEXT_FIT


def test_missing_compensatory_dim_lowers_the_score(tmp_path: Path) -> None:
    s = settings(str(tmp_path))
    full = vector(default=1.0)
    missing = vector(
        {COMPENSATORY: dim(COMPENSATORY, availability=Availability.NOT_AVAILABLE)}, default=1.0
    )
    a = project(full, passed(), FakeCap(), s, LinearProjection(), no_penalty())
    b = project(missing, passed(), FakeCap(), s, LinearProjection(), no_penalty())
    assert b.decision_score is not None and a.decision_score is not None
    assert b.decision_score < a.decision_score


def test_drop_equals_removing_exactly_that_weight(tmp_path: Path) -> None:
    s = settings(str(tmp_path))
    missing = vector(
        {COMPENSATORY: dim(COMPENSATORY, availability=Availability.NOT_AVAILABLE)}, default=1.0
    )
    res = project(missing, passed(), FakeCap(), s, LinearProjection(), no_penalty())
    expected = sum(w for d, w in s.weights.items() if d is not COMPENSATORY)
    assert res.decision_score == pytest.approx(expected)
    assert res.decision_score < 1.0 - 1e-9
