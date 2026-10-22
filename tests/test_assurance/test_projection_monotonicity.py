"""Monotonicity: raising one calibrated dimension never lowers the score.

Seeded random sampling (no external property-testing dependency) over the three
strategies the invariant covers: linear, monotonic and rule_only.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from graqle.assurance.confidence_vector import DimensionName, EntityClass
from graqle.assurance.projection import (
    LinearProjection,
    MonotonicProjection,
    ProjectionStrategyName,
    RuleOnlyProjection,
    build_strategy,
    project,
)

from ._proj_fakes import MANDATORY, FakeCap, dim, no_penalty, passed, settings, vector

D = DimensionName
SAMPLES = 400
SEED = 7


def _knots_file(tmp_path: Path) -> Path:
    # Arbitrary monotone test knots, identical shape for every dimension.
    data = {d.value: [[0.0, 0.0], [0.5, 0.25], [1.0, 1.0]] for d in D}
    p = tmp_path / "knots.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _settings(tmp_path: Path, strategy: ProjectionStrategyName):
    extra = {}
    if strategy is ProjectionStrategyName.MONOTONIC:
        extra["GRAQLE_DAG_CV_KNOTS_PATH"] = str(_knots_file(tmp_path))
    return settings(str(tmp_path), strategy, **extra)


@pytest.mark.parametrize(
    "strategy",
    [ProjectionStrategyName.LINEAR, ProjectionStrategyName.MONOTONIC, ProjectionStrategyName.RULE_ONLY],
)
def test_strategy_score_is_monotone_in_every_dimension(tmp_path: Path, strategy) -> None:
    s = _settings(tmp_path, strategy)
    strat = build_strategy(s)
    rng = random.Random(SEED)
    for _ in range(SAMPLES):
        x = {d: rng.random() for d in D}
        d = rng.choice(list(D))
        higher = dict(x)
        higher[d] = min(1.0, x[d] + rng.random())
        for entity_class in EntityClass:
            assert strat.score(higher, s, entity_class) >= strat.score(x, s, entity_class) - 1e-12


@pytest.mark.parametrize(
    "strategy",
    [ProjectionStrategyName.LINEAR, ProjectionStrategyName.MONOTONIC, ProjectionStrategyName.RULE_ONLY],
)
def test_decision_score_is_monotone_through_project(tmp_path: Path, strategy) -> None:
    s = _settings(tmp_path, strategy)
    strat = build_strategy(s)
    rng = random.Random(SEED + 1)
    for _ in range(SAMPLES // 4):
        base = {d: rng.random() for d in D}
        d = rng.choice(list(D))
        raised = dict(base)
        raised[d] = min(1.0, base[d] + rng.random())
        lo = project(
            vector({k: dim(k, v) for k, v in base.items()}), passed(), FakeCap(), s, strat, no_penalty()
        )
        hi = project(
            vector({k: dim(k, v) for k, v in raised.items()}), passed(), FakeCap(), s, strat, no_penalty()
        )
        assert lo.decision_score is not None and hi.decision_score is not None
        assert hi.decision_score >= lo.decision_score - 1e-12
        if lo.admitted:
            assert hi.admitted


def test_rule_only_needs_every_mandatory_floor(tmp_path: Path) -> None:
    s = _settings(tmp_path, ProjectionStrategyName.RULE_ONLY)
    strat = RuleOnlyProjection()
    high = {d: 1.0 for d in D}
    assert strat.score(high, s, EntityClass.DECISION) == 1.0
    for d in MANDATORY:
        missing = {k: v for k, v in high.items() if k is not d}
        assert strat.score(missing, s, EntityClass.DECISION) == 0.0
        below = dict(high)
        below[d] = 0.0
        assert strat.score(below, s, EntityClass.DECISION) == 0.0


def test_piecewise_map_is_clamped_at_the_ends(tmp_path: Path) -> None:
    s = _settings(tmp_path, ProjectionStrategyName.MONOTONIC)
    strat = MonotonicProjection()
    assert strat.score({D.CORROBORATION: 0.0}, s, EntityClass.ENTITY) == 0.0
    assert strat.score({D.CORROBORATION: 1.0}, s, EntityClass.ENTITY) == pytest.approx(
        s.weights[D.CORROBORATION]
    )


def test_linear_is_the_weighted_sum(tmp_path: Path) -> None:
    s = _settings(tmp_path, ProjectionStrategyName.LINEAR)
    x = {d: 0.5 for d in D}
    assert LinearProjection().score(x, s, EntityClass.ENTITY) == pytest.approx(0.5)
