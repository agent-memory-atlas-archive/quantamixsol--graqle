"""CR-014 PR-014a — causal baselines: deterministic, monotone, private parameters.

Map knots and exponents here are TEST SUBSTITUTES, not deployed values.
"""

from __future__ import annotations

import ast
import inspect

import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st
from pydantic import ValidationError

import graqle.assurance.causal_baselines as cb
from graqle.assurance.settings import ConfigurationError, DagSettings

SALT = "test-substitute-salt-0123456789abcdef-XYZ"
DOWN = cb.MonotoneMap(knots_x=(0.0, 3.0, 9.0), knots_y=(1.0, 0.6, 0.2))
UP = cb.MonotoneMap(knots_x=(0.0, 1.0), knots_y=(0.3, 1.0))
FAIL_DOWN = cb.MonotoneMap(knots_x=(0.0, 1.0), knots_y=(1.0, 0.1))


def _params(**overrides) -> cb.CausalBaselineParams:  # type: ignore[no-untyped-def]
    maps = {"steps": DOWN, "retry": DOWN, "contra": DOWN, "fresh": UP, "tool": FAIL_DOWN}
    exps = {name: 1.0 for name in cb.BASELINE_NAMES}
    maps.update(overrides.pop("maps", {}))
    exps.update(overrides.pop("exponents", {}))
    return cb.CausalBaselineParams(maps=maps, exponents=exps)


def _inp(**overrides) -> cb.CausalBaselineInput:  # type: ignore[no-untyped-def]
    base = dict(
        elapsed_steps=2,
        retry_count=1,
        unresolved_contradictions=0,
        evidence_freshness=0.8,
        tool_failure_history=0.1,
    )
    base.update(overrides)
    return cb.CausalBaselineInput(**base)


SETTINGS = DagSettings(config_salt=SALT)
PARAMS = _params()


def _score(**overrides) -> cb.CausalBaselineScores:  # type: ignore[no-untyped-def]
    return cb.baseline_scores(_inp(**overrides), params=PARAMS, settings=SETTINGS)


def test_deterministic_across_100_runs() -> None:
    first = _score()
    assert all(_score() == first for _ in range(100))


@h_settings(max_examples=150, deadline=None)
@given(a=st.integers(0, 50), b=st.integers(0, 50))
def test_more_steps_retries_or_contradictions_never_raise_the_score(a: int, b: int) -> None:
    lo, hi = sorted((a, b))
    for field, attr in (
        ("elapsed_steps", "b_steps"),
        ("retry_count", "b_retry"),
        ("unresolved_contradictions", "b_contra"),
    ):
        s_lo, s_hi = _score(**{field: lo}), _score(**{field: hi})
        assert getattr(s_hi, attr) <= getattr(s_lo, attr)
        assert s_hi.b_combined <= s_lo.b_combined


@h_settings(max_examples=150, deadline=None)
@given(a=st.floats(0.0, 1.0), b=st.floats(0.0, 1.0))
def test_freshness_up_and_tool_failures_down(a: float, b: float) -> None:
    lo, hi = sorted((a, b))
    assert _score(evidence_freshness=hi).b_fresh >= _score(evidence_freshness=lo).b_fresh
    assert _score(tool_failure_history=hi).b_tool <= _score(tool_failure_history=lo).b_tool


def test_one_collapsed_baseline_collapses_the_combination() -> None:
    zero_tool = cb.MonotoneMap(knots_x=(0.0, 0.5), knots_y=(1.0, 0.0))
    params = _params(maps={"tool": zero_tool})
    out = cb.baseline_scores(_inp(tool_failure_history=0.9), params=params, settings=SETTINGS)
    assert out.b_tool == 0.0 and out.b_combined == 0.0


def test_hash_tracks_input_and_commitment_tracks_params() -> None:
    a = _score()
    assert _score(retry_count=2).inputs_hash != a.inputs_hash
    other = cb.baseline_scores(_inp(), params=_params(exponents={"steps": 2.0}), settings=SETTINGS)
    assert other.config_version != a.config_version
    assert other.inputs_hash == a.inputs_hash


def test_commitment_is_keyed_by_the_salt() -> None:
    other_salt = DagSettings(config_salt=SALT + "-other")
    assert (
        cb.baseline_scores(_inp(), params=PARAMS, settings=other_salt).config_version
        != _score().config_version
    )


def test_missing_salt_refuses() -> None:
    with pytest.raises(ConfigurationError, match="SALT"):
        cb.baseline_scores(_inp(), params=PARAMS, settings=DagSettings())


def test_parameters_never_appear_in_repr_or_results() -> None:
    assert repr(PARAMS) == "CausalBaselineParams(<private>)"
    assert repr(DOWN) == "MonotoneMap(<private>)"
    assert set(cb.CausalBaselineScores.model_fields) == {
        "b_steps",
        "b_retry",
        "b_contra",
        "b_fresh",
        "b_tool",
        "b_combined",
        "inputs_hash",
        "rule_version",
        "config_version",
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"maps": {"steps": UP}},  # wrong direction (must be non-increasing)
        {"maps": {"fresh": DOWN}},  # wrong direction (must be non-decreasing)
        {"exponents": {"retry": 0.0}},
        {"exponents": {"retry": -1.0}},
        {"exponents": {"retry": float("inf")}},
    ],
)
def test_invalid_params_rejected(overrides) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValidationError):
        _params(**overrides)


def test_params_must_cover_exactly_the_five_baselines() -> None:
    with pytest.raises(ValidationError, match="cover exactly"):
        cb.CausalBaselineParams(maps={"steps": DOWN}, exponents={"steps": 1.0})


@pytest.mark.parametrize(
    ("xs", "ys"),
    [
        ((0.0,), (1.0,)),
        ((0.0, 0.0), (1.0, 0.5)),
        ((-1.0, 1.0), (1.0, 0.5)),
        ((0.0, 1.0), (1.2, 0.5)),
    ],
)
def test_invalid_map_knots_rejected(xs, ys) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValidationError):
        cb.MonotoneMap(knots_x=xs, knots_y=ys)


@pytest.mark.parametrize(
    "overrides",
    [{"elapsed_steps": -1}, {"evidence_freshness": 1.5}, {"tool_failure_history": float("nan")}],
)
def test_invalid_inputs_rejected(overrides) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValidationError):
        _inp(**overrides)


def test_module_contains_no_numeric_map_or_exponent_values() -> None:
    """CR-014 AC-19 / TS-1: no float literal other than the [0, 1] range bounds."""
    tree = ast.parse(inspect.getsource(cb))
    floats = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, float)
    }
    assert floats <= {0.0, 1.0}


def test_params_and_settings_are_keyword_only() -> None:
    with pytest.raises(TypeError):
        cb.baseline_scores(_inp(), PARAMS, SETTINGS)  # type: ignore[misc]
