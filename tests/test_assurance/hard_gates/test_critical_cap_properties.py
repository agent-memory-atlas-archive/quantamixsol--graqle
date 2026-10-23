"""CR-013 PR-013c: critical-failure cap properties (AC-14) and leak guard (AC-15).

Thresholds are the TEST SUBSTITUTES from ``_builders`` (CR-013 §12).
"""

from __future__ import annotations

import json
import logging
import math
from typing import Any

import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from graqle.assurance.critical_cap import CapResult, CriticalFailureCap, apply_cap
from graqle.assurance.hard_gates import (
    GATE_ORDER,
    ContradictionRef,
    HardGateResult,
    default_registry,
)
from graqle.assurance.sensitivity import sensitivity_report
from graqle.assurance.settings import ConfigurationError

from ._builders import (
    HG05_SUB,
    HG07_SUB,
    NOW,
    SUBSTITUTE_SETTINGS,
    leaks,
    make_ctx,
    make_settings,
)

CAP_SUB = SUBSTITUTE_SETTINGS["cap_value"]
_HASH = "sha256:" + "0" * 64
_CFG = "sha256:" + "1" * 64
_CODE = {
    "HG-01": "DAG-HG01-POLICY_MISSING",
    "HG-02": "DAG-HG02-EVIDENCE_INVALIDATED",
    "HG-03": "DAG-HG03-PROVENANCE_MISSING",
    "HG-04": "DAG-HG04-BINDING_ABSENT",
    "HG-05": "DAG-HG05-POISONING_DETECTED",
    "HG-06": "DAG-HG06-ACTOR_UNAUTHORIZED",
    "HG-07": "DAG-HG07-CONTRADICTION_UNRESOLVED",
}

CAP = CriticalFailureCap(make_settings())


def _result(rule_id: str, passed: bool) -> HardGateResult:
    return HardGateResult(
        rule_id=rule_id,
        rule_version="1.0.0",
        severity="CRITICAL",
        passed=passed,
        decisive_conditions=() if passed else ("x",),
        reason_codes=() if passed else (_CODE[rule_id],),
        inputs_hash=_HASH,
        config_version=_CFG,
        evaluated_at=NOW,
        duration_ms=0.0,
    )


def _results(mask: tuple[bool, ...]) -> tuple[HardGateResult, ...]:
    return tuple(_result(rule_id, ok) for rule_id, ok in zip(GATE_ORDER, mask, strict=True))


masks = st.tuples(*[st.booleans()] * len(GATE_ORDER))
unit = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
PROPS = hyp_settings(
    max_examples=10_000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)


@PROPS
@given(a=unit, mask=masks)
def test_cap_is_idempotent_and_bounded(a: float, mask: tuple[bool, ...]) -> None:
    results = _results(mask)
    once = CAP.apply(a, results)
    twice = CAP.apply(once.output_value, results)
    assert twice.output_value == once.output_value  # INV-CAP-1
    assert once.output_value <= a
    if not all(mask):
        assert once.output_value <= CAP_SUB < 1.0  # INV-CAP-3
    else:
        assert once.output_value == a


@PROPS
@given(a=unit, b=unit, mask=masks)
def test_cap_is_monotone(a: float, b: float, mask: tuple[bool, ...]) -> None:
    lo, hi = sorted((a, b))
    results = _results(mask)
    assert CAP.apply(lo, results).output_value <= CAP.apply(hi, results).output_value  # INV-CAP-2


@PROPS
@given(a=unit, mask=masks)
def test_cap_applied_iff_a_gate_failed_and_decisive_is_first(
    a: float, mask: tuple[bool, ...]
) -> None:
    out = CAP.apply(a, _results(mask))
    assert out.cap_applied is (not all(mask))
    expected = next((r for r, ok in zip(GATE_ORDER, mask, strict=True) if not ok), None)
    assert out.decisive_rule == expected
    assert ("DAG-RP-CAP_APPLIED" in out.reason_codes) is out.cap_applied
    if out.cap_applied:
        failed_codes = {_CODE[r] for r, ok in zip(GATE_ORDER, mask, strict=True) if not ok}
        assert failed_codes <= set(out.reason_codes)


@given(a=unit, mask=masks, order=st.permutations(range(len(GATE_ORDER))))
def test_result_order_does_not_change_the_cap(
    a: float, mask: tuple[bool, ...], order: list[int]
) -> None:
    base = _results(mask)
    shuffled = tuple(base[i] for i in order)
    assert CAP.apply(a, shuffled) == CAP.apply(a, base)


@pytest.mark.parametrize(
    "bad", [math.nan, math.inf, -math.inf, -0.1, 1.1, None, "0.9", True, [0.9]]
)
def test_malformed_aggregate_is_treated_as_worst(bad: Any) -> None:
    out = CAP.apply(bad, _results((True,) * 7))
    assert out.input_value == 0.0
    assert out.output_value == 0.0


@pytest.mark.parametrize(
    "results",
    [
        (),
        _results((True,) * 7)[:6],
        _results((True,) * 7) + (_result("HG-01", True),),
        (_result("HG-01", True),) * 7,
    ],
    ids=["empty", "partial", "duplicate-extra", "one-gate-repeated"],
)
def test_incomplete_result_set_fails_closed(results: tuple[HardGateResult, ...]) -> None:
    out = CAP.apply(0.9, results)
    assert out.cap_applied is True
    assert out.output_value <= CAP_SUB
    assert out.decisive_rule is None
    assert "DAG-RP-EVALUATION_ERROR" in out.reason_codes


def test_non_result_objects_fail_closed() -> None:
    out = CAP.apply(0.9, ["pass"] * 7)  # type: ignore[list-item]
    assert out.cap_applied is True and out.output_value <= CAP_SUB


def test_missing_cap_value_refuses_construction() -> None:
    with pytest.raises(ConfigurationError):
        CriticalFailureCap(make_settings(cap_value=None))


def test_cap_result_validator_rejects_inconsistent_state() -> None:
    with pytest.raises(ValueError):
        CapResult(input_value=0.2, output_value=0.5, cap_applied=False)
    with pytest.raises(ValueError):
        CapResult(input_value=0.2, output_value=0.2, cap_applied=True)
    with pytest.raises(ValueError):
        CapResult(
            input_value=0.2,
            output_value=0.2,
            cap_applied=False,
            reason_codes=("DAG-RP-CAP_APPLIED",),
        )


def test_apply_cap_wrapper_matches_class() -> None:
    results = _results((True, True, True, True, False, True, True))
    assert apply_cap(0.9, results, make_settings()) == CAP.apply(0.9, results)


# ── AC-15: no serialised result, repr or log record carries a threshold ──────────────────


def _floats_in(obj: Any) -> list[float]:
    if isinstance(obj, float):
        return [obj]
    if isinstance(obj, dict):
        return [f for v in obj.values() for f in _floats_in(v)]
    if isinstance(obj, list | tuple):
        return [f for v in obj for f in _floats_in(v)]
    return []


_SECRETS = (CAP_SUB, HG05_SUB, HG07_SUB)


def _assert_clean(*objs: Any) -> None:
    for obj in objs:
        text = repr(obj)
        for secret in _SECRETS:
            assert not leaks(secret, text), f"threshold leaked in {type(obj).__name__}"
        dump = obj.model_dump(mode="python") if hasattr(obj, "model_dump") else None
        if dump is not None:
            assert not set(_floats_in(dump)) & set(_SECRETS)
            blob = json.dumps(obj.model_dump(mode="json"))
            for secret in _SECRETS:
                assert not leaks(secret, blob)


def test_no_threshold_in_any_serialised_object(caplog: pytest.LogCaptureFixture) -> None:
    settings = make_settings()
    registry = default_registry()
    # Aggregate BELOW the cap: the output is then not the cap itself (the one
    # observable case, documented in critical_cap.py).
    aggregate = 0.2
    ctx = make_ctx(
        poisoning_severity=0.9,
        contradictions=(ContradictionRef(a_id="a", b_id="b", materiality=0.9),),
    )
    with caplog.at_level(logging.DEBUG):
        results = registry.evaluate_all(ctx, settings)
        cap = CriticalFailureCap(settings)
        out = cap.apply(aggregate, results)
        report = sensitivity_report(registry, settings, ctx)
    assert out.cap_applied and out.output_value == aggregate
    _assert_clean(cap, out, *results)
    blob = json.dumps(report, default=str)
    for secret in _SECRETS:
        assert not leaks(secret, blob)
    assert not hasattr(out, "cap_value") and not hasattr(out, "cap")
    for record in caplog.records:
        message = record.getMessage()
        for secret in _SECRETS:
            assert not leaks(secret, message)


def test_leak_matcher_is_token_exact() -> None:
    # Regression: a measured duration such as 0.3131 must not read as the 0.31 secret.
    assert not leaks(0.31, "duration_ms=0.3131990000042606, error=None")
    assert not leaks(0.31, "x=10.31")
    assert leaks(0.31, "cap_value=0.31, error=None")
    assert leaks(0.31, '{"v": 0.31}')
