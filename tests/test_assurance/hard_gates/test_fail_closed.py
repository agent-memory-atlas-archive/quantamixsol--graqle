"""CR-013 AC-8 (P-EXC, P-MISS) — every failure path is FAIL, never PASS, and value-free."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st
from pydantic import ValidationError

import graqle.assurance.hard_gates as hg

from ._builders import HG05_SUB, make_ctx, make_settings

GATE_CLASSES = [
    hg.HG01MandatoryPolicy,
    hg.HG02InvalidatedEvidence,
    hg.HG03ProvenanceForHighImpact,
    hg.HG04ArgsBinding,
    hg.HG05Poisoning,
    hg.HG06ActorAuthorized,
    hg.HG07MaterialContradiction,
]
LEAKY = f"threshold is {HG05_SUB}"  # an exception message that carries a value


@pytest.mark.parametrize("cls", GATE_CLASSES, ids=lambda c: c.rule_id)
def test_predicate_exception_fails_closed_without_leaking(cls, monkeypatch, settings) -> None:  # type: ignore[no-untyped-def]
    def boom(self, ctx, s, deadline):  # type: ignore[no-untyped-def]
        raise RuntimeError(LEAKY)

    monkeypatch.setattr(cls, "_predicate", boom)
    r = cls().evaluate(make_ctx(), settings)
    assert not r.passed
    assert r.severity == "CRITICAL"
    assert r.error == "RuntimeError"
    assert r.decisive_conditions == ("evaluation_error",)
    assert r.reason_codes[0] == "DAG-RP-EVALUATION_ERROR"
    assert str(HG05_SUB) not in r.model_dump_json()


@pytest.mark.parametrize("cls", GATE_CLASSES, ids=lambda c: c.rule_id)
def test_projection_exception_fails_closed_with_a_valid_hash(cls, monkeypatch, settings) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cls, "project", lambda self, ctx: {"bad": float("nan")})
    r = cls().evaluate(make_ctx(), settings)
    assert not r.passed and r.error is not None
    assert r.inputs_hash.startswith("sha256:")


def test_hg06_error_also_carries_rbac_unavailable(monkeypatch, settings) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(hg.HG06ActorAuthorized, "_predicate", lambda *a: 1 / 0)
    r = hg.HG06ActorAuthorized().evaluate(make_ctx(), settings)
    assert r.reason_codes == ("DAG-RP-EVALUATION_ERROR", "DAG-HG06-RBAC_UNAVAILABLE")


def test_exceeding_the_gate_deadline_fails(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def slow(self, ctx, s, deadline):  # type: ignore[no-untyped-def]
        time.sleep(0.05)
        return []

    monkeypatch.setattr(hg.HG01MandatoryPolicy, "_predicate", slow)
    r = hg.HG01MandatoryPolicy().evaluate(make_ctx(), make_settings(gate_timeout_ms=1))
    assert not r.passed
    assert r.error == "TimeoutError: gate deadline exceeded"


def test_hg04_fails_closed_when_the_binding_is_absent(settings) -> None:  # type: ignore[no-untyped-def]
    r = hg.HG04ArgsBinding().evaluate(make_ctx(), settings)
    assert not r.passed and r.error is None
    assert r.reason_codes == ("DAG-HG04-BINDING_ABSENT",)


class TestResultValidator:
    _BASE = dict(
        rule_id="HG-05",
        rule_version="1.0.0",
        severity="CRITICAL",
        inputs_hash="sha256:" + "0" * 64,
        config_version="sha256:x",
        evaluated_at=datetime(2026, 9, 27, tzinfo=timezone.utc),
        duration_ms=0.0,
    )

    def test_error_cannot_pass(self) -> None:
        with pytest.raises(ValidationError, match="error must not pass"):
            hg.HardGateResult(**self._BASE, passed=True, error="RuntimeError")

    def test_pass_carries_no_codes(self) -> None:
        with pytest.raises(ValidationError, match="no conditions"):
            hg.HardGateResult(
                **self._BASE, passed=True, reason_codes=("DAG-HG05-POISONING_DETECTED",)
            )

    def test_fail_needs_a_code(self) -> None:
        with pytest.raises(ValidationError, match="at least one"):
            hg.HardGateResult(**self._BASE, passed=False)

    def test_unregistered_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            hg.HardGateResult(**self._BASE, passed=False, reason_codes=("DAG-HG05-MADE_UP",))


@h_settings(max_examples=50, deadline=None)
@given(victim=st.sampled_from(GATE_CLASSES))
def test_exception_in_one_gate_leaves_the_others_evaluated(victim) -> None:  # type: ignore[no-untyped-def]
    original = victim._predicate
    victim._predicate = lambda self, ctx, s, d: (_ for _ in ()).throw(RuntimeError("x"))
    try:
        results = hg.default_registry().evaluate_all(make_ctx(), make_settings())
    finally:
        victim._predicate = original
    assert len(results) == 7
    by_id = {r.rule_id: r for r in results}
    assert by_id[victim.rule_id].error == "RuntimeError"
    assert all(r.error is None for rid, r in by_id.items() if rid != victim.rule_id)
