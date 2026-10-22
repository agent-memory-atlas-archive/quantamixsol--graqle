"""CR-013 AC-1, AC-2 — registry completeness and ordered, non-short-circuit evaluation."""

from __future__ import annotations

import pytest

import graqle.assurance.hard_gates as hg
from graqle.assurance.settings import ConfigurationError

from ._builders import make_ctx, make_settings


def _all_gates() -> list[hg.HardGate]:
    return list(hg.default_registry().gates)


def test_default_registry_has_seven_gates_in_fixed_order() -> None:
    assert tuple(g.rule_id for g in hg.default_registry().gates) == hg.GATE_ORDER
    assert hg.GATE_ORDER == ("HG-01", "HG-02", "HG-03", "HG-04", "HG-05", "HG-06", "HG-07")


def test_every_gate_satisfies_the_protocol() -> None:
    for gate in _all_gates():
        assert isinstance(gate, hg.HardGate)


@pytest.mark.parametrize("drop", hg.GATE_ORDER)
def test_registry_refuses_construction_when_a_gate_is_missing(drop: str) -> None:  # AC-1
    with pytest.raises(ConfigurationError, match="incomplete"):
        hg.HardGateRegistry(g for g in _all_gates() if g.rule_id != drop)


def test_registry_refuses_duplicate_gate() -> None:
    gates = _all_gates()
    with pytest.raises(ConfigurationError, match="duplicate"):
        hg.HardGateRegistry([*gates, gates[0]])


def test_registry_refuses_unknown_gate() -> None:
    class HG08(hg.HG05Poisoning):
        rule_id = "HG-08"

    with pytest.raises(ConfigurationError, match="unknown"):
        hg.HardGateRegistry([*_all_gates(), HG08()])


def test_registry_order_is_independent_of_input_order() -> None:
    reg = hg.HardGateRegistry(reversed(_all_gates()))
    assert tuple(g.rule_id for g in reg.gates) == hg.GATE_ORDER


def test_evaluate_all_never_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:  # AC-2
    calls: list[str] = []
    real = hg._BaseGate.evaluate

    def spy(self, ctx, settings):  # type: ignore[no-untyped-def]
        calls.append(self.rule_id)
        return real(self, ctx, settings)

    monkeypatch.setattr(hg._BaseGate, "evaluate", spy)
    ctx = make_ctx(policy=None)  # HG-01 fails first
    results = hg.default_registry().evaluate_all(ctx, make_settings())
    assert calls == list(hg.GATE_ORDER)
    assert len(results) == 7
    assert [r.rule_id for r in results] == list(hg.GATE_ORDER)


def test_decisive_rule_is_first_failure_in_gate_order(settings) -> None:  # type: ignore[no-untyped-def]
    results = hg.default_registry().evaluate_all(make_ctx(policy=None), settings)
    assert hg.decisive_rule(results) == "HG-01"
    # With HG-01 passing, the fail-closed HG-02 placeholder is decisive.
    results = hg.default_registry().evaluate_all(make_ctx(), settings)
    assert hg.decisive_rule(results) == "HG-02"
    assert not hg.all_passed(results)


def test_decisive_rule_none_and_all_passed_when_nothing_fails() -> None:
    assert hg.decisive_rule(()) is None
    assert hg.all_passed(())


@pytest.mark.parametrize("field", ["hg05_poisoning_threshold", "hg07_materiality_threshold"])
def test_missing_required_setting_refuses_before_any_gate_runs(
    field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(hg._BaseGate, "evaluate", lambda self, c, s: calls.append(self.rule_id))
    with pytest.raises(ConfigurationError, match=field):
        hg.default_registry().evaluate_all(make_ctx(), make_settings(**{field: None}))
    assert calls == []


def test_a_gate_that_raises_outside_its_wrapper_is_recorded_as_fail(
    monkeypatch: pytest.MonkeyPatch, settings
) -> None:  # type: ignore[no-untyped-def]
    def boom(self, ctx, s):  # type: ignore[no-untyped-def]
        raise RuntimeError("escaped")

    monkeypatch.setattr(hg.HG05Poisoning, "evaluate", boom)
    results = hg.default_registry().evaluate_all(make_ctx(), settings)
    by_id = {r.rule_id: r for r in results}
    assert len(results) == 7
    assert not by_id["HG-05"].passed
    assert by_id["HG-05"].error == "RuntimeError"
    assert "DAG-RP-EVALUATION_ERROR" in by_id["HG-05"].reason_codes
    assert by_id["HG-07"].passed  # later gates still evaluated
