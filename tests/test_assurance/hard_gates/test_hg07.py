"""CR-013 AC-7 — HG-07 material contradiction, de-duplicated by pair."""

from __future__ import annotations

import itertools

import pytest

from graqle.assurance.hard_gates import ContradictionRef, HG07MaterialContradiction

from ._builders import HG07_SUB, make_ctx

GATE = HG07MaterialContradiction()


def _c(
    a: str = "a", b: str = "b", m: float | None = 0.9, coexists: str | None = None
) -> ContradictionRef:
    return ContradictionRef(
        a_id=a, b_id=b, source_ids=("s1",), materiality=m, coexists_rule_id=coexists
    )


def _passed(settings, *cs: ContradictionRef) -> bool:  # type: ignore[no-untyped-def]
    return GATE.evaluate(make_ctx(contradictions=cs), settings).passed


def test_no_contradictions_passes(settings) -> None:  # type: ignore[no-untyped-def]
    assert _passed(settings)


def test_unresolved_material_pair_fails(settings) -> None:  # type: ignore[no-untyped-def]
    r = GATE.evaluate(make_ctx(contradictions=(_c(),)), settings)
    assert not r.passed and r.reason_codes == ("DAG-HG07-CONTRADICTION_UNRESOLVED",)


def test_boundary_is_greater_or_equal(settings) -> None:  # type: ignore[no-untyped-def]
    assert not _passed(settings, _c(m=HG07_SUB))
    assert _passed(settings, _c(m=HG07_SUB - 1e-9))


def test_unknown_materiality_is_material(settings) -> None:  # type: ignore[no-untyped-def]
    assert not _passed(settings, _c(m=None))


def test_coexistence_ruling_resolves(settings) -> None:  # type: ignore[no-untyped-def]
    assert _passed(settings, _c(coexists="rule-1"))


def test_same_pair_listed_twice_or_reversed_counts_once(settings) -> None:  # type: ignore[no-untyped-def]
    one = GATE.evaluate(make_ctx(contradictions=(_c(),)), settings)
    many = GATE.evaluate(make_ctx(contradictions=(_c(), _c(), _c("b", "a"))), settings)
    assert one.passed == many.passed
    assert one.reason_codes == many.reason_codes


@pytest.mark.parametrize(
    "records",
    [
        (_c(m=0.1), _c(m=0.9)),  # materiality is the max over records
        (_c(coexists="rule-1"), _c()),  # resolved only if EVERY record is resolved
        (_c(m=0.1, coexists="rule-1"), _c(m=None)),
    ],
)
def test_pair_decision_is_order_independent_and_fail_closed(records, settings) -> None:  # type: ignore[no-untyped-def]
    outcomes = {
        GATE.evaluate(make_ctx(contradictions=perm), settings).passed
        for perm in itertools.permutations(records)
    }
    assert outcomes == {False}


def test_one_material_pair_among_resolved_ones_fails(settings) -> None:  # type: ignore[no-untyped-def]
    assert not _passed(settings, _c("x", "y", coexists="r"), _c("p", "q", m=0.1), _c("a", "b"))
