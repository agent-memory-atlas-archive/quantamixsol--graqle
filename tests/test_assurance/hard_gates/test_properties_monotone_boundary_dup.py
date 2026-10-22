"""CR-013 PR-013c: P-MONO, P-BOUND and P-DUP property tests (AC-17).

P-DUP tests assert that the ATTACK FAILS: duplicating evidence never turns a
FAIL into a PASS.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from graqle.assurance.hard_gates import (
    ContradictionRef,
    HG03ProvenanceForHighImpact,
    HG05Poisoning,
    HG07MaterialContradiction,
)

from ._builders import HG05_SUB, HG07_SUB, make_ctx, make_settings

HG05 = HG05Poisoning()
HG07 = HG07MaterialContradiction()
HG03 = HG03ProvenanceForHighImpact()
SETTINGS = make_settings()
unit = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
PROPS = hyp_settings(max_examples=500, deadline=None)


def _hg05_fails(severity: float | None, threshold: float = HG05_SUB) -> bool:
    s = make_settings(hg05_poisoning_threshold=threshold)
    return not HG05.evaluate(make_ctx(poisoning_severity=severity), s).passed


def _pair(materiality: float | None, **kw: object) -> ContradictionRef:
    return ContradictionRef(a_id="a", b_id="b", materiality=materiality, **kw)  # type: ignore[arg-type]


def _hg07_fails(materiality: float | None, threshold: float = HG07_SUB) -> bool:
    s = make_settings(hg07_materiality_threshold=threshold)
    return not HG07.evaluate(make_ctx(contradictions=(_pair(materiality),)), s).passed


# ── P-MONO: a worse input never rescues a FAIL ─────────────────────────────────────────


@PROPS
@given(a=unit, b=unit)
def test_hg05_is_monotone_in_severity(a: float, b: float) -> None:
    lo, hi = sorted((a, b))
    if _hg05_fails(lo):
        assert _hg05_fails(hi)


@PROPS
@given(a=unit, b=unit)
def test_hg07_is_monotone_in_materiality(a: float, b: float) -> None:
    lo, hi = sorted((a, b))
    if _hg07_fails(lo):
        assert _hg07_fails(hi)


# ── P-BOUND: ≥ semantics at the threshold, eps = 1e-9, float32 round-trip ──────────────

_thresholds = st.floats(min_value=0.01, max_value=1.0, allow_nan=False)


def _f32(x: float) -> float:
    return struct.unpack("f", struct.pack("f", x))[0]


@PROPS
@given(t=_thresholds)
def test_hg05_boundary(t: float) -> None:
    assert _hg05_fails(t, threshold=t)
    assert not _hg05_fails(t - 1e-9, threshold=t)
    t32 = _f32(t)
    assert _hg05_fails(t32, threshold=t32)
    assert not _hg05_fails(t32 - 1e-9, threshold=t32)


@PROPS
@given(t=_thresholds)
def test_hg07_boundary(t: float) -> None:
    assert _hg07_fails(t, threshold=t)
    assert not _hg07_fails(t - 1e-9, threshold=t)
    t32 = _f32(t)
    assert _hg07_fails(t32, threshold=t32)
    assert not _hg07_fails(t32 - 1e-9, threshold=t32)


def test_missing_severity_and_materiality_fail() -> None:
    assert _hg05_fails(None)
    assert _hg07_fails(None)


# ── P-DUP: duplicating evidence never flips FAIL → PASS ────────────────────────────────

_ids = st.lists(st.text(alphabet="abcdef", min_size=1, max_size=3), max_size=4)


@PROPS
@given(events=_ids, sources=_ids, k=st.integers(min_value=1, max_value=20))
def test_hg03_duplicate_provenance_changes_nothing(
    events: list[str], sources: list[str], k: int
) -> None:
    base = make_ctx(
        risk_level="HIGH", provenance_event_ids=tuple(events), provenance_source_ids=tuple(sources)
    )
    dup = make_ctx(
        risk_level="HIGH",
        provenance_event_ids=tuple(events) * k,
        provenance_source_ids=tuple(sources) * k,
    )
    before, after = HG03.evaluate(base, SETTINGS), HG03.evaluate(dup, SETTINGS)
    assert after.passed is before.passed
    assert after.decisive_conditions == before.decisive_conditions
    assert after.inputs_hash == before.inputs_hash  # k copies hash as one (P-CORR)


@PROPS
@given(k=st.integers(min_value=1, max_value=50))
def test_hg03_attack_by_duplicating_one_event_without_a_source_fails(k: int) -> None:
    ctx = make_ctx(
        risk_level="CRITICAL",
        provenance_event_ids=("e1",) * k,
        provenance_source_ids=(),
    )
    assert not HG03.evaluate(ctx, SETTINGS).passed


@PROPS
@given(k=st.integers(min_value=1, max_value=50))
def test_hg03_attack_by_duplicating_one_source_without_an_event_fails(k: int) -> None:
    ctx = make_ctx(
        risk_level="CRITICAL",
        provenance_event_ids=(),
        provenance_source_ids=("s1",) * k,
    )
    assert not HG03.evaluate(ctx, SETTINGS).passed


@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING (PR-013a, not fixed here): HG-03 counts a blank source id as a distinct "
        "provenance source, so a high-impact action with provenance_source_ids=('',) passes. "
        "Strict xfail: flips to a failure as soon as HG-03 rejects blank ids."
    ),
)
def test_hg03_blank_source_id_must_not_count_as_provenance() -> None:
    ctx = make_ctx(
        risk_level="CRITICAL", provenance_event_ids=("e1",), provenance_source_ids=("",) * 3
    )
    assert not HG03.evaluate(ctx, SETTINGS).passed


@PROPS
@given(k=st.integers(min_value=1, max_value=50), reverse=st.booleans())
def test_hg07_duplicating_an_unresolved_pair_never_resolves_it(k: int, reverse: bool) -> None:
    pair = _pair(0.9)
    flipped = ContradictionRef(a_id="b", b_id="a", materiality=0.9)
    dups = tuple(flipped if reverse and i % 2 else pair for i in range(k))
    single = HG07.evaluate(make_ctx(contradictions=(pair,)), SETTINGS)
    many = HG07.evaluate(make_ctx(contradictions=dups), SETTINGS)
    assert not single.passed and not many.passed
    assert many.decisive_conditions == single.decisive_conditions


@PROPS
@given(k=st.integers(min_value=1, max_value=20))
def test_hg07_duplicating_a_resolved_pair_does_not_change_the_result(k: int) -> None:
    resolved = _pair(0.9, coexists_rule_id="rule-1")
    one = HG07.evaluate(make_ctx(contradictions=(resolved,)), SETTINGS)
    many = HG07.evaluate(make_ctx(contradictions=(resolved,) * k), SETTINGS)
    assert one.passed and many.passed
    assert many.inputs_hash == one.inputs_hash


@PROPS
@given(k=st.integers(min_value=1, max_value=20))
def test_hg07_forged_resolution_listed_beside_an_unresolved_record_still_fails(k: int) -> None:
    """Adversarial case C12: a duplicate record may not hide an unresolved pair."""
    unresolved = _pair(0.9)
    forged = _pair(0.9, coexists_rule_id="forged")
    for records in ((forged,) * k + (unresolved,), (unresolved,) + (forged,) * k):
        assert not HG07.evaluate(make_ctx(contradictions=records), SETTINGS).passed
