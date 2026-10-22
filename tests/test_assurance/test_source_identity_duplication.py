"""CR-014 PR-014b AC-11 (duplication immunity) and the section 2.4.1 / AC-25 rules."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from graqle.assurance.confidence_vector import DimensionName
from graqle.assurance.source_identity import (
    GeneratorRef,
    independent_source_count,
    normalise_locator,
    normalise_model_family,
    source_identity,
)
from tests.test_assurance._cv_fakes import builder, candidate, context, evidence

_BUNDLE = 1


def _count(items, pairs=()):
    return independent_source_count(items, pairs, _BUNDLE)


def test_hand_built_seven_evidence_example() -> None:
    # e1,e2 identical bytes (1 comp); e3 derived from e4 (1 comp); e5,e6 same authority
    # inside the bundle window (1 comp); e7 alone  => 4 components.
    items = [
        evidence(1, content="a" * 64, authority="x"),
        evidence(2, content="a" * 64, authority="x", locator="https://other.example/y"),
        evidence(3),
        evidence(4),
        evidence(5, authority="same", at=100.0),
        evidence(6, authority="same", at=100.5),
        evidence(7),
    ]
    assert _count(items, [("e3", "e4"), ("e9", "e1")]).count == 4


@settings(max_examples=60, deadline=None)
@given(k=st.integers(min_value=1, max_value=50), loc=st.text(min_size=1, max_size=12))
def test_duplicates_never_change_raw_cor(k: int, loc: str) -> None:
    base = [evidence(1), evidence(2)]
    dupes = [evidence(100 + i, content=base[0].content_sha256, authority=base[0].origin_authority_id,
                      locator=f"https://{i}.example/{loc}") for i in range(k)]
    cvs = [
        builder().build(candidate(), context(evidence=tuple(ev))).dims[DimensionName.CORROBORATION]
        for ev in (base, base + dupes)
    ]
    assert cvs[0].raw == cvs[1].raw


def test_same_bytes_different_locator_share_identity_component_but_not_hash() -> None:
    a = evidence(1, content="b" * 64, authority="x", locator="https://a.example/p")
    b = evidence(2, content="b" * 64, authority="x", locator="https://c.example/p")
    assert source_identity(a) != source_identity(b)
    assert _count([a, b]).count == 1


class TestGeneratorCorrelation:
    def _g(self, family="fam-1", tpl="t1", dec="d1"):
        return GeneratorRef(model_family=family, prompt_template_id=tpl, decoding_class=dec)

    def test_equal_generator_collapses_and_is_reported(self) -> None:
        items = [evidence(1, generator=self._g()), evidence(2, generator=self._g()), evidence(3)]
        r = _count(items)
        assert r.count == 2 and r.generator_collapsed is True

    def test_non_model_items_never_collapse_on_none(self) -> None:
        r = _count([evidence(1), evidence(2), evidence(3)])
        assert r.count == 3 and r.generator_collapsed is False

    def test_model_and_non_model_do_not_collapse(self) -> None:
        r = _count([evidence(1, generator=self._g()), evidence(2)])
        assert r.count == 2

    def test_point_version_does_not_decorrelate(self) -> None:
        items = [
            evidence(1, generator=self._g(family="fam-1.2")),
            evidence(2, generator=self._g(family="fam-1.3")),
        ]
        assert _count(items).count == 1
        assert normalise_model_family("Fam-1.2") == normalise_model_family("fam-1.3")

    def test_different_generators_not_evidence_of_independence_but_stay_separate(self) -> None:
        items = [evidence(1, generator=self._g(tpl="a")), evidence(2, generator=self._g(tpl="b"))]
        assert _count(items).count == 2

    def test_info_code_present_exactly_when_collapse_occurs(self) -> None:
        code = "DAG-CV-004-GENERATOR_CORRELATED"
        collapsed = builder().build(
            candidate(), context(evidence=(evidence(1, generator=self._g()), evidence(2, generator=self._g())))
        )
        plain = builder().build(candidate(), context(evidence=(evidence(1), evidence(2))))
        assert code in collapsed.dims[DimensionName.CORROBORATION].reason_codes
        assert code not in plain.dims[DimensionName.CORROBORATION].reason_codes


def test_unresolved_identity_is_reported() -> None:
    item = evidence(1).model_copy(update={"identity_known": False})
    cv = builder().build(candidate(), context(evidence=(item,)))
    assert "DAG-CV-009-SOURCE_INDEPENDENCE_UNRESOLVED" in cv.dims[DimensionName.CORROBORATION].reason_codes


def test_non_positive_bundle_window_is_refused() -> None:
    with pytest.raises(ValueError):
        independent_source_count([evidence(1)], [], 0)


def test_locator_normalisation() -> None:
    assert normalise_locator("HTTPS://A.example/p/?q=1#f") == normalise_locator("https://a.example/p")
