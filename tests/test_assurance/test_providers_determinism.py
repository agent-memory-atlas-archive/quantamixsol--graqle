"""CR-014 PR-014b AC-9 (determinism) and AC-12 (temporal)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from graqle.assurance.confidence_vector import Availability, DimensionName
from graqle.assurance.providers.corroboration import f_cor
from graqle.assurance.providers.operational import f_ops
from graqle.assurance.providers.reasoning import f_rsn
from graqle.governance.failure_predictor import _MIN_TRACES
from tests.test_assurance._cv_fakes import NOW, builder, candidate, context, evidence

_TRACES = [
    {"trace_id": f"t{i}", "tool_name": "tool", "outcome": "success", "gate": "T1"}
    for i in range(_MIN_TRACES)
]


def _ctx(**kw):
    return context(
        evidence=(evidence(1, at=NOW - 1), evidence(2, at=NOW - 2)),
        mandatory_evidence=(evidence(1, at=NOW - 1),),
        recent_traces=_TRACES,
        near_miss_store=SimpleNamespace(corpus_size=lambda: 1),
        drace_score=SimpleNamespace(
            dependency=0.5, reasoning=0.0, auditability=0.1, constraint=0.2, explainability=0.3
        ),
        activation_confidence=0.6,
        activation_variance=0.02,
        **kw,
    )


def test_all_computable_providers_are_deterministic_over_100_runs() -> None:
    first = builder().build(candidate(), _ctx())
    computable = [
        DimensionName.EXTRACTION_RELIABILITY,
        DimensionName.CORROBORATION,
        DimensionName.TEMPORAL_VALIDITY,
        DimensionName.REASONING_SUPPORT,
        DimensionName.OPERATIONAL_RELIABILITY,
    ]
    for name in computable:
        assert first.dims[name].availability is Availability.AVAILABLE, name
    for _ in range(100):
        again = builder().build(candidate(), _ctx())
        assert again.inputs_hash == first.inputs_hash
        for name in computable:
            assert again.dims[name].raw == first.dims[name].raw
            assert [s.inputs_hash for s in again.dims[name].signal_sources] == [
                s.inputs_hash for s in first.dims[name].signal_sources
            ]


def test_operational_unavailable_without_traces_or_store() -> None:
    cv = builder().build(candidate(), context())
    assert cv.dims[DimensionName.OPERATIONAL_RELIABILITY].availability is Availability.NOT_AVAILABLE
    cv = builder().build(candidate(), context(recent_traces=_TRACES))
    assert cv.dims[DimensionName.OPERATIONAL_RELIABILITY].availability is Availability.NOT_AVAILABLE


def test_operational_unavailable_below_min_traces() -> None:
    ctx = context(
        recent_traces=_TRACES[: _MIN_TRACES - 1],
        near_miss_store=SimpleNamespace(corpus_size=lambda: 1),
    )
    cv = builder().build(candidate(), ctx)
    d = cv.dims[DimensionName.OPERATIONAL_RELIABILITY]
    assert d.availability is Availability.NOT_AVAILABLE
    assert d.raw is None


def test_extraction_snapshot_absent_is_recorded_not_defaulted() -> None:
    cv = builder().build(candidate(), context())
    d = cv.dims[DimensionName.EXTRACTION_RELIABILITY]
    assert d.raw == 0.5 and "snapshot=absent" in d.decisive_conditions
    snap = SimpleNamespace(completeness_ratio=lambda: 0.5)
    cv = builder().build(candidate(), context(evidence_state_snapshot=snap))
    assert cv.dims[DimensionName.EXTRACTION_RELIABILITY].raw == 0.25


class TestTemporal:
    def test_superseded_evidence_gives_zero(self) -> None:
        res = SimpleNamespace(
            is_resolved=lambda r: False, is_superseded=lambda e: e.id == "e1"
        )
        cv = builder().build(
            candidate(),
            context(
                mandatory_evidence=(evidence(1, at=NOW), evidence(2, at=NOW)), resolutions=res
            ),
        )
        assert cv.dims[DimensionName.TEMPORAL_VALIDITY].raw == 0.0

    def test_missing_timestamp_is_not_available(self) -> None:
        cv = builder().build(candidate(), context(mandatory_evidence=(evidence(1, at=None),)))
        d = cv.dims[DimensionName.TEMPORAL_VALIDITY]
        assert d.availability is Availability.NOT_AVAILABLE and d.raw is None

    def test_future_timestamp_is_not_available(self) -> None:
        cv = builder().build(candidate(), context(mandatory_evidence=(evidence(1, at=NOW + 5),)))
        assert cv.dims[DimensionName.TEMPORAL_VALIDITY].availability is Availability.NOT_AVAILABLE

    def test_no_mandatory_evidence_is_not_available(self) -> None:
        cv = builder().build(candidate(), context())
        assert cv.dims[DimensionName.TEMPORAL_VALIDITY].availability is Availability.NOT_AVAILABLE

    def test_unknown_source_class_fails_closed(self) -> None:
        e = evidence(1, at=NOW).model_copy(update={"source_class": "unlisted"})
        cv = builder().build(candidate(), context(mandatory_evidence=(e,)))
        assert cv.dims[DimensionName.TEMPORAL_VALIDITY].availability is Availability.PROVIDER_ERROR

    def test_fresher_evidence_scores_higher(self) -> None:
        old = builder().build(candidate(), context(mandatory_evidence=(evidence(1, at=NOW - 20),)))
        new = builder().build(candidate(), context(mandatory_evidence=(evidence(1, at=NOW - 1),)))
        assert new.dims[DimensionName.TEMPORAL_VALIDITY].raw > old.dims[
            DimensionName.TEMPORAL_VALIDITY
        ].raw


class TestMaps:
    def test_f_cor_monotone_and_saturating(self) -> None:
        assert f_cor(1, 0, 3) < f_cor(2, 0, 3) < f_cor(3, 0, 3) == f_cor(9, 0, 3)
        assert f_cor(2, 1, 3) < f_cor(2, 0, 3)
        assert f_cor(0, 0, 3) == 0.0

    def test_f_cor_rejects_bad_inputs(self) -> None:
        with pytest.raises(ValueError):
            f_cor(1, 0, 0)
        with pytest.raises(ValueError):
            f_cor(-1, 0, 3)

    def test_f_ops_any_collapse_dominates_and_is_monotone(self) -> None:
        assert f_ops(1.0, 0.0, 0.0, 0.0) == 0.0
        assert f_ops(0.2, 0.0, 0.0, 0.0) > f_ops(0.4, 0.0, 0.0, 0.0)
        assert f_ops(0.0, 0.0, 0.0, 0.0) == 1.0

    def test_f_rsn_requires_a_signal(self) -> None:
        with pytest.raises(ValueError):
            f_rsn(None, None)
        assert f_rsn(0.5, None) == 0.5
