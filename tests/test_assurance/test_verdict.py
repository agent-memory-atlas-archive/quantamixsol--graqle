"""CR-012 / PR-012b — ``GateVerdict`` and friends (CR-012 §4.3, AC-7).

The verdict is fail-closed by construction: EXECUTE is unreachable whenever a
hard gate failed or the evaluation itself errored. Every model is
``extra="forbid"``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.verdict import (
    VERDICT_SCHEMA_VERSION,
    DeterminismRecord,
    GateVerdict,
    GateVerdictRef,
    HardGateResultRef,
)

_NOW = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
_HASH = "sha256:" + "a" * 64


def _determinism(**overrides) -> DeterminismRecord:
    defaults = {
        "inputs_hash": _HASH,
        "rule_id": "HG-01",
        "rule_version": "1",
        "config_version": "sha256:deadbeef",
    }
    defaults.update(overrides)
    return DeterminismRecord(**defaults)


def _verdict(**overrides) -> GateVerdict:
    defaults = {
        "outcome": GateOutcome.HOLD,
        "determinism_record": _determinism(),
        "evaluated_at": _NOW,
    }
    defaults.update(overrides)
    return GateVerdict(**defaults)


class TestDeterminismRecord:
    def test_inputs_hash_shape_is_enforced(self) -> None:
        with pytest.raises(ValidationError):
            _determinism(inputs_hash="not-a-hash")

    def test_probabilistic_requires_variance(self) -> None:
        with pytest.raises(ValidationError, match="variance"):
            _determinism(probabilistic=True)

    def test_probabilistic_with_variance_is_accepted(self) -> None:
        assert _determinism(probabilistic=True, variance=0.31).variance == 0.31


class TestHardGateResultRef:
    def test_error_implies_failure(self) -> None:
        with pytest.raises(ValidationError, match="must not pass"):
            HardGateResultRef(
                rule_id="HG-01",
                rule_version="1",
                passed=True,
                inputs_hash=_HASH,
                evaluated_at=_NOW,
                error="gate raised",
            )

    def test_error_on_a_failed_gate_is_fine(self) -> None:
        ref = HardGateResultRef(
            rule_id="HG-01",
            rule_version="1",
            passed=False,
            inputs_hash=_HASH,
            evaluated_at=_NOW,
            error="gate raised",
        )
        assert ref.passed is False


class TestGateVerdictFailClosed:
    def test_execute_is_impossible_with_a_failed_hard_gate(self) -> None:
        failed = HardGateResultRef(
            rule_id="HG-01",
            rule_version="1",
            passed=False,
            inputs_hash=_HASH,
            evaluated_at=_NOW,
        )
        with pytest.raises(ValidationError, match="failed hard gate"):
            _verdict(outcome=GateOutcome.EXECUTE, hard_gate_results=[failed])

    def test_execute_is_impossible_with_evaluation_errors(self) -> None:
        with pytest.raises(ValidationError, match="evaluation_errors"):
            _verdict(outcome=GateOutcome.EXECUTE, evaluation_errors=["boom"])

    def test_execute_is_allowed_when_every_gate_passed(self) -> None:
        passed = HardGateResultRef(
            rule_id="HG-01",
            rule_version="1",
            passed=True,
            inputs_hash=_HASH,
            evaluated_at=_NOW,
        )
        assert _verdict(
            outcome=GateOutcome.EXECUTE, hard_gate_results=[passed]
        ).outcome is GateOutcome.EXECUTE

    def test_a_failed_gate_is_fine_on_a_non_execute_outcome(self) -> None:
        failed = HardGateResultRef(
            rule_id="HG-01",
            rule_version="1",
            passed=False,
            inputs_hash=_HASH,
            evaluated_at=_NOW,
        )
        assert _verdict(
            outcome=GateOutcome.REJECT, hard_gate_results=[failed]
        ).outcome is GateOutcome.REJECT


class TestGateVerdictSchema:
    def test_default_schema_version(self) -> None:
        assert _verdict().schema_version == VERDICT_SCHEMA_VERSION == "1"

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _verdict(bogus=1)

    def test_unregistered_reason_code_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unregistered"):
            _verdict(reason_codes=["DAG-XX-NOPE"])

    def test_registered_reason_codes_are_deduplicated_in_order(self) -> None:
        v = _verdict(
            reason_codes=[
                "DAG-CV-DIM_MISSING",
                "DAG-TR-EARLY_ERROR",
                "DAG-CV-DIM_MISSING",
            ]
        )
        assert v.reason_codes == ["DAG-CV-DIM_MISSING", "DAG-TR-EARLY_ERROR"]

    def test_confidence_vector_range_is_enforced(self) -> None:
        with pytest.raises(ValidationError, match="out of range"):
            _verdict(confidence_vector={"grounding": 1.7})

    def test_confidence_vector_stays_optional_until_cr014(self) -> None:
        assert _verdict().confidence_vector is None
        assert _verdict().trajectory_reliability is None


class TestGateVerdictRef:
    def test_outcome_is_a_plain_string(self) -> None:
        # The trace side must not import the GateOutcome enum.
        ref = GateVerdictRef(
            verdict_schema_version="1",
            outcome="REJECT",
            reason_codes=["DAG-HG01-POLICY_MISSING"],
            inputs_hash=_HASH,
            config_version="sha256:c",
        )
        assert isinstance(ref.outcome, str)
        assert ref.evaluation_error_count == 0

    def test_carries_no_confidence_vector(self) -> None:
        # TS-1/TS-2: the ref carries hashes and codes, never weights.
        assert "confidence_vector" not in GateVerdictRef.model_fields
        assert "trajectory_reliability" not in GateVerdictRef.model_fields
