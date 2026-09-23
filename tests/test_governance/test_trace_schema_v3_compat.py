"""CR-012 / PR-012b — trace schema v3 compatibility (AC-12 … AC-15).

v3 adds ONE optional field (`assurance`). The reader accepts v1/v2/v3 and
PRESERVES the version a record was written under; the writer omits `assurance`
while it is None so a v3 record stays readable by a v0.83.0 reader.
"""

from __future__ import annotations

import json

import pytest

from graqle.governance.tamper_evidence.leaf_input_schema import (
    LEAF_HASH_FIELDS,
    LEAF_INPUT_VERSION,
)
from graqle.governance.trace_schema import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    Decision,
    GateVerdictRef,
    GovernedTrace,
    Outcome,
    read_trace,
)

_V1 = {"tool_name": "graq_inspect", "query": "old", "outcome": "SUCCESS", "confidence": 0.9}
_V2 = {**_V1, "schema_version": "2"}


def _ref() -> GateVerdictRef:
    return GateVerdictRef(
        verdict_schema_version="1",
        outcome="REJECT",
        reason_codes=["DAG-HG01-CC"],
        decisive_rule="HG-01",
        cap_applied=True,
        inputs_hash="sha256:" + "a" * 64,
        config_version="sha256:b",
    )


class TestConstants:
    def test_writer_version_is_3(self) -> None:
        assert CURRENT_SCHEMA_VERSION == "3"

    def test_reader_supports_1_2_3(self) -> None:
        assert SUPPORTED_SCHEMA_VERSIONS == frozenset({"1", "2", "3"})


class TestAC12LegacyRecords:
    """v1 and v2 records read without error; assurance is None; version kept."""

    def test_v1_record_keeps_its_version(self) -> None:
        trace = read_trace(_V1)
        assert trace.schema_version == "1"
        assert trace.assurance is None

    def test_v2_record_keeps_its_version(self) -> None:
        trace = read_trace(_V2)
        assert trace.schema_version == "2"
        assert trace.assurance is None

    def test_reader_never_mutates_the_input(self) -> None:
        raw = dict(_V2)
        snapshot = dict(raw)
        read_trace(raw)
        assert raw == snapshot

    def test_legacy_record_is_not_relabelled_as_v3(self) -> None:
        # A relabelled record would assert a schema generation it predates, and
        # schema_version reaches governance_metadata inside LEAF_HASH_FIELDS —
        # so the record would hash to a different Merkle leaf than at commit.
        assert read_trace(_V1).schema_version != CURRENT_SCHEMA_VERSION


class TestAC13V3RoundTrip:
    def test_round_trip_preserves_the_verdict(self) -> None:
        trace = GovernedTrace(
            tool_name="graq_edit",
            query="q",
            outcome=Outcome.BLOCKED,
            confidence=0.62,
            assurance=_ref(),
        )
        restored = read_trace(trace.to_internal_dict())
        assert restored.assurance is not None
        assert restored.assurance.outcome == "REJECT"
        assert restored.assurance.reason_codes == ["DAG-HG01-CC"]
        assert restored.schema_version == "3"

    def test_public_dict_excludes_internal_fields(self) -> None:
        trace = GovernedTrace(
            tool_name="graq_edit",
            query="q",
            outcome=Outcome.BLOCKED,
            confidence=0.62,
            assurance=_ref(),
        )
        public = trace.to_public_dict()
        assert "assurance" not in public
        assert "governance_decisions" not in public

    def test_assurance_is_omitted_entirely_while_none(self) -> None:
        # Not `"assurance": null` — the key is absent, so a v0.83.0 reader with
        # extra="forbid" still accepts the record.
        trace = GovernedTrace(
            tool_name="t", query="q", outcome=Outcome.SUCCESS, confidence=0.1
        )
        internal = trace.to_internal_dict()
        assert "assurance" not in internal
        json.dumps(internal, default=str)


class TestAC14UnknownVersions:
    def test_strict_rejects_a_future_version(self) -> None:
        with pytest.raises(ValueError, match="unsupported"):
            read_trace({**_V1, "schema_version": "4"}, strict=True)

    def test_non_strict_warns_and_parses(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            trace = read_trace(
                {**_V1, "schema_version": "4", "brand_new_key": 1}, strict=False
            )
        assert trace.schema_version == "4"
        assert "brand_new_key" in caplog.text

    def test_strict_is_read_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GRAQLE_TRACE_SCHEMA_STRICT", "true")
        with pytest.raises(ValueError):
            read_trace({**_V1, "schema_version": "4"})

    def test_strict_defaults_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GRAQLE_TRACE_SCHEMA_STRICT", raising=False)
        assert read_trace({**_V1, "schema_version": "4"}).schema_version == "4"

    def test_invalid_record_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="failed v2 validation"):
            read_trace({"schema_version": "2", "tool_name": "t"})


class TestAC15LeafUnchanged:
    def test_leaf_hash_fields_tuple_is_untouched(self) -> None:
        assert LEAF_HASH_FIELDS == (
            "proof_format_version",
            "record_id",
            "content_hash",
            "timestamp_unix",
            "governance_metadata",
        )

    def test_leaf_input_version_is_untouched(self) -> None:
        assert LEAF_INPUT_VERSION == "1.0.0"


class TestDecisionEnumUntouched:
    def test_decision_still_has_exactly_three_members(self) -> None:
        # Review checklist (1): PR-012b must not extend Decision.
        assert [d.value for d in Decision] == ["PASS", "BLOCK", "WARN"]
