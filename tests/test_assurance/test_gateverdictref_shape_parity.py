"""CR-012 / PR-012b OQ-3 — `GateVerdictRef` shape parity.

The model is DUPLICATED across the assurance/governance boundary so that
`graqle.governance` never imports `graqle.assurance` (AC-21). Duplication is a
drift risk, so this test is the drift DETECTOR the CR relies on: the two
definitions must stay field-identical, with one deliberate difference —
`outcome` is the `GateOutcome` enum on the assurance side and a plain `str` on
the trace side.

OQ-3 is open with the Research Team: a shared leaf module would make drift
impossible by construction rather than detectable after the fact.
"""

from __future__ import annotations

from graqle.assurance.verdict import GateVerdictRef as AssuranceRef
from graqle.governance.trace_schema import GateVerdictRef as TraceRef


def _shape(model: type) -> dict[str, object]:
    return {name: field.is_required() for name, field in model.model_fields.items()}


class TestShapeParity:
    def test_same_field_names_in_the_same_order(self) -> None:
        assert list(AssuranceRef.model_fields) == list(TraceRef.model_fields)

    def test_same_requiredness(self) -> None:
        assert _shape(AssuranceRef) == _shape(TraceRef)

    def test_same_defaults(self) -> None:
        for name, field in AssuranceRef.model_fields.items():
            assert field.default == TraceRef.model_fields[name].default, name

    def test_both_forbid_unknown_fields(self) -> None:
        assert AssuranceRef.model_config.get("extra") == "forbid"
        assert TraceRef.model_config.get("extra") == "forbid"

    def test_outcome_is_str_typed_on_the_trace_side(self) -> None:
        # The deliberate difference: trace_schema must not import GateOutcome.
        assert TraceRef.model_fields["outcome"].annotation is str

    def test_a_verdict_ref_crosses_the_boundary_by_value(self) -> None:
        payload = {
            "verdict_schema_version": "1",
            "outcome": "REJECT",
            "reason_codes": ["DAG-HG01-POLICY_MISSING"],
            "decisive_rule": "HG-01",
            "cap_applied": True,
            "inputs_hash": "sha256:" + "a" * 64,
            "config_version": "sha256:b",
            "evaluation_error_count": 0,
        }
        assert AssuranceRef(**payload).model_dump() == TraceRef(**payload).model_dump()
