"""CR-016 PR-016d AC-13: assurance validation never changes an R22 gate result."""

from __future__ import annotations

import pytest

pytest.importorskip("pyshacl")

from graqle.governance.shacl import ShaclValidator, check_output_gate  # noqa: E402
from graqle.governance.shacl.assurance_validator import (  # noqa: E402
    AssuranceShaclValidator,
    check_assurance_gate,
)
from graqle.governance.trace_schema import GovernedTrace  # noqa: E402
from tests.test_governance.test_shacl import _make_valid_trace  # noqa: E402
from tests.test_ontology.test_assurance_shapes import _graph  # noqa: E402


def _trace(**kw) -> GovernedTrace:
    # R22 on this base requires all eight protocol steps, so reuse the conforming trace
    return _make_valid_trace(query="independence", **kw)


def _r22(trace: GovernedTrace) -> dict:
    r = check_output_gate(trace, ShaclValidator())
    d = r.report.to_dict()
    d.pop("validated_at")
    for v in d["violations"]:
        v.pop("shape")  # blank-node id of the source shape, regenerated on every load
    return {"passed": r.passed, "report": d}


@pytest.mark.parametrize("tool_name", ["graq_reason", ""], ids=["r22-pass", "r22-block"])
def test_r22_result_unchanged_by_assurance_violations(tool_name):
    trace = _trace(tool_name=tool_name)
    before = _r22(trace)
    assert before["passed"] is bool(tool_name)
    bad = check_assurance_gate(
        _graph(claim_supported=False), None, AssuranceShaclValidator()
    )
    assert not bad.passed  # assurance side really has a violation
    assert _r22(trace) == before
    good = check_assurance_gate(_graph(), None, AssuranceShaclValidator())
    assert good.passed
    assert _r22(trace) == before


def test_validators_use_distinct_shape_files():
    r22, assurance = ShaclValidator(), AssuranceShaclValidator()
    assert r22.shapes_file_hash != assurance.shapes_file_hash
    assert "assurance" not in str(r22._shapes_path)
    assert str(assurance._inner._shapes_path).endswith("assurance.ttl")
