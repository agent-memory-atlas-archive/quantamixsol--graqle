"""CR-016 PR-016d: assurance SHACL shapes + validator (AC-11 constructor, AC-12, AC-14)."""

from __future__ import annotations

import copy
from typing import Any

import pytest

pytest.importorskip("pyshacl")

from graqle.governance.shacl import assurance_validator as av  # noqa: E402
from graqle.governance.shacl.assurance_validator import (  # noqa: E402
    AssuranceShaclValidator,
    check_assurance_gate,
)
from tests.test_ontology._assurance_fixtures import base, link  # noqa: E402

HASH = "a" * 64


def _graph(*, claim_supported=True, invalidate=False, contradict=None) -> dict[str, Any]:
    """Minimal conformant graph; flags introduce exactly one structural defect each."""
    ev = base(
        "ev",
        "Evidence",
        evidence_id="ev",
        source="s",
        captured_at="2026-09-01T00:00:00Z",
        canonical_hash=HASH,
        sensitivity="PUBLIC",
        authenticity_status="ATTESTED",
    )

    def claim(cid: str) -> dict[str, Any]:
        return base(
            cid,
            "Claim",
            claim_id=cid,
            canonical_id=f"c-{cid}",
            subject="s",
            predicate="p",
            object="o",
            confidence_vector_version="cv",
            valid_time="2026-07-01T00:00:00Z/",
            status="ACTIVE",
        )

    pe = base(
        "pe",
        "ProvenanceEvent",
        event_id="pe",
        event_type="CREATION",
        actor="ag",
        inputs=[],
        outputs=[],
        canonical_hash=HASH,
        timestamp="2026-09-01T00:00:00Z",
    )
    nodes = [ev, claim("cl"), pe]
    links = []
    if claim_supported:
        links.append(link("cl", "ev", "SUPPORTED_BY", prov=False))
    if invalidate:
        links.append(link("pe", "cl", "INVALIDATES"))
    if contradict is not None:
        nodes.append(claim("cl2"))
        links.append(link("cl2", "ev", "SUPPORTED_BY", prov=False))
        links.append(link("cl", "cl2", "CONTRADICTS", prov=False, **contradict))
    return {"nodes": nodes, "links": links}


@pytest.fixture(scope="module")
def validator() -> AssuranceShaclValidator:
    return AssuranceShaclValidator()


def test_constructs_without_shapes_path_and_reports_version(validator):
    assert validator._shape_set_version == "1.0.0"  # AC-11 (constructor half)
    assert len(validator.shapes_file_hash) == 64


def test_positive_fixture_conforms(validator):
    r = validator.validate_subgraph(_graph())
    assert r.conforms, r.violations
    assert r.shape_set_version == "1.0.0"


def test_positive_contradiction_with_resolution_reference(validator):
    g = _graph(contradict={"resolution_event_id": "pe"})
    assert validator.validate_subgraph(g).conforms


@pytest.mark.parametrize(
    ("kwargs", "text"),
    [
        ({"claim_supported": False}, "SUPPORTED_BY"),
        ({"invalidate": True}, "INVALIDATES target"),
        ({"contradict": {}}, "CONTRADICTS pair"),
    ],
    ids=["claim-support", "invalidated-active", "contradiction-unresolved"],
)
def test_each_sparql_shape_yields_exactly_one_violation(validator, kwargs, text):
    r = validator.validate_subgraph(_graph(**kwargs))  # AC-12
    assert not r.conforms
    assert len(r.violations) == 1, r.violations
    assert text in r.violations[0].message


def test_invalidated_node_that_is_not_active_conforms(validator):
    g = _graph(invalidate=True)
    for n in g["nodes"]:
        if n["id"] == "cl":
            n["lifecycle_status"] = n["status"] = "INVALIDATED"
    assert validator.validate_subgraph(g).conforms


def test_contradiction_ignored_when_one_side_not_active(validator):
    g = _graph(contradict={})
    for n in g["nodes"]:
        if n["id"] == "cl2":
            n["lifecycle_status"] = n["status"] = "SUPERSEDED"
    assert validator.validate_subgraph(g).conforms


def test_property_shapes(validator):
    g = _graph()
    g["nodes"][0]["canonical_hash"] = "not-a-hash"
    r = validator.validate_subgraph(g)
    assert not r.conforms and len(r.violations) == 1

    g = _graph()
    g["nodes"][1]["lifecycle_status"] = "BOGUS"
    g["nodes"][1]["status"] = "ACTIVE"
    assert not validator.validate_subgraph(g).conforms


def test_decision_requires_governance(validator):
    dec = base(
        "de",
        "Decision",
        decision_id="de",
        alternatives=["a"],
        gate_outcome="HOLD",
        residual_risk=0.1,
        status="ACTIVE",
    )
    g = _graph()
    g["nodes"].append(dec)
    r = validator.validate_subgraph(g)
    assert not r.conforms and any("GOVERNED_BY" in v.message for v in r.violations)
    g["nodes"].append(
        base(
            "po",
            "Policy",
            policy_id="po",
            version="1",
            jurisdiction="EU",
            severity="HIGH",
            effective_time="2026-07-01T00:00:00Z",
        )
    )
    g["links"].append(link("de", "po", "GOVERNED_BY", prov=False))
    assert validator.validate_subgraph(g).conforms


def test_node_ids_restriction_keeps_context(validator):
    g = _graph(claim_supported=False)
    assert not validator.validate_subgraph(g, ["cl"]).conforms
    # the supporting evidence is a neighbour, so a supported claim still conforms
    ok = _graph()
    assert validator.validate_subgraph(ok, ["cl"]).conforms
    assert validator.validate_subgraph(g, ["ev"]).conforms  # defect is outside the slice


def test_validator_does_not_mutate_source(validator):
    g = _graph()
    before = copy.deepcopy(g)
    validator.validate_subgraph(g)
    assert g == before


# -- AC-14: fail closed ------------------------------------------------------


def test_injected_fault_is_non_conformance(validator, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("injected")

    monkeypatch.setattr(av, "export_prov", boom)
    r = validator.validate_subgraph(_graph())
    assert r.conforms is False
    assert r.violations[0].shape == "ga:ValidatorError"
    assert "RuntimeError: injected" in r.violations[0].message


def test_malformed_node_is_non_conformance(validator):
    g = _graph()
    g["nodes"][1]["assurance_type"] = "NotAClass"
    r = validator.validate_subgraph(g)
    assert not r.conforms and r.violations[0].shape == "ga:ValidatorError"


def test_inner_validation_error_is_non_conformance(validator, monkeypatch):
    def boom(_g):
        raise ValueError("shacl blew up")

    monkeypatch.setattr(validator._inner, "validate_graph", boom)
    r = validator.validate_subgraph(_graph())
    assert not r.conforms and r.violations[0].shape == "ga:ValidatorError"


def test_missing_shapes_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        AssuranceShaclValidator(tmp_path / "absent.ttl")


# -- gate --------------------------------------------------------------------


def test_gate_passes_and_blocks(validator):
    ok = check_assurance_gate(_graph(), None, validator)
    assert ok.passed and ok.blocked_at is None
    bad = check_assurance_gate(_graph(claim_supported=False), None, validator)
    assert not bad.passed and bad.blocked_at


def test_gate_blocks_on_validator_error(validator, monkeypatch):
    monkeypatch.setattr(av, "export_prov", lambda *a, **k: 1 / 0)
    assert not check_assurance_gate(_graph(), None, validator).passed


def test_gate_without_pyshacl_raises(validator, monkeypatch):
    monkeypatch.setattr(av, "_SHACL_AVAILABLE", False)
    with pytest.raises(ImportError):
        check_assurance_gate(_graph(), None, validator)
