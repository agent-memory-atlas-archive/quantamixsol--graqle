"""CR-016 AC-4 — kind-aware validation flags every §4.3 violation; the 9-class example passes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from graqle.core.types import ClearanceLevel
from graqle.ontology.assurance import (
    ASSURANCE_EDGE_KIND_SHAPES,
    AssuranceEdge,
    Claim,
    EdgeKind,
    Evidence,
    validate_assurance_graph,
)

from ._assurance_fixtures import base, conformant_graph, edge, link


def _errors(graph: dict) -> list[str]:
    return [v.message for v in validate_assurance_graph(graph).violations if v.severity == "ERROR"]


def test_conformant_nine_class_example_has_no_errors() -> None:
    graph = conformant_graph()
    assert {n["assurance_type"] for n in graph["nodes"]} == {
        "Evidence",
        "Claim",
        "Abstraction",
        "Instruction",
        "Policy",
        "Decision",
        "Action",
        "Agent",
        "ProvenanceEvent",
    }
    assert {link["properties"]["kind"] for link in graph["links"]} == {k.value for k in EdgeKind}
    assert _errors(graph) == []


def test_every_kind_has_a_shape() -> None:
    assert set(ASSURANCE_EDGE_KIND_SHAPES) == set(EdgeKind)


@pytest.mark.parametrize(
    ("bad_link", "fragment"),
    [
        (link("ev", "cl", "SUPPORTED_BY", prov=False), "not permitted"),  # wrong source class
        (link("de", "ev", "GOVERNED_BY", prov=False), "not permitted"),  # wrong target class
        (link("cl", "ab", "SUPERSEDES"), "same class"),  # cross-class revision
        (link("pe", "pe", "GENERATED"), "not permitted"),  # GENERATED never targets an event
        (link("pe", "ag", "INVALIDATES"), "not permitted"),  # agents are not invalidated
        (link("cl2", "cl", "SUPERSEDES", prov=False), "requires prov_event_id"),
        (link("cl", "ev", "SUPPORTED_BY", prov=False, scope_key=""), "missing scope_key"),
        (link("cl", "ev", "SUPPORTED_BY", prov=False, asserted_at=None), "missing asserted_at"),
    ],
)
def test_each_violation_is_flagged(bad_link: dict, fragment: str) -> None:
    graph = conformant_graph()
    graph["links"].append(bad_link)
    assert any(fragment in m for m in _errors(graph)), _errors(graph)


def test_foreign_and_kindless_relates_to_links_are_ignored() -> None:
    graph = conformant_graph()
    graph["links"] += [
        {
            "source": "cl",
            "target": "ev",
            "relationship": "RELATES_TO",
            "properties": {"kind": "PREREQUISITE_OF"},
        },
        {"source": "cl", "target": "ev", "relationship": "RELATES_TO", "properties": {}},
    ]
    assert _errors(graph) == []


def test_node_model_violations_are_reported() -> None:
    graph = conformant_graph()
    graph["nodes"].append(base("x", "Claim", surprise_field=1))
    graph["nodes"].append(base("y", "NotAClass"))
    errors = _errors(graph)
    assert any("unknown assurance_type" in m for m in errors)
    assert any("surprise_field" in m or "claim_id" in m for m in errors)


def test_models_forbid_extra_fields() -> None:
    node = conformant_graph()["nodes"][0]
    with pytest.raises(ValidationError):
        Evidence.model_validate({**node, "unexpected": 1})


def test_model_class_must_match_assurance_type() -> None:
    node = conformant_graph()["nodes"][0]
    with pytest.raises(ValidationError, match="Evidence model"):
        Evidence.model_validate({**node, "assurance_type": "Claim"})


def test_status_must_equal_lifecycle_status() -> None:
    claim = conformant_graph()["nodes"][1]
    with pytest.raises(ValidationError, match="status must equal"):
        Claim.model_validate({**claim, "status": "PROPOSED"})


def test_claim_valid_time_mirrors_the_interval() -> None:
    claim = conformant_graph()["nodes"][1]
    with pytest.raises(ValidationError, match="valid_time"):
        Claim.model_validate({**claim, "valid_time": "2020-01-01T00:00:00Z/"})


def test_sensitivity_accepts_clearance_names() -> None:
    ev = Evidence.model_validate(conformant_graph()["nodes"][0])
    assert ev.sensitivity is ClearanceLevel.PUBLIC


class TestEdgeModel:
    def test_valid_edge(self) -> None:
        assert AssuranceEdge.model_validate(edge("cl", "ev", "SUPPORTED_BY", strength=0.8))

    def test_id_must_be_deterministic(self) -> None:
        with pytest.raises(ValidationError, match="edge_id"):
            AssuranceEdge.model_validate({**edge("cl", "ev", "SUPPORTED_BY"), "id": "made-up"})

    @pytest.mark.parametrize("kind", ["SUPERSEDES", "CORRECTS", "INVALIDATES", "USED", "GENERATED"])
    def test_prov_event_required(self, kind: str) -> None:
        with pytest.raises(ValidationError, match="prov_event_id"):
            AssuranceEdge.model_validate(edge("a", "b", kind))

    def test_resolved_contradiction_needs_event(self) -> None:
        with pytest.raises(ValidationError, match="resolution_event_id"):
            AssuranceEdge.model_validate(
                edge("a", "b", "CONTRADICTS", resolution_status="RESOLVED")
            )

    @pytest.mark.parametrize("strength", [-0.1, 1.1])
    def test_strength_bounded(self, strength: float) -> None:
        with pytest.raises(ValidationError):
            AssuranceEdge.model_validate(edge("a", "b", "SUPPORTED_BY", strength=strength))
