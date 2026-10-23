"""CR-016 PR-016c AC-9: PROV-O round-trip, external validation, direction, historical filter."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

rdflib = pytest.importorskip("rdflib")
pyshacl = pytest.importorskip("pyshacl")

from rdflib import RDF, RDFS, BNode, Graph, Namespace, URIRef  # noqa: E402

from graqle.ontology.assurance import EdgeKind, edge_id, validate_assurance_graph  # noqa: E402
from graqle.ontology.prov_export import (  # noqa: E402
    DEFAULT_BASE_IRI,
    ProvExportError,
    export_prov,
    import_prov,
    public_projection,
    serialize,
)
from tests.test_ontology._assurance_fixtures import (  # noqa: E402
    SCOPE,
    T0,
    T1,
    base,
    conformant_graph,
    link,
)

PROV = Namespace("http://www.w3.org/ns/prov#")
GA = Namespace(DEFAULT_BASE_IRI)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "prov"
PROV_O_SHA256 = "7d203989f67b38bca572253942acc5a1bf24ce3ccfece16f072dcb4be2b79a96"
AT = "2026-10-01T00:00:00Z"  # after every fixture timestamp; keeps tests clock-independent


def _norm(data: dict) -> dict:
    return {
        "nodes": sorted(data["nodes"], key=lambda n: n["id"]),
        "links": sorted(
            data["links"], key=lambda e: (e["source"], e["target"], e["properties"]["kind"])
        ),
    }


def test_vendored_prov_o_is_pinned() -> None:
    assert hashlib.sha256((FIXTURES / "prov-o.ttl").read_bytes()).hexdigest() == PROV_O_SHA256


def test_roundtrip_equals_public_projection() -> None:
    g = conformant_graph()
    back = import_prov(export_prov(g, at_iso=AT))
    assert _norm(back) == _norm(public_projection(g, at_iso=AT))
    assert {n["id"] for n in back["nodes"]} == {n["id"] for n in g["nodes"]}
    assert len(back["links"]) == len(g["links"])
    assert {e["properties"]["kind"] for e in back["links"]} == {k.value for k in EdgeKind}


def test_roundtrip_through_turtle_text() -> None:
    g = conformant_graph()
    parsed = Graph().parse(data=serialize(export_prov(g, at_iso=AT)), format="turtle")
    assert _norm(import_prov(parsed)) == _norm(public_projection(g, at_iso=AT))


def test_roundtrip_preserves_values_and_types() -> None:
    back = {n["id"]: n for n in import_prov(export_prov(conformant_graph(), at_iso=AT))["nodes"]}
    assert back["de"]["residual_risk"] == 0.1 and isinstance(back["de"]["residual_risk"], float)
    assert back["ab"]["version"] == 1 and isinstance(back["ab"]["version"], int)
    assert back["ab"]["inputs"] == ["cl"] and back["pe"]["inputs"] == []
    assert back["ev"]["authenticity_status"] == "ATTESTED"
    assert back["ev"]["captured_at"] == T1


def test_imported_valid_subgraph_validates() -> None:
    # Claim/Abstraction/Decision/Policy need the never-exported vectors, so check the rest.
    g = conformant_graph()
    keep = {"ev", "in", "ac", "ag", "pe"}
    sub = {
        "nodes": [n for n in g["nodes"] if n["id"] in keep],
        "links": [e for e in g["links"] if e["source"] in keep and e["target"] in keep],
    }
    back = import_prov(export_prov(sub, at_iso=AT))
    assert back["links"], "fixture subgraph must keep at least one edge"
    assert validate_assurance_graph(back).is_valid


def test_exported_turtle_conforms_to_vendored_prov_constraints() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    shapes = Graph().parse(FIXTURES / "prov-constraints-shacl.ttl", format="turtle")
    conforms, _g, text = pyshacl.validate(data, shacl_graph=shapes, inference="none")
    assert conforms, text


def test_constraints_reject_a_bad_graph() -> None:
    # The validator must be able to fail: an Activity that is also an Entity.
    data = export_prov(conformant_graph(), at_iso=AT)
    data.add((GA["pe"], RDF.type, PROV.Entity))
    shapes = Graph().parse(FIXTURES / "prov-constraints-shacl.ttl", format="turtle")
    conforms, _g, _t = pyshacl.validate(data, shacl_graph=shapes, inference="none")
    assert not conforms


def test_exported_parses_as_json_ld() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    parsed = Graph().parse(data=serialize(data, "json-ld"), format="json-ld")
    assert len(parsed) == len(data)


def test_prov_o_ontology_loads_and_defines_terms_we_use() -> None:
    onto = Graph().parse(FIXTURES / "prov-o.ttl", format="turtle")
    for term in (
        "used", "wasGeneratedBy", "wasInvalidatedBy", "wasDerivedFrom", "wasRevisionOf",
        "wasInfluencedBy", "startedAtTime", "wasAssociatedWith", "atTime", "value",
        "Entity", "Activity", "Agent", "Influence",
    ):  # fmt: skip
        assert (PROV[term], RDF.type, None) in onto, term


def test_every_ga_term_has_a_prov_super_term() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    onto = Graph().parse(FIXTURES / "prov-o.ttl", format="turtle")
    ga = str(GA)
    ga_classes = {o for _s, _p, o in data.triples((None, RDF.type, None)) if str(o).startswith(ga)}
    ga_props = {p for _s, p, _o in data if str(p).startswith(ga)}
    assert ga_classes and ga_props
    for cls in ga_classes:
        parents = {o for o in data.objects(cls, RDFS.subClassOf) if str(o).startswith(str(PROV))}
        assert parents, f"{cls} has no prov: super-class"
        assert all((p, RDF.type, None) in onto for p in parents)
    for prop in ga_props:
        parents = {
            o for o in data.objects(prop, RDFS.subPropertyOf) if str(o).startswith(str(PROV))
        }
        assert parents, f"{prop} has no prov: super-property"
        assert all((p, RDF.type, None) in onto for p in parents)
    # and nothing redefines a prov: term
    assert not [s for s in data.subjects(RDFS.subClassOf, None) if str(s).startswith(str(PROV))]
    assert not [s for s in data.subjects(RDFS.subPropertyOf, None) if str(s).startswith(str(PROV))]


def test_class_mapping() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    assert (GA["pe"], RDF.type, PROV.Activity) in data
    assert (GA["ag"], RDF.type, PROV.Agent) in data
    for nid in ("ev", "cl", "ab", "in", "po", "de", "ac"):
        assert (GA[nid], RDF.type, PROV.Entity) in data
    assert (GA["pe"], PROV.wasAssociatedWith, GA["ag"]) in data


def test_inverted_predicates_point_the_prov_way() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    # pe GENERATED ev  ->  ev prov:wasGeneratedBy pe
    assert (GA["ev"], PROV.wasGeneratedBy, GA["pe"]) in data
    assert (GA["pe"], PROV.wasGeneratedBy, GA["ev"]) not in data
    # pe INVALIDATES cl  ->  cl prov:wasInvalidatedBy pe
    assert (GA["cl"], PROV.wasInvalidatedBy, GA["pe"]) in data
    assert (GA["pe"], PROV.wasInvalidatedBy, GA["cl"]) not in data
    # non-inverted: pe USED ev, ab DERIVED_FROM cl, cl2 SUPERSEDES cl
    assert (GA["pe"], PROV.used, GA["ev"]) in data
    assert (GA["ab"], PROV.wasDerivedFrom, GA["cl"]) in data
    assert (GA["cl2"], PROV.wasRevisionOf, GA["cl"]) in data
    # extension kinds keep ga: predicates
    assert (GA["cl"], GA["SUPPORTED_BY"], GA["ev"]) in data
    assert (GA["SUPPORTED_BY"], RDFS.subPropertyOf, PROV.wasInfluencedBy) in data


def test_qualified_relation_carries_edge_id() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    qs = list(data.subjects(RDF.type, GA.AssuranceRelation))
    assert len(qs) == len(conformant_graph()["links"])
    assert all(isinstance(q, BNode) for q in qs)
    want = edge_id("pe", "ev", "USED", SCOPE)
    assert any(str(o) == want for o in data.objects(None, GA["edgeId"]))


def test_plain_prov_triples_import_with_inferred_kind() -> None:
    data = export_prov(conformant_graph(), at_iso=AT)
    for q in list(data.subjects(RDF.type, GA.AssuranceRelation)):
        data.remove((q, None, None))
    back = import_prov(data)
    assert {e["properties"]["kind"] for e in back["links"]} == {k.value for k in EdgeKind}
    assert all(e["properties"]["strength"] == 1.0 for e in back["links"])


def test_historical_nodes_only_when_requested() -> None:
    g = conformant_graph()
    old = base(
        "old", "Agent", agent_id="old", agent_type="software", identity_assurance="IAL1",
        role="r", authorization_scope=[], valid_until="2026-08-01T00:00:00Z",
    )  # fmt: skip
    g["nodes"].append(old)
    assert (GA["old"], RDF.type, PROV.Agent) not in export_prov(g, at_iso=AT)
    assert (GA["old"], RDF.type, PROV.Agent) in export_prov(g, include_historical=True, at_iso=AT)
    retracted = copy.deepcopy(g)
    retracted["links"][0]["properties"]["retracted_at"] = "2026-09-15T00:00:00Z"
    cur = import_prov(export_prov(retracted, at_iso=AT))
    hist = import_prov(export_prov(retracted, include_historical=True, at_iso=AT))
    assert len(hist["links"]) == len(cur["links"]) + 1


def test_non_assurance_content_is_ignored() -> None:
    g = conformant_graph()
    g["nodes"].append({"id": "plain", "type": "CHUNK", "label": "x"})
    g["links"].append(
        {"source": "plain", "target": "ev", "relationship": "HAS_CHUNK", "properties": {}}
    )
    g["links"].append(link("plain", "ev", "NOT_A_KIND"))
    want = _norm(public_projection(conformant_graph(), at_iso=AT))
    assert _norm(import_prov(export_prov(g, at_iso=AT))) == want


def test_odd_node_ids_survive() -> None:
    node = base(
        "a b/c#1", "Agent", agent_id="x", agent_type="t", identity_assurance="IAL1",
        role="r", authorization_scope=[],
    )  # fmt: skip
    back = import_prov(export_prov({"nodes": [node], "links": []}, at_iso=AT))
    assert back["nodes"][0]["id"] == "a b/c#1"


def test_base_iri_is_configurable_and_never_prov() -> None:
    other = "urn:example:assurance:"
    data = export_prov(conformant_graph(), at_iso=AT, base_iri=other)
    assert (URIRef(other + "pe"), RDF.type, PROV.Activity) in data
    assert not any(str(s).startswith(DEFAULT_BASE_IRI) for s in data.subjects())
    want = _norm(public_projection(conformant_graph(), at_iso=AT))
    assert _norm(import_prov(data, base_iri=other)) == want
    for bad in ("", "  ", "http://www.w3.org/ns/prov#", "http://www.w3.org/ns/prov#x:"):
        with pytest.raises(ProvExportError):
            export_prov(conformant_graph(), base_iri=bad)


def test_fail_closed_on_malformed_input() -> None:
    bad_node = {"nodes": [{"id": "x", "assurance_type": "Claim"}], "links": []}  # no valid_from
    with pytest.raises(ProvExportError):
        export_prov(bad_node, at_iso=AT)
    unknown = {
        "nodes": [{"id": "x", "assurance_type": "Nope", "valid_from": T0, "asserted_at": T1}],
        "links": [],
    }
    with pytest.raises(ProvExportError):
        export_prov(unknown, at_iso=AT)
    g = conformant_graph()
    g["links"].append(
        {"source": "cl", "target": "ev", "relationship": "RELATES_TO",
         "properties": {"kind": "SUPPORTED_BY"}}  # no scope_key
    )  # fmt: skip
    with pytest.raises(ProvExportError):
        export_prov(g, at_iso=AT)
    with pytest.raises(ProvExportError):
        export_prov(conformant_graph(), at_iso="not-a-time")


def test_import_refuses_subjects_outside_the_namespace() -> None:
    foreign = Graph()
    foreign.add((URIRef("urn:other:x"), RDF.type, GA["Agent"]))
    with pytest.raises(ProvExportError):
        import_prov(foreign)
