# ruff: noqa: N806  -- rdflib is imported lazily, so its CamelCase names are function locals
"""PROV-O export / import for the assurance ontology (CR-016 §2.5, §5.5, PR-016c).

The mapping is a homomorphism onto W3C PROV-O: ``ProvenanceEvent`` is a
``prov:Activity``, ``Agent`` a ``prov:Agent``, every other class a
``prov:Entity``. Edge kinds with a PROV equivalent use it directly (inverting
the direction where PROV points the other way); the rest become
``ga:<KIND>`` properties declared ``rdfs:subPropertyOf prov:wasInfluencedBy``.
Every edge also gets a qualified ``ga:AssuranceRelation`` (a ``prov:Influence``)
carrying its id and metadata so :func:`import_prov` is lossless.

PROV-O terms are never redefined: every ``ga:`` class and property this module
emits is declared ``rdfs:subClassOf`` / ``rdfs:subPropertyOf`` a ``prov:`` term.

Never exported (CR-016 §5.5, AC-10): ``confidence_vector_json``,
``score_vector_json`` and ``conditions`` (only their version strings, which are
ordinary properties, are exported). Because of that exclusion a re-imported
graph does not carry those three properties; round-trip identity is defined on
:func:`public_projection`, which applies the same exclusion to the source.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.prov_export
# risk: LOW (impact radius: 0 existing callers -- new module, never invoked by default)
# dependencies: rdflib (lazy), graqle.ontology.assurance
# constraints: no weights/vectors in RDF; base IRI configurable but never inside the prov: namespace
# -- /graqle:intelligence --
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, unquote

from graqle.core.exceptions import GraqleError
from graqle.ontology.assurance import (
    AssuranceClass,
    EdgeKind,
    _check_iso_utc,
    _parse_iso_utc,
    covers,
    edge_id,
    to_iso_utc,
)

if TYPE_CHECKING:  # pragma: no cover
    from rdflib import Graph

__all__ = [
    "DEFAULT_BASE_IRI",
    "NEVER_EXPORTED",
    "ProvExportError",
    "export_prov",
    "import_prov",
    "public_projection",
    "serialize",
]

PROV_NS = "http://www.w3.org/ns/prov#"
#: Public namespace for GraQle terms (CR-016 §2.5). Configurable per call.
DEFAULT_BASE_IRI = "urn:graqle:assurance:"

#: Secret scoring payloads: never written to RDF.
NEVER_EXPORTED = frozenset({"confidence_vector_json", "score_vector_json", "conditions"})

#: Node keys that are structure, not exported as plain properties.
_STRUCTURAL = frozenset({"id", "assurance_type"})
_TEMPORAL = frozenset(
    {"valid_from", "valid_until", "asserted_at", "retracted_at", "captured_at", "timestamp"}
)
_EDGE_FIELDS = (
    "scope_key",
    "asserted_at",
    "retracted_at",
    "prov_event_id",
    "contradiction_id",
    "resolution_status",
    "resolution_event_id",
)

#: kind -> (prov predicate local name, inverted)
_DIRECT: dict[str, tuple[str, bool]] = {
    "USED": ("used", False),
    "GENERATED": ("wasGeneratedBy", True),
    "DERIVED_FROM": ("wasDerivedFrom", False),
    "SUPERSEDES": ("wasRevisionOf", False),
    "INVALIDATES": ("wasInvalidatedBy", True),
}
_EXTENSION = frozenset({"SUPPORTED_BY", "CONTRADICTS", "CORRECTS", "COEXISTS_WITH", "GOVERNED_BY"})
_CLASS_MAP = {"ProvenanceEvent": "Activity", "Agent": "Agent"}  # all others -> Entity
_INVERSE_DIRECT = {local: (kind, inv) for kind, (local, inv) in _DIRECT.items()}


class ProvExportError(GraqleError):
    """Export/import refused (fail closed): malformed assurance data or unusable IRI base."""


def _rdflib() -> Any:
    try:
        import rdflib
    except ImportError as exc:  # pragma: no cover - rdflib ships with the [api] extras
        raise ProvExportError("PROV-O export needs rdflib (install graqle[api])") from exc
    return rdflib


def _check_base(base_iri: str) -> str:
    if not isinstance(base_iri, str) or not base_iri.strip():
        raise ProvExportError("base_iri must be a non-empty string")
    if base_iri.startswith(PROV_NS) or PROV_NS.startswith(base_iri):
        raise ProvExportError("base_iri must not overlap the prov: namespace")
    return base_iri


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or (
        isinstance(value, list) and all(isinstance(v, str) for v in value)
    )


def _node_props(node: Mapping[str, Any]) -> dict[str, Any]:
    """Exportable properties of a node: no structure, no secrets, no None, scalar/str-list only."""
    return {
        k: v
        for k, v in node.items()
        if k not in _STRUCTURAL and k not in NEVER_EXPORTED and v is not None and _scalar(v)
    }


def _edge_of(link: Mapping[str, Any]) -> dict[str, Any] | None:
    """Normalise one assurance link, or ``None`` if it is not an assurance edge."""
    if link.get("relationship") != "RELATES_TO":
        return None
    props = link.get("properties") or {}
    try:
        kind = EdgeKind(props.get("kind"))
    except ValueError:
        return None
    src, tgt = link.get("source"), link.get("target")
    if (
        not isinstance(src, str)
        or not isinstance(tgt, str)
        or not props.get("scope_key")
        or not isinstance(props.get("asserted_at"), str)
    ):
        raise ProvExportError(f"{kind.value} edge needs string endpoints, scope_key, asserted_at")
    out: dict[str, Any] = {
        "source": src,
        "target": tgt,
        "kind": kind.value,
        "id": props.get("id") or edge_id(src, tgt, kind, props["scope_key"]),
        "strength": float(props.get("strength", 1.0)),
    }
    out.update({f: props[f] for f in _EDGE_FIELDS if props.get(f) is not None})
    return out


def _select(
    source: Mapping[str, Any], include_historical: bool, at_iso: str | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The assurance subgraph (``assurance_type`` present), current at ``at`` unless historical."""
    try:
        at = _parse_iso_utc(_check_iso_utc(at_iso)) if at_iso else datetime.now(timezone.utc)
    except ValueError as exc:
        raise ProvExportError(f"at_iso: {exc}") from None
    at_s = at.strftime("%Y-%m-%dT%H:%M:%SZ")
    nodes: dict[str, dict[str, Any]] = {}
    for n in source.get("nodes", []):
        if n.get("assurance_type") is None:
            continue
        try:
            AssuranceClass(n["assurance_type"])
            if not isinstance(n["id"], str):
                raise TypeError("node id must be a string")
            current = include_historical or covers(n, at)
        except (KeyError, ValueError, TypeError) as exc:
            raise ProvExportError(f"malformed assurance node {n.get('id')!r}: {exc}") from None
        if current:
            nodes[n["id"]] = dict(n)
    edges: list[dict[str, Any]] = []
    for link in source.get("links", []):
        e = _edge_of(link)
        if e is None or e["source"] not in nodes or e["target"] not in nodes:
            continue
        retracted = e.get("retracted_at")
        ended = bool(retracted) and retracted <= at_s
        if not include_historical and (e["asserted_at"] > at_s or ended):
            continue
        edges.append(e)
    return (
        sorted(nodes.values(), key=lambda n: n["id"]),
        sorted(edges, key=lambda e: (e["source"], e["target"], e["kind"])),
    )


def public_projection(
    source: Mapping[str, Any], *, include_historical: bool = False, at_iso: str | None = None
) -> dict[str, Any]:
    """``graph_data`` restricted to exactly what :func:`export_prov` carries.

    ``import_prov(export_prov(G)) == public_projection(G)`` (AC-9).
    """
    nodes, edges = _select(source, include_historical, at_iso)
    out_nodes = [
        {"id": n["id"], "assurance_type": n["assurance_type"], **_node_props(n)} for n in nodes
    ]
    links = [_link_of(e) for e in edges]
    return {"nodes": out_nodes, "links": links}


def _link_of(e: Mapping[str, Any]) -> dict[str, Any]:
    props = {k: v for k, v in e.items() if k not in ("source", "target")}
    return {
        "source": e["source"],
        "target": e["target"],
        "relationship": "RELATES_TO",
        "properties": props,
    }


def _literal(rdflib: Any, name: str, value: Any) -> Any:
    L, XSD, RDF = rdflib.Literal, rdflib.XSD, rdflib.RDF
    if name in _TEMPORAL:
        return L(value, datatype=XSD.dateTime)
    if isinstance(value, bool):
        return L(value, datatype=XSD.boolean)
    if isinstance(value, int):
        return L(value, datatype=XSD.integer)
    if isinstance(value, float):
        return L(value, datatype=XSD.double)
    if isinstance(value, list):
        return L(json.dumps(value), datatype=RDF.JSON)
    return L(value)


def _from_literal(rdflib: Any, lit: Any) -> Any:
    XSD, RDF = rdflib.XSD, rdflib.RDF
    dt = lit.datatype
    if dt == RDF.JSON:
        return json.loads(str(lit))
    if dt == XSD.dateTime:  # rdflib normalises the lexical form; restore the canonical width
        value = lit.toPython()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ProvExportError(f"timestamp {str(lit)!r} is not an aware xsd:dateTime")
        return to_iso_utc(value)
    if dt == XSD.boolean:
        return str(lit).strip().lower() in ("true", "1")
    if dt == XSD.integer:
        return int(str(lit))
    if dt == XSD.double:
        return float(str(lit))
    return str(lit)  # strings and xsd:dateTime keep their canonical lexical form


def export_prov(
    source: Mapping[str, Any],
    *,
    include_historical: bool = False,
    at_iso: str | None = None,
    base_iri: str = DEFAULT_BASE_IRI,
) -> Graph:
    """Export the assurance subgraph of ``source`` (``graph_data``) as a PROV-O graph."""
    rdflib = _rdflib()
    RDF, RDFS, XSD, BNode, Literal, URIRef = (
        rdflib.RDF,
        rdflib.RDFS,
        rdflib.XSD,
        rdflib.BNode,
        rdflib.Literal,
        rdflib.URIRef,
    )
    PROV = rdflib.Namespace(PROV_NS)
    GA = rdflib.Namespace(_check_base(base_iri))
    nodes, edges = _select(source, include_historical, at_iso)

    def iri(node_id: str) -> Any:
        return URIRef(GA[quote(node_id, safe="")])

    g = rdflib.Graph()
    g.bind("prov", PROV)
    g.bind("ga", GA)
    props: dict[str, Any] = {}  # ga property local name -> prov super-property

    def declare(name: str, parent: Any) -> Any:
        props.setdefault(name, parent)
        return GA[name]

    def declare_attr(name: str) -> Any:
        return declare(name, PROV.atTime if name in _TEMPORAL else PROV.value)

    ids = {n["id"] for n in nodes}
    for n in nodes:
        u, cls = iri(n["id"]), n["assurance_type"]
        g.add((u, RDF.type, PROV[_CLASS_MAP.get(cls, "Entity")]))
        g.add((u, RDF.type, GA[cls]))
        for name, value in _node_props(n).items():
            g.add((u, declare_attr(name), _literal(rdflib, name, value)))
        if cls == "ProvenanceEvent":
            if isinstance(n.get("timestamp"), str):
                g.add((u, PROV.startedAtTime, Literal(n["timestamp"], datatype=XSD.dateTime)))
            if n.get("actor") in ids:
                g.add((u, PROV.wasAssociatedWith, iri(n["actor"])))
            if n.get("prior_event") in ids:
                g.add((u, declare("priorEvent", PROV.wasInfluencedBy), iri(n["prior_event"])))

    for e in edges:
        s, t = iri(e["source"]), iri(e["target"])
        if e["kind"] in _DIRECT:
            local, invert = _DIRECT[e["kind"]]
            g.add((t, PROV[local], s) if invert else (s, PROV[local], t))
        else:
            g.add((s, declare(e["kind"], PROV.wasInfluencedBy), t))
        q = BNode()  # qualified form carries the edge metadata for a lossless round-trip
        g.add((q, RDF.type, GA.AssuranceRelation))
        g.add((q, declare_attr("edgeId"), Literal(e["id"])))
        g.add((q, declare_attr("edgeKind"), Literal(e["kind"])))
        g.add((q, declare("edgeSource", PROV.wasInfluencedBy), s))
        g.add((q, declare("edgeTarget", PROV.wasInfluencedBy), t))
        g.add((q, declare_attr("strength"), Literal(e["strength"], datatype=XSD.double)))
        for f in _EDGE_FIELDS:
            if f in e:
                g.add((q, declare_attr(f), _literal(rdflib, f, e[f])))

    # vocabulary: every ga: term is a sub-term of a prov: term, never a redefinition
    for cls in AssuranceClass:
        g.add((GA[cls.value], RDFS.subClassOf, PROV[_CLASS_MAP.get(cls.value, "Entity")]))
    g.add((GA.AssuranceRelation, RDFS.subClassOf, PROV.Influence))
    for name, parent in sorted(props.items()):
        g.add((GA[name], RDFS.subPropertyOf, parent))
    return g


def import_prov(g: Graph, *, base_iri: str = DEFAULT_BASE_IRI) -> dict[str, Any]:
    """Rebuild ``graph_data`` from ``ga:``-typed nodes and ``ga:AssuranceRelation`` forms.

    Plain PROV triples with no qualified form are imported with the kind
    inferred from the inverse mapping; ``strength`` defaults to 1.0 and
    ``scope_key``/``asserted_at`` come from the source node, so downstream
    validation (``validate_assurance_graph``) flags any that lack required
    metadata rather than this function inventing it.
    """
    rdflib = _rdflib()
    RDF, URIRef, Literal = rdflib.RDF, rdflib.URIRef, rdflib.Literal
    PROV = rdflib.Namespace(PROV_NS)
    GA = rdflib.Namespace(_check_base(base_iri))
    prefix = str(GA)

    def node_id(u: Any) -> str:
        if not isinstance(u, URIRef) or not str(u).startswith(prefix):
            raise ProvExportError(f"IRI {u} is outside the assurance namespace")
        return unquote(str(u)[len(prefix) :])

    def local(p: Any) -> str | None:
        return str(p)[len(prefix) :] if str(p).startswith(prefix) else None

    nodes: dict[str, dict[str, Any]] = {}
    for cls in AssuranceClass:
        for u in g.subjects(RDF.type, GA[cls.value]):
            n: dict[str, Any] = {"id": node_id(u), "assurance_type": cls.value}
            for p, o in g.predicate_objects(u):
                name = local(p)
                if name is not None and isinstance(o, Literal):
                    n[name] = _from_literal(rdflib, o)
            nodes[n["id"]] = n

    links: dict[tuple[str, str, str], dict[str, Any]] = {}
    for q in g.subjects(RDF.type, GA.AssuranceRelation):
        d: dict[str, Any] = {}
        for p, o in g.predicate_objects(q):
            name = local(p)
            if name is not None and isinstance(o, Literal):
                d[name] = _from_literal(rdflib, o)
        src, tgt = g.value(q, GA.edgeSource), g.value(q, GA.edgeTarget)
        try:
            kind = EdgeKind(d["edgeKind"]).value
            edge = {
                "id": d.pop("edgeId"),
                "kind": kind,
                "strength": d.pop("strength"),
                **{k: v for k, v in d.items() if k in _EDGE_FIELDS},
            }
        except (KeyError, ValueError):
            raise ProvExportError("malformed ga:AssuranceRelation") from None
        links[(node_id(src), node_id(tgt), kind)] = edge

    # plain PROV triples that have no qualified form
    def plain(s: Any, t: Any, kind: str) -> None:
        key = (node_id(s), node_id(t), kind)
        if key in links or key[0] not in nodes or key[1] not in nodes:
            return
        src = nodes[key[0]]
        edge: dict[str, Any] = {"kind": kind, "strength": 1.0}
        for f in ("scope_key", "asserted_at"):
            if f in src:
                edge[f] = src[f]
        if "scope_key" in edge:
            edge["id"] = edge_id(key[0], key[1], kind, edge["scope_key"])
        links[key] = edge

    for kind, (name, invert) in _DIRECT.items():
        for a, b in g.subject_objects(PROV[name]):
            plain(*((b, a) if invert else (a, b)), kind)
    for kind in _EXTENSION:
        for a, b in g.subject_objects(GA[kind]):
            plain(a, b, kind)

    out_links = [
        {
            "source": s,
            "target": t,
            "relationship": "RELATES_TO",
            "properties": {k: v for k, v in e.items()},
        }
        for (s, t, _k), e in sorted(links.items())
    ]
    return {"nodes": [nodes[k] for k in sorted(nodes)], "links": out_links}


def serialize(g: Graph, fmt: str = "turtle") -> bytes:
    """Serialise ``g`` (``turtle``, ``json-ld``, ...) as UTF-8 bytes."""
    out = g.serialize(format=fmt, encoding="utf-8")
    return out if isinstance(out, bytes) else str(out).encode("utf-8")
