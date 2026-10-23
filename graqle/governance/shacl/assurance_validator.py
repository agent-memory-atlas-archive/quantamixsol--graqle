"""SHACL validation of the assurance graph (CR-016 section 5.6, PR-016d).

The data graph is the PROV-O export of the assurance subgraph
(:func:`graqle.ontology.prov_export.export_prov`); the shapes are the packaged
``graqle/ontology/shapes/assurance.ttl``.

Independence guarantee: this module never loads the R22 ``shapes.ttl`` and never
calls ``_trace_to_rdf``; ``check_output_gate`` never loads ``assurance.ttl``. It
reuses :meth:`ShaclValidator.validate_graph` (parse, hash, ``inference="none"``)
and fails closed: any error becomes a non-conforming result carrying a synthetic
``ga:ValidatorError`` violation.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.governance.shacl.assurance_validator
# risk: LOW (impact radius: 0 existing callers -- new module, never invoked by default)
# dependencies: graqle.governance.shacl.validator, graqle.ontology.prov_export, pyshacl (lazy)
# constraints: no R22 shapes, no _trace_to_rdf; fail closed on any exception
# -- /graqle:intelligence --
import importlib.resources
from collections.abc import Collection, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rdflib import URIRef

try:
    import pyshacl as _pyshacl  # noqa: F401

    _SHACL_AVAILABLE = True
except ImportError:
    _SHACL_AVAILABLE = False

from graqle.governance.shacl.output_gate import ShaclGateResult
from graqle.governance.shacl.validator import (
    ShaclValidationResult,
    ShaclValidator,
    ViolationDetail,
)
from graqle.ontology.prov_export import PROV_NS, export_prov

__all__ = ["AssuranceShaclValidator", "check_assurance_gate"]

_VALIDATOR_ERROR = "ga:ValidatorError"
_SET_META = URIRef("urn:graqle:assurance:ShapeSetMetadata")
_SET_VERSION = URIRef("urn:graqle:assurance:shapeSetVersion")


def _packaged_shapes() -> Path:
    return Path(str(importlib.resources.files("graqle.ontology.shapes") / "assurance.ttl"))


def _restrict(g: Any, node_ids: Collection[str], base_iri: str) -> Any:
    """Subgraph of ``g`` around ``node_ids``.

    Keeps every triple whose subject is a requested node or is a direct
    neighbour of one (so a Claim's SUPPORTED_BY Evidence stays visible), plus
    the qualified ``ga:AssuranceRelation`` forms that touch a requested node.
    Neighbours are context, but they are validated too, so this can only add
    violations, never hide one.
    """
    from urllib.parse import quote

    import rdflib

    ga = rdflib.Namespace(base_iri)
    focus = {rdflib.URIRef(ga[quote(i, safe="")]) for i in node_ids}
    relations = {
        q
        for q in g.subjects(rdflib.RDF.type, ga.AssuranceRelation)
        if (q, ga.edgeSource, None) in g
        and (
            any(s in focus for s in g.objects(q, ga.edgeSource))
            or any(t in focus for t in g.objects(q, ga.edgeTarget))
        )
    }
    keep = set(focus)
    for s, _, o in g:
        if isinstance(o, rdflib.URIRef) and not str(o).startswith(PROV_NS):
            if s in focus:
                keep.add(o)
            elif o in focus and isinstance(s, rdflib.URIRef):
                keep.add(s)
    out = rdflib.Graph()
    for prefix, ns in g.namespaces():
        out.bind(prefix, ns)
    for s, p, o in g:
        if s in keep or s in relations:
            out.add((s, p, o))
    return out


class AssuranceShaclValidator:
    """Validate the assurance subgraph against the packaged ``assurance.ttl``."""

    def __init__(self, shapes_path: Path | None = None) -> None:
        self._inner = ShaclValidator(shapes_path=shapes_path or _packaged_shapes())
        # ShaclValidator reads the version from the R22 namespace; ours lives in ga:.
        self._shape_set_version = "unknown"
        for _, _, v in self._inner._shapes_graph.triples((_SET_META, _SET_VERSION, None)):
            self._shape_set_version = str(v)
            break

    @property
    def shapes_file_hash(self) -> str:
        return self._inner.shapes_file_hash

    def validate_subgraph(
        self,
        source: Mapping[str, Any],
        node_ids: list[str] | None = None,
        *,
        include_historical: bool = True,
        base_iri: str = "urn:graqle:assurance:",
    ) -> ShaclValidationResult:
        """Export ``source`` (``graph_data``) and validate it. Never raises (fail closed)."""
        try:
            g = export_prov(source, include_historical=include_historical, base_iri=base_iri)
            if node_ids is not None:
                g = _restrict(g, node_ids, base_iri)
            result = self._inner.validate_graph(g)
            result.shape_set_version = self._shape_set_version
            return result
        except Exception as exc:  # noqa: BLE001 - fail closed: any error is non-conformance
            return ShaclValidationResult(
                conforms=False,
                violations=[
                    ViolationDetail(_VALIDATOR_ERROR, "", f"{type(exc).__name__}: {exc}"[:200])
                ],
            )


def check_assurance_gate(
    source: Mapping[str, Any],
    node_ids: list[str] | None,
    validator: AssuranceShaclValidator,
) -> ShaclGateResult:
    """Fail-closed gate over :meth:`AssuranceShaclValidator.validate_subgraph`.

    Mirrors ``output_gate.check_output_gate``: raises ImportError without
    pyshacl, otherwise any violation blocks.
    """
    if not _SHACL_AVAILABLE:
        raise ImportError("assurance SHACL gate requires pyshacl: pip install 'graqle[api]'")
    result = validator.validate_subgraph(source, node_ids)
    if not result.conforms:
        return ShaclGateResult(
            passed=False, report=result, blocked_at=datetime.now(timezone.utc).isoformat()
        )
    return ShaclGateResult(passed=True, report=result, blocked_at=None)
