"""DAG-2026 assurance write operations (CR-016 §5.3, PR-016b).

An :class:`AssuranceOp` is a validated description of ONE assurance write. It
carries no Cypher. The only code that turns ops into database writes is the
private module ``graqle.governance.tamper_evidence._assurance_write``, reached
only through :meth:`Neo4jBatchPersister.persist_assurance_ops`.

Four shapes exist, and nothing else can be expressed:

* ``create_node``: a new assurance node, validated by its pydantic model. The
  write-once fields (:data:`WRITE_ONCE_NODE_FIELDS`) are set on create only;
  an existing node with different values is REFUSED, never overwritten.
* ``set_if_absent``: the migration's field-by-field ``coalesce`` write onto an
  existing substrate node. It can only fill a field that is empty.
* ``create_edge``: an assurance ``RELATES_TO {kind}`` edge, validated by
  :class:`~graqle.ontology.assurance.AssuranceEdge`. SUPERSEDES and CORRECTS
  get the ordering rule (d), the canonical-id rule (c) and the cardinality
  properties inside the write transaction.
* ``resign_node`` / ``resign_edge``: re-stamp an integrity digest under the
  current key during a key rotation, only after the old digest verifies.

The callers never supply cardinality properties or digests.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.assurance_ops
# risk: LOW (impact radius: 0 existing callers -- PR-016b write path, CR-017/018 consume it)
# dependencies: graqle.ontology.assurance
# constraints: no Cypher here; ops are data only
# -- /graqle:intelligence --
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from graqle.ontology.assurance import (
    CLASS_TO_TYPE_KEY,
    MODEL_FOR_CLASS,
    AssuranceClass,
    AssuranceEdge,
    AssuranceNodeBase,
    EdgeKind,
    _check_iso_utc,
)

__all__ = [
    "ORDERED_EDGE_KINDS",
    "RESERVED_PROPS",
    "SET_IF_ABSENT_FIELDS",
    "WRITE_ONCE_NODE_FIELDS",
    "AssuranceOp",
    "OpKind",
]

OpKind = Literal["create_node", "set_if_absent", "create_edge", "resign_node", "resign_edge"]

#: Edge kinds that carry the ordering rule (d) and the DB cardinality properties.
ORDERED_EDGE_KINDS: frozenset[EdgeKind] = frozenset({EdgeKind.SUPERSEDES, EdgeKind.CORRECTS})

#: Fields an SDK write can never change once a node has them (Research ruling 9).
WRITE_ONCE_NODE_FIELDS: tuple[str, ...] = (
    "assurance_type",
    "canonical_id",
    "scope_key",
    "valid_from",
    "asserted_at",
)

#: The only fields the migration's ``set_if_absent`` may fill (CR-016 §5.3).
SET_IF_ABSENT_FIELDS: tuple[str, ...] = (
    "assurance_type",
    "lifecycle_status",
    "valid_from",
    "asserted_at",
    "prov_event_id",
    "schema_version",
)

#: Properties only the write path sets; any caller-supplied value is rejected.
RESERVED_PROPS: frozenset[str] = frozenset(
    {
        "integrity_digest",
        "integrity_hmac_version",
        "supersedes_in",
        "supersedes_out",
        "corrects_in",
        "corrects_out",
        "assurance_filled_fields",
    }
)

_TIMESTAMP_FIELDS = frozenset({"valid_from", "asserted_at"})


def _json_value(v: Any) -> Any:
    return v.value if hasattr(v, "value") and not isinstance(v, (str, bytes)) else v


def _flat(props: Mapping[str, Any]) -> dict[str, Any]:
    """Neo4j stores primitives and lists of primitives; nothing else passes."""
    out: dict[str, Any] = {}
    for k, v in props.items():
        v = _json_value(v)
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, (list, tuple)) and all(
            isinstance(x, (str, int, float, bool)) for x in v
        ):
            out[k] = list(v)
        else:
            raise ValueError(f"property {k!r} is not a Neo4j primitive or list of primitives")
    return out


@dataclass(frozen=True)
class AssuranceOp:
    """One validated assurance write. Build it with the classmethods, never directly."""

    kind: OpKind
    node_id: str | None = None
    props: Mapping[str, Any] = field(default_factory=dict)
    source_id: str | None = None
    target_id: str | None = None
    edge_kind: EdgeKind | None = None
    edge_id: str | None = None

    # ── constructors ─────────────────────────────────────────────────────

    @classmethod
    def create_node(cls, node: AssuranceNodeBase | Mapping[str, Any]) -> AssuranceOp:
        """A new assurance node. Validated by its class model (``extra="forbid"``)."""
        if isinstance(node, AssuranceNodeBase):
            model = node
        else:
            try:
                klass = AssuranceClass(node.get("assurance_type"))
            except ValueError as exc:
                raise ValueError("create_node needs a known assurance_type") from exc
            model = MODEL_FOR_CLASS[klass].model_validate(dict(node))
        props = _flat(model.model_dump(mode="json", exclude_none=True))
        cls_value = props["assurance_type"]
        # Substrate fields the loader reads; never part of the write-once set.
        props.setdefault("label", model.id)
        props.setdefault("entity_type", CLASS_TO_TYPE_KEY[AssuranceClass(cls_value)])
        props.pop("type", None)
        return cls(kind="create_node", node_id=model.id, props=props)

    @classmethod
    def set_if_absent(cls, node_id: str, props: Mapping[str, Any]) -> AssuranceOp:
        """Fill empty assurance fields on an existing node (migration only)."""
        if not node_id:
            raise ValueError("set_if_absent needs a node id")
        unknown = sorted(set(props) - set(SET_IF_ABSENT_FIELDS))
        if unknown:
            raise ValueError(f"set_if_absent cannot write {unknown}")
        clean = _flat(props)
        if "assurance_type" in clean:
            AssuranceClass(clean["assurance_type"])  # ValueError on an unknown class
        for f in _TIMESTAMP_FIELDS & set(clean):
            _check_iso_utc(clean[f])
        return cls(kind="set_if_absent", node_id=node_id, props=clean)

    @classmethod
    def create_edge(cls, edge: AssuranceEdge | Mapping[str, Any]) -> AssuranceOp:
        """An assurance ``RELATES_TO {kind}`` edge, validated by :class:`AssuranceEdge`."""
        model = (
            edge if isinstance(edge, AssuranceEdge) else AssuranceEdge.model_validate(dict(edge))
        )
        props = _flat(model.model_dump(mode="json", exclude_none=True))
        for k in ("id", "source_id", "target_id"):
            props.pop(k)
        return cls(
            kind="create_edge",
            source_id=model.source_id,
            target_id=model.target_id,
            edge_kind=model.kind,
            edge_id=model.id,
            props=props,
        )

    @classmethod
    def resign_node(cls, node_id: str) -> AssuranceOp:
        """Re-stamp a node digest under the current key, after the old one verifies."""
        if not node_id:
            raise ValueError("resign_node needs a node id")
        return cls(kind="resign_node", node_id=node_id)

    @classmethod
    def resign_edge(cls, edge_id: str) -> AssuranceOp:
        """Re-stamp an edge digest under the current key, after the old one verifies."""
        if not edge_id:
            raise ValueError("resign_edge needs an edge id")
        return cls(kind="resign_edge", edge_id=edge_id)

    def __post_init__(self) -> None:
        clash = sorted(RESERVED_PROPS & set(self.props))
        if clash:
            raise ValueError(f"reserved properties are set by the write path only: {clash}")
