"""PRIVATE: the one module that writes assurance fields and ordered edges (CR-016 PR-016b).

Reached ONLY through :meth:`Neo4jBatchPersister.persist_assurance_ops` and
:meth:`Neo4jBatchPersister.rollback_assurance_migration`. The AST gate
``scripts/ci/assurance_write_path_gate.py`` fails CI if any other module under
``graqle/`` carries Cypher that creates SUPERSEDES/CORRECTS edges or writes
``valid_from`` / ``asserted_at``, or if anything but ``kg_persist`` imports this
module.

Every call is ONE ``session.execute_write``: the ops of a batch land together or
not at all. Refusals raise :class:`AssuranceWriteRefusedError` inside the transaction,
so the transaction rolls back.

Enforcement, by rule (Research ruling 2026-09-28):

* (a) unique ``(canonical_id, scope_key, valid_from)``: DB composite constraint.
* (b) at most one SUPERSEDES/CORRECTS in and out per node: the four cardinality
  properties are set HERE, inside the CREATE, from the endpoint ids, and the DB
  relationship-property uniqueness constraints reject a second one. A race of
  concurrent writers therefore commits exactly one.
* (c) ``canonical_id`` on both participants: checked here, in the transaction.
* (d) ``(asserted_at, valid_from)`` strictly decreases along the edge, and
  SUPERSEDES needs ``source.valid_from > target.valid_from``: checked here. The
  endpoint values are write-once through this path, so the check cannot race
  with another SDK writer.
* write-once: ``create_node`` refuses an existing node whose write-once fields
  differ; ``set_if_absent`` can only fill empty fields.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.governance.tamper_evidence._assurance_write
# risk: MEDIUM (impact radius: 1 -- only kg_persist.Neo4jBatchPersister imports it)
# dependencies: graqle.ontology.{assurance_ops,assurance_integrity}
# constraints: private; single execute_write per call; static Cypher only (labels and
#   property names come from code constants, never from input)
# -- /graqle:intelligence --
from collections.abc import Callable, Sequence
from typing import Any

from graqle.governance.tamper_evidence.kg_persist import AssuranceWriteRefusedError
from graqle.ontology.assurance_integrity import (
    IntegrityKeyring,
    edge_digest,
    node_digest,
    ordering_violation,
    verify_digest,
)
from graqle.ontology.assurance_ops import (
    ORDERED_EDGE_KINDS,
    SET_IF_ABSENT_FIELDS,
    WRITE_ONCE_NODE_FIELDS,
    AssuranceOp,
)

_NODE_RETURN = (
    "RETURN n.id AS id, n.assurance_type AS assurance_type, n.canonical_id AS canonical_id, "
    "n.scope_key AS scope_key, n.valid_from AS valid_from, n.asserted_at AS asserted_at, "
    "n.integrity_digest AS digest, n.integrity_hmac_version AS version"
)

_Q_CREATE_NODE = (
    "MERGE (n:CogniNode {id: $id}) "
    "ON CREATE SET n += $props, n.integrity_digest = $digest, n.integrity_hmac_version = $version "
    + _NODE_RETURN
)

# Record which fields the op filled BEFORE filling them (SET items apply in order),
# so a migration rollback removes exactly those and nothing a node already had.
_Q_SET_IF_ABSENT = (
    "MATCH (n:CogniNode {id: $id}) "
    "SET n.assurance_filled_fields = coalesce(n.assurance_filled_fields, []) + "
    "[f IN $fields WHERE n[f] IS NULL AND $p[f] IS NOT NULL], "
    + ", ".join(f"n.{f} = coalesce(n.{f}, $p.{f})" for f in SET_IF_ABSENT_FIELDS)
    + " "
    + _NODE_RETURN
)

_Q_SET_NODE_DIGEST = (
    "MATCH (n:CogniNode {id: $id}) "
    "SET n.integrity_digest = $digest, n.integrity_hmac_version = $version"
)

_Q_ENDPOINTS = (
    "MATCH (a:CogniNode {id: $s}) MATCH (b:CogniNode {id: $t}) "
    "RETURN a.canonical_id AS a_canonical_id, a.asserted_at AS a_asserted_at, "
    "a.valid_from AS a_valid_from, "
    "b.canonical_id AS b_canonical_id, b.asserted_at AS b_asserted_at, b.valid_from AS b_valid_from"
)

_EDGE_MERGE = (
    "MATCH (a:CogniNode {id: $s}) MATCH (b:CogniNode {id: $t}) "
    "MERGE (a)-[r:RELATES_TO {id: $eid}]->(b) "
    "ON CREATE SET r += $props, r.integrity_digest = $digest, r.integrity_hmac_version = $version"
)
_EDGE_RETURN = (
    " RETURN r.kind AS kind, r.scope_key AS scope_key, r.asserted_at AS asserted_at, "
    "r.prov_event_id AS prov_event_id"
)
#: Static per kind: property names cannot be parameters. The caller never
#: supplies these four; they are always the endpoint ids.
_Q_CREATE_EDGE: dict[str, str] = {
    "SUPERSEDES": _EDGE_MERGE + ", r.supersedes_in = b.id, r.supersedes_out = a.id" + _EDGE_RETURN,
    "CORRECTS": _EDGE_MERGE + ", r.corrects_in = b.id, r.corrects_out = a.id" + _EDGE_RETURN,
    "*": _EDGE_MERGE + _EDGE_RETURN,
}

_Q_EDGE_READ = (
    "MATCH (a:CogniNode)-[r:RELATES_TO {id: $eid}]->(b:CogniNode) "
    "RETURN a.id AS source_id, b.id AS target_id, r.kind AS kind, r.scope_key AS scope_key, "
    "r.prov_event_id AS prov_event_id, r.asserted_at AS asserted_at, "
    "r.integrity_digest AS digest, r.integrity_hmac_version AS version"
)
_Q_SET_EDGE_DIGEST = (
    "MATCH ()-[r:RELATES_TO {id: $eid}]->() "
    "SET r.integrity_digest = $digest, r.integrity_hmac_version = $version"
)

# Migration rollback: only nodes a MIGRATION event GENERATED and still points at,
# and only the fields that event filled.
_Q_ROLLBACK_NODES = (
    "MATCH (ev:CogniNode {assurance_type: 'ProvenanceEvent', event_type: 'MIGRATION'})"
    "-[:RELATES_TO {kind: 'GENERATED'}]->(n:CogniNode) "
    "WHERE n.prov_event_id = ev.id "
    "WITH DISTINCT n, coalesce(n.assurance_filled_fields, []) AS filled "
    + " ".join(
        f"FOREACH (_ IN CASE WHEN '{f}' IN filled THEN [1] ELSE [] END | REMOVE n.{f})"
        for f in SET_IF_ABSENT_FIELDS
    )
    + " REMOVE n.integrity_digest, n.integrity_hmac_version, n.assurance_filled_fields "
    "RETURN count(n) AS nodes"
)
_Q_ROLLBACK_EVENTS = (
    "MATCH (ev:CogniNode {assurance_type: 'ProvenanceEvent', event_type: 'MIGRATION'}) "
    "DETACH DELETE ev RETURN count(*) AS events"
)


def _refuse(msg: str) -> AssuranceWriteRefusedError:
    return AssuranceWriteRefusedError(msg)


def _single(result: Any) -> dict[str, Any] | None:
    rec = result.single()
    return None if rec is None else dict(rec)


# ── op handlers (each runs inside the caller's transaction) ──────────────────


def _create_node(tx: Any, op: AssuranceOp, keyring: IntegrityKeyring) -> None:
    values = {**op.props, "id": op.node_id}
    rec = _single(
        tx.run(
            _Q_CREATE_NODE,
            id=op.node_id,
            props=dict(op.props),
            digest=node_digest(keyring, values),
            version=keyring.current_version,
        )
    )
    if rec is None:  # pragma: no cover - MERGE always returns a row
        raise _refuse(f"{op.node_id}: create returned no row")
    for f in WRITE_ONCE_NODE_FIELDS:
        if rec.get(f) != op.props.get(f):
            raise _refuse(f"{op.node_id}: write-once field {f!r} differs from the stored value")


def _set_if_absent(tx: Any, op: AssuranceOp, keyring: IntegrityKeyring) -> None:
    rec = _single(tx.run(_Q_SET_IF_ABSENT, id=op.node_id, p=dict(op.props), fields=list(op.props)))
    if rec is None:
        raise _refuse(f"{op.node_id}: node not found")
    if rec.get("assurance_type") and not rec.get("digest"):
        tx.run(
            _Q_SET_NODE_DIGEST,
            id=op.node_id,
            digest=node_digest(keyring, rec),
            version=keyring.current_version,
        )


def _create_edge(tx: Any, op: AssuranceOp, keyring: IntegrityKeyring) -> None:
    assert op.edge_kind is not None  # set by AssuranceOp.create_edge
    kind = op.edge_kind.value
    ends = _single(tx.run(_Q_ENDPOINTS, s=op.source_id, t=op.target_id))
    if ends is None:
        raise _refuse(f"{kind} {op.source_id}->{op.target_id}: endpoint not found")
    if op.edge_kind in ORDERED_EDGE_KINDS:
        for side, name in (("a", "source"), ("b", "target")):
            if not ends.get(f"{side}_canonical_id"):
                raise _refuse(f"{kind}: {name} has no canonical_id (rule c)")
        reason = ordering_violation(
            kind,
            {"asserted_at": ends["a_asserted_at"], "valid_from": ends["a_valid_from"]},
            {"asserted_at": ends["b_asserted_at"], "valid_from": ends["b_valid_from"]},
        )
        if reason:
            raise _refuse(f"{kind} {op.source_id}->{op.target_id}: {reason} (rule d)")
    values = {
        "source_id": op.source_id,
        "target_id": op.target_id,
        "kind": kind,
        "scope_key": op.props.get("scope_key"),
        "prov_event_id": op.props.get("prov_event_id"),
        "asserted_at": op.props.get("asserted_at"),
    }
    rec = _single(
        tx.run(
            _Q_CREATE_EDGE.get(kind, _Q_CREATE_EDGE["*"]),
            s=op.source_id,
            t=op.target_id,
            eid=op.edge_id,
            props=dict(op.props),
            digest=edge_digest(keyring, values),
            version=keyring.current_version,
        )
    )
    if rec is None:  # pragma: no cover - endpoints were matched above
        raise _refuse(f"{kind} {op.source_id}->{op.target_id}: edge write returned no row")
    for f in ("kind", "scope_key", "asserted_at", "prov_event_id"):
        if rec.get(f) != values[f]:
            raise _refuse(f"edge {op.edge_id}: existing {f!r} differs from the op")


def _resign_node(tx: Any, op: AssuranceOp, keyring: IntegrityKeyring) -> None:
    rec = _single(tx.run(f"MATCH (n:CogniNode {{id: $id}}) {_NODE_RETURN}", id=op.node_id))
    if rec is None:
        raise _refuse(f"{op.node_id}: node not found")
    if rec.get("version") == keyring.current_version:
        return
    status = verify_digest(keyring, "node", rec, rec.get("digest"), rec.get("version"))
    if status != "OK":
        raise _refuse(f"{op.node_id}: old digest is {status}; refusing to re-sign")
    tx.run(
        _Q_SET_NODE_DIGEST,
        id=op.node_id,
        digest=node_digest(keyring, rec),
        version=keyring.current_version,
    )


def _resign_edge(tx: Any, op: AssuranceOp, keyring: IntegrityKeyring) -> None:
    rows = [dict(r) for r in tx.run(_Q_EDGE_READ, eid=op.edge_id)]
    if len(rows) != 1:
        raise _refuse(f"edge {op.edge_id}: expected exactly one, found {len(rows)}")
    rec = rows[0]
    if rec.get("version") == keyring.current_version:
        return
    status = verify_digest(keyring, "edge", rec, rec.get("digest"), rec.get("version"))
    if status != "OK":
        raise _refuse(f"edge {op.edge_id}: old digest is {status}; refusing to re-sign")
    tx.run(
        _Q_SET_EDGE_DIGEST,
        eid=op.edge_id,
        digest=edge_digest(keyring, rec),
        version=keyring.current_version,
    )


_DISPATCH: dict[str, Callable[[Any, AssuranceOp, IntegrityKeyring], None]] = {
    "create_node": _create_node,
    "set_if_absent": _set_if_absent,
    "create_edge": _create_edge,
    "resign_node": _resign_node,
    "resign_edge": _resign_edge,
}


# ── entry points (called by kg_persist only) ─────────────────────────────────


def write_ops(
    driver: Any, database: str, ops: Sequence[AssuranceOp], keyring: IntegrityKeyring
) -> None:
    """Apply ``ops`` in order, in ONE write transaction."""

    def _tx(tx: Any) -> None:
        for op in ops:
            _DISPATCH[op.kind](tx, op, keyring)

    with driver.session(database=database) as session:
        session.execute_write(_tx)


def rollback_migration(driver: Any, database: str) -> dict[str, int]:
    """Undo every MIGRATION event, in ONE write transaction (CR-016 §5.3)."""
    out: dict[str, int] = {}

    def _tx(tx: Any) -> None:
        out["nodes"] = int(tx.run(_Q_ROLLBACK_NODES).single()["nodes"])
        out["events"] = int(tx.run(_Q_ROLLBACK_EVENTS).single()["events"])

    with driver.session(database=database) as session:
        session.execute_write(_tx)
    return out
