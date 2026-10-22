"""DAG-2026 assurance migration: additive, idempotent, reversible (CR-016 §5.3, PR-016b).

``plan_migration`` is read-only and returns a :class:`MigrationPlan` with a
``plan_hash``. ``apply_migration`` (``dry_run=True`` by default) writes through
:meth:`Neo4jBatchPersister.persist_assurance_ops` only: one deterministic
MIGRATION ProvenanceEvent, a ``set_if_absent`` per assigned node, and a
GENERATED edge from the event to each node. Re-applying the same plan changes
nothing: the event id is derived from the plan hash, its timestamps are reused
from the stored event, and ``set_if_absent`` only fills empty fields.
``rollback_migration`` removes exactly what MIGRATION events filled, deletes the
events and their GENERATED edges, and drops the secondary labels. ``HAS_CHUNK``
and ``:Chunk`` are never touched.

Which substrate nodes become which class is PRIVATE configuration: callers pass
:class:`BridgingRules`. The public default assigns nothing.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.assurance_migration
# risk: MEDIUM (impact radius: 0 existing callers -- writes via Neo4jBatchPersister only)
# dependencies: graqle.ontology.{assurance,assurance_ops,assurance_config},
#   graqle.governance.tamper_evidence.canonicalize
# constraints: no direct Cypher writes; bridging rules are caller-supplied private config
# -- /graqle:intelligence --
import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from graqle.ontology.assurance import AssuranceClass, EdgeKind, edge_id
from graqle.ontology.assurance_config import AssuranceOntologyConfig
from graqle.ontology.assurance_ops import AssuranceOp

__all__ = [
    "GLOBAL_SCOPE_KEY",
    "BridgingRules",
    "MigrationPlan",
    "MigrationReport",
    "NoBridgingRules",
    "apply_migration",
    "migration_event_id",
    "plan_migration",
    "rollback_migration",
    "verify_migration",
]

logger = logging.getLogger(__name__)

#: Scope of the migration's own event and GENERATED edges.
GLOBAL_SCOPE_KEY = "global"
_ACTOR = "agent_sdk_migration"


class BridgingRules(Protocol):
    def assign(self, connector: Any) -> Mapping[str, AssuranceClass]: ...


class NoBridgingRules:
    """The public default: no substrate node is reclassified."""

    def assign(self, connector: Any) -> Mapping[str, AssuranceClass]:
        return {}


@dataclass(frozen=True)
class MigrationPlan:
    total_nodes: int
    total_edges: int
    class_assignments: Mapping[str, AssuranceClass]
    labels_enabled: bool
    batch_size: int
    plan_hash: str


@dataclass(frozen=True)
class MigrationReport:
    plan: MigrationPlan
    ops: int
    applied: bool
    verified: bool | None = None
    labels_applied: int = 0


def _canon_hash(obj: Mapping[str, Any]) -> str:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return hashlib.sha256(canon(dict(obj))).hexdigest()


def _scalar(connector: Any, query: str, **params: Any) -> int:
    rows = connector.read_assurance_rows([(query, params)])[0]
    return int(rows[0]["c"]) if rows else 0


def plan_migration(
    connector: Any, config: AssuranceOntologyConfig, rules: BridgingRules | None = None
) -> MigrationPlan:
    """Read-only. Counts, private class assignments, label decision, ``plan_hash``."""
    n = _scalar(connector, "MATCH (n:CogniNode) RETURN count(n) AS c")
    e = _scalar(connector, "MATCH ()-[r:RELATES_TO]->() RETURN count(r) AS c")
    assignments = dict((rules or NoBridgingRules()).assign(connector))
    labels_enabled = config.secondary_labels_enabled and n <= config.label_safe_node_ceiling
    if config.secondary_labels_enabled and not labels_enabled:
        logger.warning(
            "assurance migration: %d CogniNodes exceeds the label ceiling; "
            "secondary labels are OFF",
            n,
        )
    plan_hash = _canon_hash(
        {
            "n": n,
            "e": e,
            "assign": sorted([k, AssuranceClass(v).value] for k, v in assignments.items()),
            "labels": labels_enabled,
        }
    )
    return MigrationPlan(n, e, assignments, labels_enabled, config.migration_batch_size, plan_hash)


def migration_event_id(plan: MigrationPlan) -> str:
    return f"pev_migration_{plan.plan_hash[:16]}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_time(connector: Any, ev_id: str) -> str | None:
    rows = connector.read_assurance_rows(
        [("MATCH (n:CogniNode {id: $id}) RETURN n.asserted_at AS t", {"id": ev_id})]
    )[0]
    return rows[0]["t"] if rows else None


def _build_ops(plan: MigrationPlan, ev_id: str, now: str) -> list[AssuranceOp]:
    ops = [
        AssuranceOp.create_node(
            {
                "id": ev_id,
                "assurance_type": AssuranceClass.PROVENANCE_EVENT.value,
                "lifecycle_status": "ACTIVE",
                "scope_key": GLOBAL_SCOPE_KEY,
                "valid_from": now,
                "asserted_at": now,
                "event_id": ev_id,
                "event_type": "MIGRATION",
                "actor": _ACTOR,
                "inputs": [],
                "outputs": [],
                "canonical_hash": plan.plan_hash,
                "timestamp": now,
            }
        )
    ]
    for node_id in sorted(plan.class_assignments):
        cls = AssuranceClass(plan.class_assignments[node_id])
        ops.append(
            AssuranceOp.set_if_absent(
                node_id,
                {
                    "assurance_type": cls.value,
                    "lifecycle_status": "ACTIVE",
                    "valid_from": now,
                    "asserted_at": now,
                    "prov_event_id": ev_id,
                    "schema_version": "1",
                },
            )
        )
        ops.append(
            AssuranceOp.create_edge(
                {
                    "id": edge_id(ev_id, node_id, EdgeKind.GENERATED, GLOBAL_SCOPE_KEY),
                    "source_id": ev_id,
                    "target_id": node_id,
                    "kind": EdgeKind.GENERATED,
                    "scope_key": GLOBAL_SCOPE_KEY,
                    "asserted_at": now,
                    "prov_event_id": ev_id,
                }
            )
        )
    return ops


def apply_migration(
    persister: Any, plan: MigrationPlan, *, dry_run: bool = True
) -> MigrationReport:
    """Write the plan through the persister. ``dry_run`` (the default) writes nothing."""
    connector = persister.connector
    ev_id = migration_event_id(plan)
    now = _event_time(connector, ev_id) or _now()  # reuse => re-apply is a no-op
    ops = _build_ops(plan, ev_id, now)
    if dry_run:
        return MigrationReport(plan=plan, ops=len(ops), applied=False)
    for i in range(0, len(ops), plan.batch_size):
        persister.persist_assurance_ops(ops[i : i + plan.batch_size])
    labels = connector.apply_secondary_labels() if plan.labels_enabled else 0
    return MigrationReport(
        plan=plan,
        ops=len(ops),
        applied=True,
        verified=verify_migration(connector, plan),
        labels_applied=labels,
    )


def verify_migration(connector: Any, plan: MigrationPlan) -> bool:
    """Every assigned node has ``assurance_type``; with labels on, every typed
    node also has its label."""
    missing = _scalar(
        connector,
        "MATCH (n:CogniNode) WHERE n.id IN $ids AND n.assurance_type IS NULL RETURN count(n) AS c",
        ids=list(plan.class_assignments),
    )
    if missing:
        return False
    if not plan.labels_enabled:
        return True
    unlabelled = _scalar(
        connector,
        "MATCH (n:CogniNode) WHERE n.assurance_type IS NOT NULL "
        "AND NOT n.assurance_type IN labels(n) RETURN count(n) AS c",
    )
    return unlabelled == 0


def rollback_migration(persister: Any) -> dict[str, int]:
    """Undo every MIGRATION event, then drop the secondary labels."""
    out = dict(persister.rollback_assurance_migration())
    out["labels"] = persister.connector.remove_secondary_labels()
    return out
