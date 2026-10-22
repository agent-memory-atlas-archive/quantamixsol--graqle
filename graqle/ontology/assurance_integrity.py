"""DAG-2026 assurance integrity: keyed digests and a read-only verifier (CR-016, PR-016b).

What is guaranteed, and where (Research ruling 2026-09-28, stated as a BOUNDED claim):

    The acyclicity guarantee holds for all writes routed through
    ``persist_assurance_ops``. For writes outside that path the violation is
    detectable but not structurally impossible.

Refusal happens at the SDK boundary (the write path refuses bad ops); detection
happens at the database boundary (this module). On Neo4j Community Edition a
raw driver can still ``SET n.valid_from`` or delete and recreate an edge: CE has
no RBAC, measured on 2026.02.2 (``CREATE ROLE``, ``SHOW ROLES`` and
``DENY SET PROPERTY`` all fail with ``UnsupportedAdministrationCommand``).
Restricting write credentials (option A) is the Enterprise/Aura hardening.

Acyclicity follows from the ordering rule (d): ``(asserted_at, valid_from)``
strictly decreases along every SUPERSEDES and CORRECTS edge, one shared order
for both kinds, so no path can return to its start. The verifier checks the
rule on every such edge, so any cycle shows up as at least one ordering
finding. SUPERSEDES additionally needs ``source.valid_from > target.valid_from``;
that also prevents ``old.valid_until := new.valid_from`` from falling before
``old.valid_from``, a negative validity interval.

Digests are HMAC-SHA256 over the RFC 8785 canonical form (one canonicaliser in
the codebase), under a key derived per ``hmac_version`` from the deployment
salt. The version is stored beside every digest, so a salt rotation is never
mistaken for tampering: an unknown version is its own finding. A NODE digest
covers ``id, assurance_type, canonical_id, scope_key, valid_from, asserted_at``.
An EDGE digest covers ``source_id, target_id, kind, scope_key, prov_event_id,
asserted_at`` and is computed from the edge's ACTUAL endpoints at verify time.
Neo4j cannot repoint an edge, so a raw writer must delete and recreate it, and
the new edge has no valid digest.

:func:`verify_assurance_integrity` is read-only and can run synchronously before
any query that depends on temporal order. With no keyring it fails closed.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.assurance_integrity
# risk: LOW (impact radius: 0 existing callers -- PR-016b; CR-017/018 and
#   Research scripts consume it)
# dependencies: graqle.governance.tamper_evidence.canonicalize (lazy)
# constraints: read-only; never writes; no keyring => ok=False
# -- /graqle:intelligence --
import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

__all__ = [
    "ASSURANCE_CONSTRAINTS",
    "ASSURANCE_CONSTRAINT_SHAPES",
    "EDGE_DIGEST_FIELDS",
    "NODE_DIGEST_FIELDS",
    "IntegrityFinding",
    "IntegrityKeyring",
    "IntegrityReport",
    "IntegrityViolationError",
    "edge_digest",
    "key_rotation_ops",
    "node_digest",
    "ordering_violation",
    "verify_assurance_integrity",
    "verify_digest",
]

#: Fixed and documented serialisation: the canonical JSON object of these keys.
NODE_DIGEST_FIELDS: tuple[str, ...] = (
    "id",
    "assurance_type",
    "canonical_id",
    "scope_key",
    "valid_from",
    "asserted_at",
)
EDGE_DIGEST_FIELDS: tuple[str, ...] = (
    "source_id",
    "target_id",
    "kind",
    "scope_key",
    "prov_event_id",
    "asserted_at",
)

#: Name → Cypher of every DB constraint PR-016b relies on (measured on CE 2026.02.2).
ASSURANCE_CONSTRAINTS: dict[str, str] = {
    "assurance_version_unique": (
        "CREATE CONSTRAINT assurance_version_unique IF NOT EXISTS FOR (n:CogniNode) "
        "REQUIRE (n.canonical_id, n.scope_key, n.valid_from) IS UNIQUE"
    ),
    "relates_to_supersedes_in": (
        "CREATE CONSTRAINT relates_to_supersedes_in IF NOT EXISTS "
        "FOR ()-[r:RELATES_TO]-() REQUIRE r.supersedes_in IS UNIQUE"
    ),
    "relates_to_supersedes_out": (
        "CREATE CONSTRAINT relates_to_supersedes_out IF NOT EXISTS "
        "FOR ()-[r:RELATES_TO]-() REQUIRE r.supersedes_out IS UNIQUE"
    ),
    "relates_to_corrects_in": (
        "CREATE CONSTRAINT relates_to_corrects_in IF NOT EXISTS "
        "FOR ()-[r:RELATES_TO]-() REQUIRE r.corrects_in IS UNIQUE"
    ),
    "relates_to_corrects_out": (
        "CREATE CONSTRAINT relates_to_corrects_out IF NOT EXISTS "
        "FOR ()-[r:RELATES_TO]-() REQUIRE r.corrects_out IS UNIQUE"
    ),
}

#: What each constraint must ENFORCE: (type, label or rel type, properties).
#: The verifier checks this shape, not the name: ``IF NOT EXISTS`` is a silent
#: no-op when an equivalent constraint exists under another name, so a check by
#: name would report a constraint missing that the DB is enforcing.
ASSURANCE_CONSTRAINT_SHAPES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "assurance_version_unique": (
        "NODE_PROPERTY_UNIQUENESS",
        "CogniNode",
        ("canonical_id", "scope_key", "valid_from"),
    ),
    "relates_to_supersedes_in": (
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
        "RELATES_TO",
        ("supersedes_in",),
    ),
    "relates_to_supersedes_out": (
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
        "RELATES_TO",
        ("supersedes_out",),
    ),
    "relates_to_corrects_in": ("RELATIONSHIP_PROPERTY_UNIQUENESS", "RELATES_TO", ("corrects_in",)),
    "relates_to_corrects_out": (
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
        "RELATES_TO",
        ("corrects_out",),
    ),
}

_DIGEST_PREFIX = "hmac-sha256:"
_KEY_LABEL = b"graqle.assurance.integrity.key.v1|"
_NODE_LABEL = b"graqle.assurance.integrity.node.v1|"
_EDGE_LABEL = b"graqle.assurance.integrity.edge.v1|"
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ORDERED_KINDS = ("SUPERSEDES", "CORRECTS")
_CARDINALITY = {
    "SUPERSEDES": ("supersedes_in", "supersedes_out"),
    "CORRECTS": ("corrects_in", "corrects_out"),
}


# ── keyring and digests ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class IntegrityKeyring:
    """Integrity keys by ``hmac_version``. ``current_version`` signs; all versions verify.

    Build it with :meth:`from_salts` (or ``graqle.assurance.integrity_keys.
    keyring_from_settings``). Keys are
    derived from each salt with a domain label, so the integrity key is never the
    same bytes as the ``config_version`` key.
    """

    current_version: str
    _keys: Mapping[str, bytes] = field(repr=False)

    @classmethod
    def from_salts(
        cls, current: tuple[str, str | bytes], *previous: tuple[str, str | bytes]
    ) -> IntegrityKeyring:
        keys: dict[str, bytes] = {}
        for version, salt in (current, *previous):
            if not version or version in keys:
                raise ValueError("every hmac_version must be non-empty and distinct")
            raw = salt.encode("utf-8") if isinstance(salt, str) else bytes(salt)
            if len(raw) < 32:
                raise ValueError("integrity salt must be at least 32 bytes")
            keys[version] = hmac.new(
                raw, _KEY_LABEL + version.encode("utf-8"), hashlib.sha256
            ).digest()
        return cls(current_version=current[0], _keys=keys)

    @property
    def versions(self) -> tuple[str, ...]:
        return tuple(self._keys)

    def key(self, version: str) -> bytes | None:
        return self._keys.get(version)


def _mac(key: bytes, label: bytes, payload: Mapping[str, Any]) -> str:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return _DIGEST_PREFIX + hmac.new(key, label + canon(dict(payload)), hashlib.sha256).hexdigest()


def _payload(fields: tuple[str, ...], values: Mapping[str, Any]) -> dict[str, Any]:
    return {f: values.get(f) for f in fields}


def node_digest(
    keyring: IntegrityKeyring, values: Mapping[str, Any], version: str | None = None
) -> str:
    v = version or keyring.current_version
    key = keyring.key(v)
    if key is None:
        raise KeyError(f"no integrity key for hmac_version {v!r}")
    return _mac(key, _NODE_LABEL, _payload(NODE_DIGEST_FIELDS, values))


def edge_digest(
    keyring: IntegrityKeyring, values: Mapping[str, Any], version: str | None = None
) -> str:
    v = version or keyring.current_version
    key = keyring.key(v)
    if key is None:
        raise KeyError(f"no integrity key for hmac_version {v!r}")
    return _mac(key, _EDGE_LABEL, _payload(EDGE_DIGEST_FIELDS, values))


DigestStatus = Literal["OK", "MISSING", "UNKNOWN_VERSION", "MISMATCH"]


def verify_digest(
    keyring: IntegrityKeyring,
    what: Literal["node", "edge"],
    values: Mapping[str, Any],
    digest: Any,
    version: Any,
) -> DigestStatus:
    """Check one stored digest. Unknown version and mismatch are distinct outcomes."""
    if not digest or not version:
        return "MISSING"
    if keyring.key(str(version)) is None:
        return "UNKNOWN_VERSION"
    fn = node_digest if what == "node" else edge_digest
    expected = fn(keyring, values, str(version))
    return "OK" if hmac.compare_digest(expected, str(digest)) else "MISMATCH"


def key_rotation_ops(connector: Any, keyring: IntegrityKeyring, *, now: str) -> list[Any]:
    """The ONE batch that rotates the integrity key (Research ruling 2026-09-28 §1(3)).

    A KEY_ROTATION ProvenanceEvent, so the rotation is a declared assurance event,
    followed by a re-sign op for every signed node and edge. Each re-sign verifies
    the old digest first, in the same transaction, and refuses on anything but
    OK, so a tampered item is never laundered by a rotation. Persist the result
    with ONE ``persist_assurance_ops`` call while the old key is still in the
    keyring (the overlap window); retire the old salt only afterwards.
    """
    from graqle.ontology.assurance_ops import AssuranceOp  # lazy: ops import the models

    nodes, edges = connector.read_assurance_rows(
        [
            (
                "MATCH (n:CogniNode) WHERE n.integrity_digest IS NOT NULL "
                "RETURN n.id AS id ORDER BY id",
                {},
            ),
            (
                "MATCH ()-[r:RELATES_TO]->() WHERE r.integrity_digest IS NOT NULL "
                "RETURN r.id AS id ORDER BY id",
                {},
            ),
        ]
    )
    ev_id = f"pev_key_rotation_{keyring.current_version}"
    event = AssuranceOp.create_node(
        {
            "id": ev_id,
            "assurance_type": "ProvenanceEvent",
            "lifecycle_status": "ACTIVE",
            "scope_key": "global",
            "valid_from": now,
            "asserted_at": now,
            "event_id": ev_id,
            "event_type": "KEY_ROTATION",
            "actor": "agent_sdk_key_rotation",
            "inputs": sorted(v for v in keyring.versions if v != keyring.current_version),
            "outputs": [keyring.current_version],
            "canonical_hash": hashlib.sha256(
                ("|".join(sorted(keyring.versions)) + "|" + keyring.current_version).encode("utf-8")
            ).hexdigest(),
            "timestamp": now,
        }
    )
    return [
        event,
        *(AssuranceOp.resign_node(r["id"]) for r in nodes),
        *(AssuranceOp.resign_edge(r["id"]) for r in edges),
    ]


def ordering_violation(
    kind: str, source: Mapping[str, Any], target: Mapping[str, Any]
) -> str | None:
    """Rule (d). ``None`` when the edge is well ordered, else the reason.

    Timestamps must be canonical ``YYYY-MM-DDTHH:MM:SSZ`` (one width, so string
    order is time order); anything else is a violation, never compared.
    """
    vals = {}
    for side, node in (("source", source), ("target", target)):
        for f in ("asserted_at", "valid_from"):
            v = node.get(f)
            if not isinstance(v, str) or not _ISO_UTC.match(v):
                return f"{side}.{f} missing or not canonical"
            vals[(side, f)] = v
    f_src = (vals[("source", "asserted_at")], vals[("source", "valid_from")])
    f_tgt = (vals[("target", "asserted_at")], vals[("target", "valid_from")])
    if not f_src > f_tgt:
        return "(asserted_at, valid_from) does not strictly decrease from source to target"
    if kind == "SUPERSEDES" and not vals[("source", "valid_from")] > vals[("target", "valid_from")]:
        return "SUPERSEDES needs source.valid_from > target.valid_from"
    return None


# ── verifier ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IntegrityFinding:
    code: str
    severity: Literal["ERROR", "WARNING"]
    subject: str
    detail: str


@dataclass(frozen=True)
class IntegrityReport:
    ok: bool
    findings: tuple[IntegrityFinding, ...]
    nodes_checked: int
    edges_checked: int
    verified_at: str

    def errors(self) -> tuple[IntegrityFinding, ...]:
        return tuple(f for f in self.findings if f.severity == "ERROR")

    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    def raise_for_errors(self) -> None:
        """For scripts that must BLOCK on a finding (Research commitment 3)."""
        if not self.ok:
            raise IntegrityViolationError(self)


class IntegrityViolationError(RuntimeError):
    def __init__(self, report: IntegrityReport) -> None:
        self.report = report
        codes = ", ".join(sorted({f.code for f in report.errors()})) or "UNMEASURED"
        super().__init__(f"assurance integrity check failed: {codes}")


_NODES_Q = (
    "MATCH (n:CogniNode) WHERE n.assurance_type IS NOT NULL "
    "AND ($scope IS NULL OR n.scope_key = $scope) "
    "RETURN n.id AS id, n.assurance_type AS assurance_type, n.canonical_id AS canonical_id, "
    "n.scope_key AS scope_key, n.valid_from AS valid_from, n.asserted_at AS asserted_at, "
    "n.integrity_digest AS digest, n.integrity_hmac_version AS version"
)
_EDGES_Q = (
    "MATCH (a:CogniNode)-[r:RELATES_TO]->(b:CogniNode) "
    "WHERE r.kind IN $kinds AND ($scope IS NULL OR r.scope_key = $scope) "
    "RETURN r.id AS edge_id, a.id AS source_id, b.id AS target_id, r.kind AS kind, "
    "r.scope_key AS scope_key, r.prov_event_id AS prov_event_id, r.asserted_at AS asserted_at, "
    "r.supersedes_in AS supersedes_in, r.supersedes_out AS supersedes_out, "
    "r.corrects_in AS corrects_in, r.corrects_out AS corrects_out, "
    "r.integrity_digest AS digest, r.integrity_hmac_version AS version, "
    "a.asserted_at AS a_asserted_at, a.valid_from AS a_valid_from, "
    "a.canonical_id AS a_canonical_id, "
    "b.asserted_at AS b_asserted_at, b.valid_from AS b_valid_from, b.canonical_id AS b_canonical_id"
)
_CONSTRAINTS_Q = "SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties RETURN *"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_assurance_integrity(
    connector: Any,
    keyring: IntegrityKeyring | None,
    *,
    scope_key: str | None = None,
) -> IntegrityReport:
    """Read-only integrity check of the assurance subgraph (optionally one scope).

    Checks the DB constraints exist, the ordering rule (d) on every SUPERSEDES
    and CORRECTS edge, the four cardinality properties against the ACTUAL
    endpoints, ``canonical_id`` on every participant, and every node and edge
    digest. Any failure to measure (no keyring, a query error) is an ERROR, so
    ``ok`` is never true for something that was not checked.
    """
    findings: list[IntegrityFinding] = []
    now = _utc_now()

    def add(
        code: str, subject: str, detail: str, severity: Literal["ERROR", "WARNING"] = "ERROR"
    ) -> None:
        findings.append(IntegrityFinding(code, severity, subject, detail))

    if keyring is None:
        add("VERIFIER_UNKEYED", "-", "no integrity keyring: digests cannot be checked")
    try:
        rows = connector.read_assurance_rows(
            [
                (_CONSTRAINTS_Q, {}),
                (_NODES_Q, {"scope": scope_key}),
                (_EDGES_Q, {"scope": scope_key, "kinds": list(_ORDERED_KINDS)}),
            ]
        )
        constraint_rows, node_rows, edge_rows = rows
    except Exception as exc:  # noqa: BLE001 - an unmeasured graph is never "ok"
        add("VERIFIER_QUERY_FAILED", "-", type(exc).__name__)
        return IntegrityReport(False, tuple(findings), 0, 0, now)

    present = {
        (r.get("type"), tuple(r.get("labelsOrTypes") or ()), tuple(r.get("properties") or ()))
        for r in constraint_rows
    }
    for name, (ctype, target, props) in ASSURANCE_CONSTRAINT_SHAPES.items():
        if (ctype, (target,), props) not in present:
            add("CONSTRAINT_MISSING", name, "no DB constraint enforces this")

    participants: set[str] = set()
    for e in edge_rows:
        participants.update((e["source_id"], e["target_id"]))

    for n in node_rows:
        nid = str(n["id"])
        is_participant = nid in participants
        if is_participant and not n.get("canonical_id"):
            add("MISSING_CANONICAL_ID", nid, "SUPERSEDES/CORRECTS participant without canonical_id")
        if keyring is None:
            continue
        status = verify_digest(keyring, "node", n, n.get("digest"), n.get("version"))
        if status == "MISSING":
            add(
                "NODE_DIGEST_MISSING",
                nid,
                "node has no integrity digest",
                "ERROR" if is_participant else "WARNING",
            )
        elif status == "UNKNOWN_VERSION":
            add(
                "UNKNOWN_HMAC_VERSION",
                nid,
                f"hmac_version {n.get('version')!r} is not in the keyring",
            )
        elif status == "MISMATCH":
            add("NODE_DIGEST_MISMATCH", nid, "write-once fields changed outside the SDK write path")

    for e in edge_rows:
        kind = str(e["kind"])
        subject = f"{e['source_id']}-[{kind}]->{e['target_id']}"
        reason = ordering_violation(
            kind,
            {"asserted_at": e["a_asserted_at"], "valid_from": e["a_valid_from"]},
            {"asserted_at": e["b_asserted_at"], "valid_from": e["b_valid_from"]},
        )
        if reason:
            add("ORDERING_VIOLATION", subject, reason)
        for side in ("a", "b"):
            if not e.get(f"{side}_canonical_id"):
                add(
                    "MISSING_CANONICAL_ID",
                    subject,
                    f"{'source' if side == 'a' else 'target'} has no canonical_id",
                )
        in_prop, out_prop = _CARDINALITY[kind]
        if e.get(in_prop) != e["target_id"] or e.get(out_prop) != e["source_id"]:
            add(
                "CARDINALITY_PROP_MISMATCH",
                subject,
                f"{in_prop}/{out_prop} do not equal the endpoints",
            )
        other = [p for k, pair in _CARDINALITY.items() if k != kind for p in pair]
        if any(e.get(p) is not None for p in other):
            add(
                "CARDINALITY_PROP_MISMATCH",
                subject,
                "carries the other kind's cardinality properties",
            )
        if keyring is None:
            continue
        status = verify_digest(keyring, "edge", e, e.get("digest"), e.get("version"))
        if status == "MISSING":
            add(
                "EDGE_DIGEST_MISSING",
                subject,
                "edge has no integrity digest (not written by the SDK path)",
            )
        elif status == "UNKNOWN_VERSION":
            add(
                "UNKNOWN_HMAC_VERSION",
                subject,
                f"hmac_version {e.get('version')!r} is not in the keyring",
            )
        elif status == "MISMATCH":
            add(
                "EDGE_DIGEST_MISMATCH",
                subject,
                "edge fields or endpoints changed outside the SDK write path",
            )

    ok = not any(f.severity == "ERROR" for f in findings)
    return IntegrityReport(ok, tuple(findings), len(node_rows), len(edge_rows), now)
