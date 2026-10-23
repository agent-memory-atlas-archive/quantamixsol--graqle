"""DAG-2026 assurance ontology (CR-016, PR-016a).

Adds nine assurance classes (Evidence, Claim, Abstraction, Instruction,
Policy, Decision, Action, Agent, ProvenanceEvent), ten edge kinds carried on
the existing ``RELATES_TO`` relationship, a lifecycle vocabulary, and
bitemporal validity. Everything here is ADDITIVE:

* The ``UPPER_HIERARCHY``, ``NODE_SHAPES`` and ``EDGE_SHAPES`` literals are
  never edited. :func:`register_assurance_ontology` mounts at runtime, and
  only when ``GRAQLE_DAG_ENABLED`` is on; with the flag off nothing is
  mutated (byte-identical, AC-1).
* A collision is refused with :class:`AssuranceRegistrationError`, never
  overwritten.
* No edge shape named ``SUPERSEDES`` is ever registered (the PAPER shape keeps
  that name). Edge kinds live in their own registry,
  :data:`ASSURANCE_EDGE_KIND_SHAPES`, and are checked by
  :func:`validate_assurance_graph`, which layers over
  :func:`graqle.ontology.schema.validate_graph` without replacing it.
* ``assurance_type`` is the authoritative property; secondary labels are an
  optional index accelerator added by the migration (PR-016b).

Timestamps are ISO-8601 UTC strings in ONE canonical width,
``YYYY-MM-DDTHH:MM:SSZ``, so that string comparison, which the Cypher
current-state predicate relies on, is also time order. Mixed widths break
that: ``"…:00.5Z"`` sorts before ``"…:00Z"``.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.assurance
# risk: MEDIUM (impact radius: 0 existing callers -- CR-016b/017/018 consume it)
# dependencies: pydantic, graqle.ontology.{schema,upper}, graqle.core.{types,exceptions},
#   graqle.assurance.settings (lazy, only when the flag is on),
#   graqle.governance.tamper_evidence.canonicalize (lazy)
# constraints: never edits UPPER_HIERARCHY / NODE_SHAPES / EDGE_SHAPES literals;
#   never registers an edge shape named SUPERSEDES; flag off => no mutation
# -- /graqle:intelligence --
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from graqle.core.exceptions import GraqleError
from graqle.core.types import ClearanceLevel
from graqle.ontology.schema import (
    EDGE_SHAPES,
    NODE_SHAPES,
    EdgeShape,
    NodeShape,
    PropertyConstraint,
    ValidationReport,
    Violation,
    register_edge_shape,
    register_node_shape,
    validate_graph,
)
from graqle.ontology.upper import UpperOntology

__all__ = [
    "ASSURANCE_EDGE_KIND_SHAPES",
    "ASSURANCE_HIERARCHY",
    "ASSURANCE_NODE_SHAPES",
    "ASSURANCE_SHAPE_VERSION",
    "CLASS_PREREQUISITES",
    "CLASS_TO_TYPE_KEY",
    "MODEL_FOR_CLASS",
    "Abstraction",
    "Action",
    "Agent",
    "AssuranceClass",
    "AssuranceEdge",
    "AssuranceNodeBase",
    "AssuranceRegistrationError",
    "AuthenticityStatus",
    "BitemporalMixin",
    "Claim",
    "Decision",
    "EdgeKind",
    "EdgeKindShape",
    "Evidence",
    "IdentityAssuranceLevel",
    "Instruction",
    "LifecycleStatus",
    "Policy",
    "ProvenanceEvent",
    "RegistrationRecord",
    "covers",
    "current_state_cypher_predicate",
    "edge_id",
    "register_assurance_ontology",
    "to_iso_utc",
    "validate_assurance_graph",
]

ASSURANCE_SHAPE_VERSION = "1.0.0"


# ── enums (CR-016 §4.1, PUBLIC) ──────────────────────────────────────────────


class AssuranceClass(str, Enum):
    """Value == ``assurance_type`` property == optional secondary label."""

    EVIDENCE = "Evidence"
    CLAIM = "Claim"
    ABSTRACTION = "Abstraction"
    INSTRUCTION = "Instruction"
    POLICY = "Policy"
    DECISION = "Decision"
    ACTION = "Action"
    AGENT = "Agent"
    PROVENANCE_EVENT = "ProvenanceEvent"


class EdgeKind(str, Enum):
    """Value == ``RELATES_TO.kind``."""

    DERIVED_FROM = "DERIVED_FROM"
    SUPPORTED_BY = "SUPPORTED_BY"
    CONTRADICTS = "CONTRADICTS"
    SUPERSEDES = "SUPERSEDES"
    CORRECTS = "CORRECTS"
    COEXISTS_WITH = "COEXISTS_WITH"
    GOVERNED_BY = "GOVERNED_BY"
    USED = "USED"
    GENERATED = "GENERATED"
    INVALIDATES = "INVALIDATES"


class LifecycleStatus(str, Enum):
    """Knowledge lifecycle. Distinct from the operational ``core.types.NodeStatus``."""

    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    PENDING_RECOMPUTE = "PENDING_RECOMPUTE"
    SUPERSEDED = "SUPERSEDED"
    INVALIDATED = "INVALIDATED"
    RETRACTED = "RETRACTED"


class AuthenticityStatus(str, Enum):
    SIGNED = "SIGNED"
    ATTESTED = "ATTESTED"
    SELF_ASSERTED = "SELF_ASSERTED"
    EXTRACTION_FAILED = "EXTRACTION_FAILED"
    UNKNOWN = "UNKNOWN"


class IdentityAssuranceLevel(str, Enum):
    """Shared with CR-018, which imports it from here."""

    IAL1 = "IAL1"
    IAL2 = "IAL2"
    IAL3 = "IAL3"


# ── upper-ontology mounts (CR-016 §4.1 table) ────────────────────────────────

ASSURANCE_HIERARCHY: dict[str, str] = {
    "ASSURANCE_AGENT": "Agent",
    "ASSURANCE_PROVENANCE_EVENT": "Lineage",
    "ASSURANCE_EVIDENCE": "Artifact",
    "ASSURANCE_CLAIM": "Artifact",
    "ASSURANCE_ABSTRACTION": "Artifact",
    "ASSURANCE_INSTRUCTION": "Governance",
    "ASSURANCE_POLICY": "Governance",
    "ASSURANCE_DECISION": "Cognitive",
    "ASSURANCE_ACTION": "Cognitive",
}
CLASS_TO_TYPE_KEY: dict[AssuranceClass, str] = {c: f"ASSURANCE_{c.name}" for c in AssuranceClass}

#: Classes that must exist before a class can be written (lifecycle rule L1 family).
CLASS_PREREQUISITES: dict[AssuranceClass, tuple[AssuranceClass, ...]] = {
    AssuranceClass.CLAIM: (AssuranceClass.EVIDENCE,),
    AssuranceClass.ABSTRACTION: (AssuranceClass.CLAIM,),
    AssuranceClass.DECISION: (AssuranceClass.POLICY,),
    AssuranceClass.ACTION: (AssuranceClass.DECISION,),
}


# ── timestamps: one canonical width ──────────────────────────────────────────

_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def to_iso_utc(dt: datetime) -> str:
    """Render an AWARE datetime in the canonical ``YYYY-MM-DDTHH:MM:SSZ`` form."""
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("naive datetime rejected; pass an aware (UTC) datetime")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _check_iso_utc(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 UTC string")
    if not _ISO_UTC.match(value):
        raise ValueError("timestamp must be canonical ISO-8601 UTC 'YYYY-MM-DDTHH:MM:SSZ'")
    _parse_iso_utc(value)  # rejects impossible dates such as 2026-02-30
    return value


# ── node models (CR-016 §4.2, extra="forbid") ────────────────────────────────


class BitemporalMixin(BaseModel):
    """Valid time ``[valid_from, valid_until)``; transaction time ``[asserted_at, retracted_at)``.

    Both intervals are half-open; ``None`` as the end means open-ended.
    """

    model_config = ConfigDict(extra="forbid")

    valid_from: str
    valid_until: str | None = None
    asserted_at: str
    retracted_at: str | None = None

    @field_validator("valid_from", "asserted_at", mode="before")
    @classmethod
    def _required_ts(cls, v: Any) -> str:
        return _check_iso_utc(v)

    @field_validator("valid_until", "retracted_at", mode="before")
    @classmethod
    def _optional_ts(cls, v: Any) -> str | None:
        return None if v is None else _check_iso_utc(v)

    @model_validator(mode="after")
    def _ordered(self) -> BitemporalMixin:
        # Canonical width makes string order == time order.
        if self.valid_until is not None and self.valid_until < self.valid_from:
            raise ValueError("valid_until precedes valid_from")
        if self.retracted_at is not None and self.retracted_at < self.asserted_at:
            raise ValueError("retracted_at precedes asserted_at")
        return self


class AssuranceNodeBase(BitemporalMixin):
    ASSURANCE_CLASS: ClassVar[AssuranceClass]

    id: str
    assurance_type: AssuranceClass
    lifecycle_status: LifecycleStatus = LifecycleStatus.PROPOSED
    scope_key: str
    canonical_id: str | None = None
    prov_event_id: str | None = None
    schema_version: str = "1"
    #: substrate fields a graph_data node legitimately carries alongside assurance ones
    type: str | None = None
    label: str | None = None

    @model_validator(mode="after")
    def _class_matches_model(self) -> AssuranceNodeBase:
        expected = getattr(type(self), "ASSURANCE_CLASS", None)
        if expected is not None and self.assurance_type is not expected:
            raise ValueError(
                f"assurance_type {self.assurance_type.value} on a {expected.value} model"
            )
        status = getattr(self, "status", None)
        if status is not None and status is not self.lifecycle_status:
            raise ValueError("status must equal lifecycle_status")
        return self


class Evidence(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.EVIDENCE
    evidence_id: str
    source: str
    captured_at: str
    canonical_hash: str
    sensitivity: ClearanceLevel
    authenticity_status: AuthenticityStatus

    @field_validator("sensitivity", mode="before")
    @classmethod
    def _clearance_by_name(cls, v: Any) -> Any:
        if isinstance(v, str) and v in ClearanceLevel.__members__:
            return ClearanceLevel[v]
        return v

    @field_validator("captured_at", mode="before")
    @classmethod
    def _captured(cls, v: Any) -> str:
        return _check_iso_utc(v)


class Claim(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.CLAIM
    claim_id: str
    subject: str
    predicate: str
    object: str
    confidence_vector_json: str
    confidence_vector_version: str
    valid_time: str
    status: LifecycleStatus
    admitted_by_policy_id: str | None = None

    @model_validator(mode="after")
    def _valid_time_mirrors(self) -> Claim:
        if self.valid_time != f"{self.valid_from}/{self.valid_until or ''}":
            raise ValueError("valid_time must mirror valid_from/valid_until as 'start/end'")
        return self


class Abstraction(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.ABSTRACTION
    abstraction_id: str
    method: str
    inputs: list[str]
    scope: str
    confidence_vector_json: str
    confidence_vector_version: str
    version: int


class Instruction(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.INSTRUCTION
    instruction_id: str
    authority: str
    precedence: int
    scope: str
    effective_time: str
    status: LifecycleStatus


class Policy(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.POLICY
    policy_id: str
    version: str
    jurisdiction: str
    conditions: str
    severity: str
    effective_time: str
    mandatory: bool = True


class Decision(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.DECISION
    decision_id: str
    alternatives: list[str]
    gate_outcome: str
    score_vector_json: str
    residual_risk: float
    status: LifecycleStatus


class Action(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.ACTION
    action_id: str
    tool: str
    approved_args_hash: str | None = None
    actual_args_hash: str | None = None
    args_hash_algo: str | None = None
    result_ref: str | None = None
    status: LifecycleStatus


class Agent(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.AGENT
    agent_id: str
    agent_type: str
    identity_assurance: IdentityAssuranceLevel
    role: str
    authorization_scope: list[str]


class ProvenanceEvent(AssuranceNodeBase):
    ASSURANCE_CLASS = AssuranceClass.PROVENANCE_EVENT
    event_id: str
    event_type: str
    actor: str
    inputs: list[str]
    outputs: list[str]
    prior_event: str | None = None
    canonical_hash: str
    timestamp: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def _ts(cls, v: Any) -> str:
        return _check_iso_utc(v)


MODEL_FOR_CLASS: dict[AssuranceClass, type[AssuranceNodeBase]] = {
    AssuranceClass.EVIDENCE: Evidence,
    AssuranceClass.CLAIM: Claim,
    AssuranceClass.ABSTRACTION: Abstraction,
    AssuranceClass.INSTRUCTION: Instruction,
    AssuranceClass.POLICY: Policy,
    AssuranceClass.DECISION: Decision,
    AssuranceClass.ACTION: Action,
    AssuranceClass.AGENT: Agent,
    AssuranceClass.PROVENANCE_EVENT: ProvenanceEvent,
}


# ── edges (CR-016 §4.3) ──────────────────────────────────────────────────────

_PROV_REQUIRED = frozenset(
    {
        EdgeKind.INVALIDATES,
        EdgeKind.SUPERSEDES,
        EdgeKind.CORRECTS,
        EdgeKind.COEXISTS_WITH,
        EdgeKind.GENERATED,
        EdgeKind.USED,
    }
)


def edge_id(source_id: str, target_id: str, kind: EdgeKind | str, scope_key: str) -> str:
    """Deterministic MERGE key: first 32 hex of SHA-256 over the canonical tuple.

    128 bits (CR-016 §4.3) is ample for an in-graph identifier; it is a MERGE
    key, not an integrity commitment. Integrity comes from the tamper-evidence
    chain, which hashes full records.
    """
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    k = kind.value if isinstance(kind, EdgeKind) else str(kind)
    payload = {"source": source_id, "target": target_id, "kind": k, "scope_key": scope_key}
    return hashlib.sha256(canon(payload)).hexdigest()[:32]


class AssuranceEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source_id: str
    target_id: str
    kind: EdgeKind
    strength: float = 1.0
    scope_key: str
    asserted_at: str
    retracted_at: str | None = None
    prov_event_id: str | None = None
    contradiction_id: str | None = None
    resolution_status: str | None = None
    resolution_event_id: str | None = None

    @field_validator("strength")
    @classmethod
    def _unit(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("strength must be in [0, 1]")
        return v

    @field_validator("asserted_at", mode="before")
    @classmethod
    def _asserted(cls, v: Any) -> str:
        return _check_iso_utc(v)

    @field_validator("retracted_at", mode="before")
    @classmethod
    def _retracted(cls, v: Any) -> str | None:
        return None if v is None else _check_iso_utc(v)

    @model_validator(mode="after")
    def _rules(self) -> AssuranceEdge:
        if self.id != edge_id(self.source_id, self.target_id, self.kind, self.scope_key):
            raise ValueError("id must equal edge_id(source, target, kind, scope_key)")
        if self.kind in _PROV_REQUIRED and not self.prov_event_id:
            raise ValueError(f"{self.kind.value} requires prov_event_id")
        if self.resolution_status == "RESOLVED" and not self.resolution_event_id:
            raise ValueError("a RESOLVED contradiction needs resolution_event_id")
        if self.retracted_at is not None and self.retracted_at < self.asserted_at:
            raise ValueError("retracted_at precedes asserted_at")
        return self


@dataclass(frozen=True)
class EdgeKindShape:
    """Kind-scoped edge constraint. Never stored in ``EDGE_SHAPES``."""

    kind: EdgeKind
    valid_source_classes: tuple[AssuranceClass, ...]
    valid_target_classes: tuple[AssuranceClass, ...]
    requires_prov_event: bool
    symmetric: bool
    propagation: str  # HARD | SOFT | NONE | BLOCK — metadata consumed by CR-017
    same_class_target: bool = False


_C = AssuranceClass
_ARTIFACT_BRANCH = (_C.EVIDENCE, _C.CLAIM, _C.ABSTRACTION)
_ALL = tuple(AssuranceClass)
_REVISABLE = (*_ARTIFACT_BRANCH, _C.INSTRUCTION, _C.POLICY)
_CONTRADICTABLE = (_C.CLAIM, _C.ABSTRACTION, _C.INSTRUCTION, _C.POLICY)

ASSURANCE_EDGE_KIND_SHAPES: dict[EdgeKind, EdgeKindShape] = {
    s.kind: s
    for s in (
        EdgeKindShape(
            EdgeKind.DERIVED_FROM,
            (_C.CLAIM, _C.ABSTRACTION, _C.DECISION),
            _ARTIFACT_BRANCH,
            False,
            False,
            "HARD",
        ),
        EdgeKindShape(
            EdgeKind.SUPPORTED_BY,
            (_C.CLAIM, _C.ABSTRACTION),
            (_C.EVIDENCE, _C.CLAIM),
            False,
            False,
            "SOFT",
        ),
        EdgeKindShape(EdgeKind.CONTRADICTS, _CONTRADICTABLE, _CONTRADICTABLE, False, True, "BLOCK"),
        EdgeKindShape(
            EdgeKind.SUPERSEDES, _REVISABLE, _REVISABLE, True, False, "NONE", same_class_target=True
        ),
        EdgeKindShape(
            EdgeKind.CORRECTS, _REVISABLE, _REVISABLE, True, False, "SOFT", same_class_target=True
        ),
        EdgeKindShape(
            EdgeKind.COEXISTS_WITH,
            (_C.CLAIM, _C.ABSTRACTION),
            (_C.CLAIM, _C.ABSTRACTION),
            True,
            True,
            "NONE",
            same_class_target=True,
        ),
        EdgeKindShape(
            EdgeKind.GOVERNED_BY,
            (_C.DECISION, _C.ACTION),
            (_C.POLICY, _C.INSTRUCTION),
            False,
            False,
            "BLOCK",
        ),
        EdgeKindShape(EdgeKind.USED, (_C.PROVENANCE_EVENT,), _ALL, True, False, "NONE"),
        EdgeKindShape(
            EdgeKind.GENERATED,
            (_C.PROVENANCE_EVENT,),
            tuple(c for c in _ALL if c is not _C.PROVENANCE_EVENT),
            True,
            False,
            "NONE",
        ),
        EdgeKindShape(
            EdgeKind.INVALIDATES,
            (_C.PROVENANCE_EVENT,),
            tuple(c for c in _ALL if c not in (_C.PROVENANCE_EVENT, _C.AGENT)),
            True,
            False,
            "HARD",
        ),
    )
}


# ── node shapes derived from the models (one source of truth) ────────────────

_PROP_TYPE = {str: "str", int: "int", float: "float", bool: "bool", list: "list"}


def _node_shape_for(cls: AssuranceClass) -> NodeShape:
    model = MODEL_FOR_CLASS[cls]
    props = []
    for name, info in model.model_fields.items():
        if name in ("type", "label"):
            continue
        origin = getattr(info.annotation, "__origin__", info.annotation)
        props.append(
            PropertyConstraint(
                name=name,
                required=info.is_required(),
                prop_type=_PROP_TYPE.get(origin, "str"),
            )
        )
    return NodeShape(
        node_type=CLASS_TO_TYPE_KEY[cls],
        description=f"Assurance {cls.value} (CR-016); authoritative property assurance_type",
        properties=props,
        allow_extra_properties=True,
    )


ASSURANCE_NODE_SHAPES: tuple[NodeShape, ...] = tuple(_node_shape_for(c) for c in AssuranceClass)

_RELATES_TO_SHAPE = EdgeShape(
    edge_type="RELATES_TO",
    description="Assurance edge carrier; kind validated by validate_assurance_graph",
    allow_any_source=True,
    allow_any_target=True,
)


# ── registration (CR-016 §5.1) ───────────────────────────────────────────────


class AssuranceRegistrationError(GraqleError):
    """A mount or shape collides with an existing, different definition."""


@dataclass(frozen=True)
class RegistrationRecord:
    skipped: bool
    mounted: tuple[str, ...] = ()
    shapes: tuple[str, ...] = ()
    skipped_shapes: tuple[str, ...] = ()
    inputs_hash: str | None = None
    rule_id: str = "CR016.register"
    rule_version: str = ASSURANCE_SHAPE_VERSION
    config_version: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


def register_assurance_ontology(
    upper: UpperOntology, *, strict: bool = True, settings: Any | None = None
) -> RegistrationRecord:
    """Mount the assurance classes and shapes, only when ``GRAQLE_DAG_ENABLED`` is on.

    Flag off: returns ``skipped=True`` and mutates nothing. Flag on: every
    collision with a different existing definition raises
    :class:`AssuranceRegistrationError`, or, with ``strict=False``, is skipped
    and reported. An existing definition is never overwritten. Registration is
    idempotent.
    """
    from graqle.assurance.settings import (  # lazy: zero cost with the flag off
        config_version,
        is_dag_enabled,
        load_dag_settings,
    )

    if not is_dag_enabled():
        return RegistrationRecord(skipped=True)
    cfg_v = config_version(settings if settings is not None else load_dag_settings())

    hierarchy = upper.hierarchy
    for key, parent in ASSURANCE_HIERARCHY.items():
        if parent not in hierarchy:
            raise AssuranceRegistrationError(f"missing upper branch {parent}")
        if key in hierarchy and hierarchy[key] != parent:
            raise AssuranceRegistrationError(f"{key} already mounted under {hierarchy[key]}")

    registered: list[str] = []
    skipped: list[str] = []
    for shape in ASSURANCE_NODE_SHAPES:
        existing = NODE_SHAPES.get(shape.node_type)
        if existing is not None and existing is not shape and existing != shape:
            if strict:
                raise AssuranceRegistrationError(f"node shape {shape.node_type} already exists")
            skipped.append(shape.node_type)
            continue
        registered.append(shape.node_type)

    upper.extend(ASSURANCE_HIERARCHY)
    for shape in ASSURANCE_NODE_SHAPES:
        if shape.node_type in registered:
            register_node_shape(shape)
    notes: list[str] = []
    existing_edge = EDGE_SHAPES.get("RELATES_TO")
    if existing_edge is None:
        register_edge_shape(_RELATES_TO_SHAPE)
    elif existing_edge is not _RELATES_TO_SHAPE:
        notes.append("RELATES_TO edge shape already present; left unchanged")

    from graqle.assurance._hashing import inputs_hash  # lazy

    return RegistrationRecord(
        skipped=False,
        mounted=tuple(ASSURANCE_HIERARCHY),
        shapes=tuple(registered),
        skipped_shapes=tuple(skipped),
        inputs_hash=inputs_hash(
            {"hierarchy": dict(ASSURANCE_HIERARCHY), "shape_version": ASSURANCE_SHAPE_VERSION}
        ),
        config_version=cfg_v,
        notes=tuple(notes),
    )


# ── kind-aware validation (CR-016 §5.1) ──────────────────────────────────────


def validate_assurance_graph(graph_data: Mapping[str, Any]) -> ValidationReport:
    """``validate_graph`` plus assurance edge-kind and node-model checks.

    Links whose ``RELATES_TO`` has no ``kind``, or a kind that is not an
    assurance kind, are left alone (research-DB edges are not ours).
    """
    report = validate_graph(dict(graph_data))
    nodes = {n.get("id"): n for n in graph_data.get("nodes", [])}

    for link in graph_data.get("links", []):
        if link.get("relationship") != "RELATES_TO":
            continue
        props = link.get("properties") or {}
        kind_raw = props.get("kind")
        if kind_raw is None:
            continue
        try:
            kind = EdgeKind(kind_raw)
        except ValueError:
            continue
        shape = ASSURANCE_EDGE_KIND_SHAPES[kind]
        src = nodes.get(link.get("source")) or {}
        tgt = nodes.get(link.get("target")) or {}
        sc, tc = _class_of(src), _class_of(tgt)

        def _err(msg: str, _src: str = str(link.get("source", "")), _sc: Any = sc) -> None:
            report.violations.append(
                Violation(_src, _sc.value if _sc else "", "ERROR", msg, edge_type=kind.value)
            )

        if sc not in shape.valid_source_classes or tc not in shape.valid_target_classes:
            _err(f"{kind.value}: {_name(sc)}->{_name(tc)} not permitted")
        elif shape.same_class_target and sc is not tc:
            _err(f"{kind.value}: target must be the same class as the source")
        if shape.requires_prov_event and not props.get("prov_event_id"):
            _err(f"{kind.value} requires prov_event_id")
        for f in ("scope_key", "asserted_at"):
            if not props.get(f):
                _err(f"{kind.value} missing {f}")
        # PR-016b rule (c): an ordered edge needs an identity on both ends.
        if kind in (EdgeKind.SUPERSEDES, EdgeKind.CORRECTS):
            for side, node in (("source", src), ("target", tgt)):
                if not node.get("canonical_id"):
                    _err(f"{kind.value} requires canonical_id on the {side}")

    for n in nodes.values():
        if "assurance_type" not in n:
            continue
        cls = _class_of(n)
        if cls is None:
            report.violations.append(
                Violation(str(n.get("id", "")), "", "ERROR", "unknown assurance_type")
            )
            continue
        try:
            MODEL_FOR_CLASS[cls].model_validate(n)
        except ValidationError as exc:
            report.violations.append(
                Violation(str(n.get("id", "")), cls.value, "ERROR", _first_error(exc))
            )
    return report


def _class_of(node: Mapping[str, Any]) -> AssuranceClass | None:
    try:
        return AssuranceClass(node.get("assurance_type"))
    except ValueError:
        return None


def _name(c: AssuranceClass | None) -> str:
    return c.value if c else "<none>"


def _first_error(exc: ValidationError) -> str:
    e = exc.errors()[0]
    loc = ".".join(str(p) for p in e.get("loc", ()))
    return f"{loc}: {e.get('msg', 'invalid')}"[:200]


# ── bitemporal predicate (CR-016 §5.2) ───────────────────────────────────────


def covers(node: Mapping[str, Any], at: datetime, at_tx: datetime | None = None) -> bool:
    """True iff ``node`` is valid at ``at`` and asserted at ``at_tx`` (default ``at``).

    Both intervals are HALF-OPEN ``[start, end)`` per CR-016 §2.2, so at a
    supersession instant (old.valid_until == new.valid_from) exactly one
    version is valid. Naive datetimes are rejected rather than assumed UTC.
    """
    at_s = to_iso_utc(at)
    tx_s = to_iso_utc(at_tx if at_tx is not None else at)
    vf, vu = _check_iso_utc(node["valid_from"]), node.get("valid_until")
    aa, ra = _check_iso_utc(node["asserted_at"]), node.get("retracted_at")
    if vu is not None:
        _check_iso_utc(vu)
    if ra is not None:
        _check_iso_utc(ra)
    return vf <= at_s and (vu is None or at_s < vu) and aa <= tx_s and (ra is None or tx_s < ra)


def current_state_cypher_predicate(
    alias: str = "n", *, historical: bool = False, at_param: bool = False
) -> str:
    """Cypher WHERE fragment selecting current assurance nodes (CR-017 consumes it).

    Plain substrate nodes (no ``assurance_type``) always pass. The caller binds
    ``$now`` (or ``$at`` when ``at_param``) as a canonical ISO-UTC string.
    ``alias`` must be a Cypher identifier; it is validated, never interpolated
    from untrusted input.
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
        raise ValueError("alias must be a Cypher identifier")
    if historical:
        return "true"
    t = "$at" if at_param else "$now"
    a = alias
    return (
        f"({a}.assurance_type IS NULL OR ("
        f"{a}.lifecycle_status = 'ACTIVE' AND coalesce({a}.dirty, false) = false "
        f"AND {a}.valid_from <= {t} AND ({a}.valid_until IS NULL OR {t} < {a}.valid_until) "
        f"AND {a}.asserted_at <= {t} AND ({a}.retracted_at IS NULL OR {t} < {a}.retracted_at)))"
    )
