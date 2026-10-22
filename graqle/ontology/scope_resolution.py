"""DAG-2026 identity and scope resolution before merge (CR-016 §5.4, PR-016a).

Lifecycle rule L2: two ACTIVE nodes may share a canonical identity only if
they live in different scopes. Before any merge, :func:`resolve_identity`
decides CREATE / MERGE_INTO / COEXIST / HOLD. The merge itself stays in
``scanner.dedup.merge.MergeEngine``; HOLD and COEXIST go to CR-017's
resolution handlers.

Which node fields form a scope is PRIVATE operator configuration. This
module ships only the algorithm: callers pass ``fields`` (loaded from private
config), and nothing here names or defaults them.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.scope_resolution
# risk: LOW (impact radius: 0 existing callers -- CR-016b/017 consume it)
# dependencies: graqle.scanner.dedup.{canonical,contradictions,merge},
#   graqle.assurance.{_hashing,settings} (lazy)
# constraints: scope fields and merge priorities are caller-supplied private config
# -- /graqle:intelligence --
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from graqle.scanner.dedup.canonical import compute_canonical_id
from graqle.scanner.dedup.contradictions import _source_type

__all__ = [
    "IdentityDecision",
    "ScopeIndex",
    "ScopeKey",
    "assurance_canonical_id",
    "compute_scope_key",
    "resolve_identity",
]

RULE_ID = "CR016.identity"
RULE_VERSION = "1"
_UNRANKED = 10

#: Identity fields per assurance class, used when the dedup canonicaliser
#: does not cover a node (CR-016 §5.4). PUBLIC: these are model field names.
_CANONICAL_KEYS: dict[str, tuple[str, ...]] = {
    "Claim": ("subject", "predicate", "object"),
    "Evidence": ("source", "canonical_hash"),
    "Policy": ("policy_id", "version"),
    "Instruction": ("instruction_id",),
    "Abstraction": ("method", "inputs"),
    "Decision": ("decision_id",),
    "Action": ("action_id",),
    "Agent": ("agent_id",),
    "ProvenanceEvent": ("event_id",),
}


def _canon_sha256(record: Mapping[str, Any]) -> str:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return hashlib.sha256(canon(dict(record))).hexdigest()


@dataclass(frozen=True)
class ScopeKey:
    """``value`` = SHA-256 of the canonical scope tuple. ``fields`` is private config."""

    value: str
    fields: tuple[str, ...] = field(repr=False)

    @property
    def inputs_hash(self) -> str:
        return "sha256:" + self.value


def _norm(value: Any) -> Any:
    """Normalise one scope component: strings are stripped; JSON-native values pass."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    return value


def compute_scope_key(node: Mapping[str, Any], fields: Sequence[str]) -> ScopeKey:
    """Scope key over ``fields`` (in the given order), read from the node or its properties."""
    if not fields:
        raise ValueError("scope fields must be configured (non-empty)")
    props = node.get("properties") or {}
    scope = {f: _norm(node[f] if f in node else props.get(f)) for f in fields}
    return ScopeKey(value=_canon_sha256(scope), fields=tuple(fields))


def assurance_canonical_id(node: Mapping[str, Any]) -> str:
    """Canonical id for assurance nodes the dedup canonicaliser does not cover."""
    cls = node.get("assurance_type")
    if cls not in _CANONICAL_KEYS:
        raise ValueError(f"no canonical identity rule for assurance_type {cls!r}")
    return _canon_sha256({"class": cls, **{k: node.get(k) for k in _CANONICAL_KEYS[cls]}})


class ScopeIndex(Protocol):
    def lookup(self, canonical_id: str) -> Sequence[Mapping[str, Any]]:
        """ACTIVE nodes with this canonical id (each with ``id`` and ``scope_key``)."""

    def user_decision(self, a_id: str, b_id: str) -> bool | None:
        """Stored user verdict on whether two nodes are the same; ``None`` if none."""


Action = Literal["CREATE", "MERGE_INTO", "COEXIST", "HOLD"]


@dataclass(frozen=True)
class IdentityDecision:
    action: Action
    target_id: str | None
    canonical_id: str
    scope_key: str
    reason: str
    inputs_hash: str
    config_version: str
    rule_id: str = RULE_ID
    rule_version: str = RULE_VERSION


def resolve_identity(
    candidate: Mapping[str, Any],
    index: ScopeIndex,
    priority: Mapping[str, int],
    *,
    fields: Sequence[str],
    settings: Any,
) -> IdentityDecision:
    """Decide how ``candidate`` relates to existing nodes before any merge.

    Deterministic: when several nodes match, the one with the smallest id is
    the target, whatever order the index returns them in.
    """
    from graqle.assurance.settings import config_version  # lazy

    cfg_v = config_version(settings)
    cid = compute_canonical_id(dict(candidate)) or assurance_canonical_id(candidate)
    sk = compute_scope_key(candidate, fields).value
    ih = "sha256:" + _canon_sha256({"cid": cid, "sk": sk, "src": _source_type(dict(candidate))})

    def decide(action: Action, target: str | None, reason: str) -> IdentityDecision:
        return IdentityDecision(action, target, cid, sk, reason, ih, cfg_v)

    matches = sorted(index.lookup(cid), key=lambda m: str(m["id"]))
    if not matches:
        return decide("CREATE", None, "no canonical match")
    same_scope = [m for m in matches if m.get("scope_key") == sk]
    if not same_scope:
        return decide("COEXIST", str(matches[0]["id"]), "canonical match in a different scope")
    target = same_scope[0]
    if index.user_decision(str(target["id"]), str(candidate["id"])) is False:
        return decide("CREATE", None, "user rejected merge")
    rank_c = priority.get(_source_type(dict(candidate)), _UNRANKED)
    rank_t = priority.get(_source_type(dict(target)), _UNRANKED)
    if rank_c < rank_t:
        return decide("MERGE_INTO", str(target["id"]), "candidate outranks target")
    if rank_c > rank_t:
        return decide("MERGE_INTO", str(target["id"]), "target outranks candidate")
    return decide("HOLD", str(target["id"]), "equal rank; needs user or CR-017 resolution")
