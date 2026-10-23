"""DAG-2026 source identity and dependency-aware independence (CR-014 sections 2.4, 5.4).

Corroboration counts INDEPENDENT sources, not evidence records, so duplicating an
item never raises confidence (I-CV-7). Independence is the number of connected
components of the dependency graph over the evidence set, computed with union-find.

Dependency clauses (an edge joins two evidence items when any holds):

* same source identity (same bytes from the same origin, at any locator);
* a supplied derivation pair (DERIVED_FROM / SUPPORTED_BY closure);
* same origin authority within the configured same-bundle window;
* equal, non-NONE generator identity (section 2.4.1 amendment).

Differing generator identities are NOT evidence of independence: the count measures
*detected* independence only.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.source_identity
# risk: LOW (impact radius: 0 modules -- new file, no existing callers)
# dependencies: hashlib, dataclasses, pydantic, graqle.assurance._hashing (lazy canon)
# constraints: never imported by graqle.governance.*; no tuned values
# -- /graqle:intelligence --

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

__all__ = [
    "EvidenceRef",
    "GeneratorRef",
    "IndependenceResult",
    "generator_identity",
    "independent_source_count",
    "normalise_locator",
    "normalise_model_family",
    "source_identity",
]

_HASH_PREFIX_CHARS = 16
_VERSION_SUFFIX = re.compile(r"[-_.@:]?v?\d+([._-]\d+)*$")


class GeneratorRef(BaseModel):
    """Who produced a model-generated evidence item (section 2.4.1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_family: str
    prompt_template_id: str
    decoding_class: str


class EvidenceRef(BaseModel):
    """One evidence item as seen by the corroboration and temporal providers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    origin_class: str
    origin_authority_id: str
    locator: str
    content_sha256: str
    source_class: str = ""
    asserted_at_unix: float | None = None
    generator: GeneratorRef | None = None
    #: ``False`` marks an item whose source identity could not be established.
    identity_known: bool = True


@dataclass(frozen=True, slots=True)
class IndependenceResult:
    """Outcome of :func:`independent_source_count`."""

    count: int
    #: True when at least one merge was caused ONLY by generator correlation.
    generator_collapsed: bool
    #: True when some item had ``identity_known`` False.
    identity_unresolved: bool


def _canon_sha256(obj: dict[str, str]) -> str:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return hashlib.sha256(canon(obj)).hexdigest()


def normalise_locator(locator: str) -> str:
    """Case-fold, strip query/fragment and trailing slashes."""
    parts = urlsplit(locator.strip())
    base = (parts.netloc + parts.path) if parts.netloc else parts.path
    scheme = f"{parts.scheme}://" if parts.netloc and parts.scheme else ""
    return (scheme + base).rstrip("/").lower()


def source_identity(e: EvidenceRef) -> str:
    """sha256 over the canonical origin descriptor (section 2.4)."""
    return _canon_sha256(
        {
            "origin_class": e.origin_class,
            "origin_authority_id": e.origin_authority_id,
            "canonical_locator": normalise_locator(e.locator),
            "content_hash_prefix": e.content_sha256[:_HASH_PREFIX_CHARS],
        }
    )


def _content_identity(e: EvidenceRef) -> tuple[str, str, str]:
    """Locator-free identity: the same bytes at two locators are one source."""
    return (e.origin_class, e.origin_authority_id, e.content_sha256[:_HASH_PREFIX_CHARS])


def normalise_model_family(family: str) -> str:
    """Strip point-version suffixes so two snapshots of one family compare equal."""
    return _VERSION_SUFFIX.sub("", family.strip().lower())


def generator_identity(e: EvidenceRef) -> str | None:
    """Generator identity, or ``None`` when the item was not model-produced.

    ``None`` is not an equivalence class: two non-model items never merge on it.
    """
    g = e.generator
    if g is None:
        return None
    return _canon_sha256(
        {
            "model_family": normalise_model_family(g.model_family),
            "prompt_template_id": g.prompt_template_id,
            "decoding_class": g.decoding_class,
        }
    )


class _UnionFind:
    def __init__(self, n: int) -> None:
        self._parent = list(range(n))

    def find(self, i: int) -> int:
        while self._parent[i] != i:
            self._parent[i] = self._parent[self._parent[i]]
            i = self._parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        ri, rj = self.find(i), self.find(j)
        if ri != rj:
            self._parent[max(ri, rj)] = min(ri, rj)

    def components(self) -> int:
        return len({self.find(i) for i in range(len(self._parent))})


def independent_source_count(
    evidence: Sequence[EvidenceRef],
    dependency_pairs: Iterable[tuple[str, str]],
    same_bundle_seconds: int,
) -> IndependenceResult:
    """Number of independent sources among ``evidence`` (union-find, section 5.4).

    ``dependency_pairs`` holds ``(evidence_id, evidence_id)`` derivation pairs; pairs
    naming an unknown id are ignored (they cannot relate items in this set).
    ``same_bundle_seconds`` must be positive; the caller (settings) enforces it and
    this function refuses a non-positive window rather than treating it as "off".
    """
    if same_bundle_seconds <= 0:
        raise ValueError("same_bundle_seconds must be positive")
    n = len(evidence)
    idx = {e.id: i for i, e in enumerate(evidence)}

    base = _UnionFind(n)
    first_by_content: dict[tuple[str, str, str], int] = {}
    for i, e in enumerate(evidence):
        key = _content_identity(e)
        if key in first_by_content:
            base.union(i, first_by_content[key])
        else:
            first_by_content[key] = i
    for a, b in dependency_pairs:
        if a in idx and b in idx:
            base.union(idx[a], idx[b])
    for i, a in enumerate(evidence):
        if a.asserted_at_unix is None:
            continue
        for j in range(i + 1, n):
            b = evidence[j]
            if (
                b.asserted_at_unix is not None
                and a.origin_authority_id == b.origin_authority_id
                and abs(a.asserted_at_unix - b.asserted_at_unix) <= same_bundle_seconds
            ):
                base.union(i, j)

    full = _UnionFind(n)
    full._parent = list(base._parent)
    first_by_gen: dict[str, int] = {}
    for i, e in enumerate(evidence):
        gid = generator_identity(e)
        if gid is None:
            continue
        if gid in first_by_gen:
            full.union(i, first_by_gen[gid])
        else:
            first_by_gen[gid] = i

    return IndependenceResult(
        count=full.components(),
        generator_collapsed=full.components() < base.components(),
        identity_unresolved=any(not e.identity_known for e in evidence),
    )
