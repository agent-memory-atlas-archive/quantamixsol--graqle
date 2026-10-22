"""DAG-2026 hard-gate input hashing (CR-013 §5.1, PR-013a).

``inputs_hash`` is the determinism anchor of every hard-gate result: SHA-256
over the RFC 8785 (JCS) canonical bytes of a gate's *projection* — the
allowlisted slice of :class:`~graqle.assurance.hard_gates.GateContext` the
gate's predicate reads.

Rules every projection must follow (reviewer checklist, CR-013 §7 PR-013a):

* JSON-native values only. ``canon`` rejects tuples, datetimes, sets and
  non-finite floats, so projections emit lists and ISO strings. A NaN or
  infinite value raises, which fails the gate closed.
* List-valued fields are de-duplicated and ordered with :func:`sorted_ids` or
  :func:`sorted_records`, so permuting the context never changes the hash
  (P-ORDER) and ``k`` copies of one source hash as one (P-CORR).
* Configured threshold values are never projected. ``config_version``
  already commits to them without revealing them.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance._hashing
# risk: LOW (impact radius: 1 module -- graqle.assurance.hard_gates)
# dependencies: hashlib, json, graqle.governance.tamper_evidence.canonicalize (lazy)
# constraints: never imported by graqle.governance.*; canonicaliser loaded lazily
#   so importing graqle.assurance stays side-effect free with the flag off
# -- /graqle:intelligence --
import hashlib
import json
from collections.abc import Iterable
from typing import Any

__all__ = ["inputs_hash", "sorted_ids", "sorted_records"]


def inputs_hash(projection: dict[str, Any]) -> str:
    """``"sha256:<hex>"`` over the JCS-canonical bytes of ``projection``."""
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return "sha256:" + hashlib.sha256(canon(projection)).hexdigest()


def sorted_ids(values: Iterable[str]) -> list[str]:
    """De-duplicate and order identifiers (P-CORR, P-ORDER)."""
    return sorted(set(values))


def sorted_records(records: Iterable[list[Any]]) -> list[list[Any]]:
    """De-duplicate and order JSON-native records.

    Ordering is by the canonical JSON text of each record, never by Python
    comparison, so records mixing ``None`` with numbers or strings sort
    deterministically instead of raising ``TypeError``.
    """
    unique = {json.dumps(r, sort_keys=True, separators=(",", ":")): r for r in records}
    return [unique[k] for k in sorted(unique)]
