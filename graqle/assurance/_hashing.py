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


_SCALARS = frozenset({str, bool, type(None)})
_JSON_ENCODE = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False).encode


_SCALARS_AND_FLOAT = _SCALARS | {float}


def _plain_float(x: float) -> bool:
    """Finite, non-integral float whose ``repr`` is plain decimal.

    For these the Python ``repr`` and the ECMAScript number text of RFC 8785
    coincide; integral values (``1.0`` vs ``1``), exponent forms, ``-0.0`` and
    non-finite values go to the full canonicaliser.
    """
    r = repr(x)
    return "e" not in r and "n" not in r and not r.endswith(".0")


def _simple_tree(obj: Any) -> bool:
    """True when ``obj`` holds only exact dict(str keys)/list/str/bool/None/float nodes.

    Anything else (tuples, numbers, subclasses, non-str keys) is left to the
    full canonicaliser, which validates or rejects it.
    """
    stack = [obj]
    while stack:
        node = stack.pop()
        if type(node) is list:
            kinds = set(map(type, node))
            if kinds <= _SCALARS:
                continue
            if kinds <= _SCALARS_AND_FLOAT:
                if all(_plain_float(x) for x in node if type(x) is float):
                    continue
                return False
            stack.extend(node)
        elif type(node) is dict:
            if not set(map(type, node)) <= {str}:
                return False
            stack.extend(node.values())
        elif type(node) is float:
            if not _plain_float(node):
                return False
        elif type(node) not in _SCALARS:
            return False
    return True


def _fast_canon(projection: dict[str, Any]) -> bytes | None:
    """JCS bytes for a simple, escape-free projection, else ``None``.

    With only str/bool/None leaves and no character needing an escape (the
    ASCII-escaped output holds no backslash), the C JSON encoder emits exactly
    the RFC 8785 bytes: same separators, same key order (ASCII code points
    equal UTF-16 code units), same literals.
    """
    if not _simple_tree(projection):
        return None
    text = _JSON_ENCODE(projection)
    if "\\" in text or not text.isascii():
        return None
    return text.encode("ascii")


def inputs_hash(projection: dict[str, Any]) -> str:
    """``"sha256:<hex>"`` over the JCS-canonical bytes of ``projection``."""
    data = _fast_canon(projection)
    if data is None:
        from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

        data = canon(projection)
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
