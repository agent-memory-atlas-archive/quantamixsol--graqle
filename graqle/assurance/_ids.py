"""Identifier and time helpers for the CR-018 recorder (PR-018b).

Kept apart from ``provenance_recorder.py`` so that module stays free of
numeric literals (AC-14: only 0, 1, 32 and 64 are allowed there).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance._ids
# risk: LOW (new module; pure helpers)
# dependencies: stdlib only
# constraints: no I/O; no graqle imports
# -- /graqle:intelligence --
import secrets
import time
import uuid
from datetime import datetime, timezone

__all__ = ["NS_DAG", "SYSTEM_KEYS_TRAJECTORY", "new_id", "rfc3339", "utcnow"]

#: Namespace for ``uuid5(NS_DAG, event_id)`` Committer trace ids (deterministic).
NS_DAG = uuid.uuid5(uuid.NAMESPACE_URL, "urn:graqle:dag:provenance:v1")

#: Fixed trajectory that carries ``key_rotated`` events (valid ``trj_`` ULID body).
SYSTEM_KEYS_TRAJECTORY = "trj_" + "0" * 26

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_TIME_BITS = 48
_RAND_BITS = 80
_CHARS = 26
_BITS_PER_CHAR = 5
_MS_PER_S = 1000


def new_id(prefix: str) -> str:
    """``<prefix>_<26-char Crockford ULID>`` (``evt``, ``dec``, ``trj``)."""
    millis = time.time_ns() // (_MS_PER_S * _MS_PER_S)
    value = ((millis & ((1 << _TIME_BITS) - 1)) << _RAND_BITS) | secrets.randbits(_RAND_BITS)
    chars = [
        _CROCKFORD[(value >> (_BITS_PER_CHAR * i)) & ((1 << _BITS_PER_CHAR) - 1)]
        for i in range(_CHARS)
    ]
    return prefix + "_" + "".join(reversed(chars))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(moment: datetime) -> str:
    """RFC 3339 UTC with a trailing ``Z`` (the only form the event accepts)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
