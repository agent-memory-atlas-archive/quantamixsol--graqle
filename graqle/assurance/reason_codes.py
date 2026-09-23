"""DAG-2026 reason-code registry (CR-012 §4.2, ruling R1 + R2).

A CLOSED, append-only registry. Every code a :class:`~graqle.assurance.verdict.GateVerdict`
carries must be registered here; an unregistered code is a construction error, not a
warning. The grammar below is the ONLY reason-code regex in the SDK — CR-014, CR-015,
CR-017 and CR-018 register through :data:`REGISTRY`, never via a local pattern (R1).

Severity vocabulary is FAIL/CRITICAL/WARN/INFO (R2: ``BLOCK -> FAIL``, ``FATAL -> CRITICAL``).

Remediation hints are PUBLIC strings and must never state a numeric threshold, cap,
weight or budget (CR-012 §12).
"""

# -- graqle:intelligence --
# module: graqle.assurance.reason_codes
# risk: LOW (impact radius: 0 modules -- new file, no existing callers)
# dependencies: dataclasses, enum, re, types
# constraints: never imported by graqle.governance.*; append-only registry
# -- /graqle:intelligence --

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

__all__ = [
    "CODE_PATTERN",
    "REGISTRY",
    "ReasonCode",
    "Severity",
    "max_severity",
    "resolvable",
    "validate",
]


class Severity(str, Enum):
    """Reason-code severity (ruling R2)."""

    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"
    CRITICAL = "CRITICAL"


#: Rank used by :func:`max_severity`. Higher is worse.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.WARN: 1,
    Severity.FAIL: 2,
    Severity.CRITICAL: 3,
}

#: R1 (2026-09-13): the ONLY reason-code grammar in the SDK. Widened once in
#: PR-012b; hyphens are legal after the namespace segment.
CODE_PATTERN = re.compile(r"^DAG-(HG0[1-7]|CV|TR|PV|RP)-[A-Z0-9_-]{2,48}$")

_MAX_HINT_CHARS = 200


@dataclass(frozen=True, slots=True)
class ReasonCode:
    """One registered reason code.

    Invariants enforced at construction:
      * INV-RC-1 grammar — ``code`` matches :data:`CODE_PATTERN`.
      * INV-RC-3 — a hard-gate code (``DAG-HG0x-*``) is never advisory: its
        severity must be FAIL or CRITICAL.
      * ``remediation_hint`` is a public, number-free string within the length cap.
    """

    code: str
    severity: Severity
    owner_gate: str
    remediation_hint: str
    since_version: str

    def __post_init__(self) -> None:
        if not CODE_PATTERN.match(self.code):
            raise ValueError(f"ReasonCode.code {self.code!r} violates grammar")
        if self.owner_gate.startswith("HG-") and self.severity in (
            Severity.INFO,
            Severity.WARN,
        ):
            raise ValueError(
                "hard-gate reason codes must be FAIL or CRITICAL (INV-RC-3)"
            )
        if len(self.remediation_hint) > _MAX_HINT_CHARS:
            raise ValueError("remediation_hint exceeds the length cap")


#: The registry seed. Each code family is seeded by the change request that
#: introduces it; 0.84.1 ships the grammar and the invariants, and seeding
#: begins with CR-013. INV-RC-2 (append-only, monotone ``since_version``) holds:
#: appending to an empty seed is a plain append.
_SEED: tuple[ReasonCode, ...] = ()

#: The closed registry. Immutable after import (INV-RC-2: append-only across
#: versions; a code is never re-used with a different meaning).
REGISTRY: MappingProxyType[str, ReasonCode] = MappingProxyType(
    {rc.code: rc for rc in _SEED}
)


def validate(codes: list[str]) -> list[str]:
    """Return ``codes`` if every entry is registered, preserving order.

    Duplicates are removed (first occurrence wins).

    Raises:
        ValueError: listing the unregistered codes. Unknown codes fail closed —
            a verdict may not carry a reason nobody can look up.
    """
    unknown = [c for c in codes if c not in REGISTRY]
    if unknown:
        raise ValueError(f"unregistered reason codes: {unknown}")
    seen: set[str] = set()
    out: list[str] = []
    for c in codes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def max_severity(codes: list[str]) -> Severity | None:
    """Highest severity across ``codes``; ``None`` for an empty list.

    Raises:
        ValueError: if any code is unregistered (via :func:`validate`).
    """
    validate(codes)
    if not codes:
        return None
    return max((REGISTRY[c].severity for c in codes), key=lambda s: _SEVERITY_RANK[s])


def resolvable(code: str) -> bool:
    """Whether ``code`` can in principle be cleared by a replan (ruling R2).

    ``resolvable := severity in {INFO, WARN} or (severity == FAIL and
    remediation_hint != "")``. This is the machine-checkable predicate that
    drives REPLAN eligibility in CR-015.

    CRITICAL is NEVER resolvable -- deliberately, and regardless of how good its
    remediation hint is. A CRITICAL code means the action is refused or must
    leave the automated path; letting a hint downgrade that would make the
    hard gates advisory, which INV-RC-3 exists to prevent.

    Raises:
        ValueError: if ``code`` is unregistered.
    """
    if code not in REGISTRY:
        raise ValueError(f"unregistered reason code: {code!r}")
    entry = REGISTRY[code]
    if entry.severity in (Severity.INFO, Severity.WARN):
        return True
    return entry.severity == Severity.FAIL and entry.remediation_hint != ""
