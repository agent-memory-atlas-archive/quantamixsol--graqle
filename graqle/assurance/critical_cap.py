"""DAG-2026 critical-failure cap (CR-013, PR-013c).

Applied AFTER the hard gates and BEFORE any downstream projection (CR-014) or
outcome mapping (CR-015). It only bounds a number: it never chooses an outcome.

Invariants (CR-013 §2.2), with ``H`` = all seven hard gates passed::

    cap(A, H) = A                  if H
              = min(A, CAP_VALUE)  otherwise

* INV-CAP-1 idempotent: ``cap(cap(A, H), H) == cap(A, H)``.
* INV-CAP-2 monotone:   ``A <= A'`` implies ``cap(A, H) <= cap(A', H)``.
* INV-CAP-3 bound:      a failed gate implies ``cap(A, H) <= CAP_VALUE < 1``.

Confidentiality rule (CR-013 §12): the cap value reaches this module only
through a frozen :class:`~graqle.assurance.settings.DagSettings`. It is never
logged, never a field of :class:`CapResult` and never part of ``repr``. Note
that ``output_value`` equals the cap whenever a larger aggregate is bounded;
that is inherent to ``min`` and is the one place the value is observable.

Fail-closed additions beyond the pseudo-code in §5.9 (each has a test):

* a malformed aggregate (not a finite number in [0, 1], or a bool) is treated
  as the worst value, 0.0;
* a result set that is not exactly one result per hard gate (empty, partial,
  duplicated or unknown ids) is treated as a failed evaluation, so an empty
  tuple can never leave an aggregate uncapped.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.critical_cap
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015 later)
# dependencies: pydantic, graqle.assurance.{hard_gates,reason_codes,settings}
# constraints: never imported by graqle.governance.*; never logs or serialises
#   the cap value (CR-013 AC-15)
# -- /graqle:intelligence --
import math
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from graqle.assurance.hard_gates import GATE_ORDER, HardGateResult, decisive_rule
from graqle.assurance.reason_codes import validate as _validate_codes
from graqle.assurance.settings import ConfigurationError, DagSettings

__all__ = ["CapResult", "CriticalFailureCap", "apply_cap"]

_CAP_APPLIED = "DAG-RP-CAP_APPLIED"
_EVALUATION_ERROR = "DAG-RP-EVALUATION_ERROR"


class CapResult(BaseModel):
    """Outcome of one cap application. Deliberately carries no cap field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_value: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    output_value: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    cap_applied: bool
    #: First failed gate in G order; ``None`` when none failed or the result
    #: set was incomplete.
    decisive_rule: str | None = None
    reason_codes: tuple[str, ...] = ()

    @field_validator("reason_codes")
    @classmethod
    def _codes_registered(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_codes(list(value)))

    @model_validator(mode="after")
    def _consistency(self) -> CapResult:
        if self.output_value > self.input_value:
            raise ValueError("the cap never raises a value")
        if self.cap_applied:
            if _CAP_APPLIED not in self.reason_codes:
                raise ValueError("an applied cap carries DAG-RP-CAP_APPLIED")
        elif self.reason_codes or self.decisive_rule is not None:
            raise ValueError("an unapplied cap carries no rule or reason codes")
        return self


def _sanitise(aggregate: object) -> float:
    """A finite number in [0, 1], else 0.0 (worst value, fail-closed)."""
    # bool is a subclass of int: reject it explicitly so True never reads as 1.0.
    if isinstance(aggregate, bool) or not isinstance(aggregate, int | float):
        return 0.0
    value = float(aggregate)
    if math.isnan(value) or not 0.0 <= value <= 1.0:
        return 0.0
    return value


def _ordered_complete(results: tuple[HardGateResult, ...]) -> tuple[HardGateResult, ...] | None:
    """The results in G order, or ``None`` unless there is exactly one per gate."""
    if not all(isinstance(r, HardGateResult) for r in results):
        return None
    by_id = {r.rule_id: r for r in results}
    if len(results) != len(GATE_ORDER) or set(by_id) != set(GATE_ORDER):
        return None
    return tuple(by_id[rule_id] for rule_id in GATE_ORDER)


class CriticalFailureCap:
    """Bounds an aggregate once any hard gate has failed."""

    __slots__ = ("_cap",)

    def __init__(self, settings: DagSettings) -> None:
        if settings.cap_value is None:
            raise ConfigurationError("GRAQLE_DAG_CAP_VALUE required when DAG enabled")
        self._cap: float = float(settings.cap_value)

    def __repr__(self) -> str:
        return "CriticalFailureCap()"

    def apply(self, aggregate: float, results: Iterable[HardGateResult]) -> CapResult:
        value = _sanitise(aggregate)
        ordered = _ordered_complete(tuple(results))
        if ordered is None:
            # Incomplete evidence of the gates is a failed evaluation, never a pass.
            return CapResult(
                input_value=value,
                output_value=min(value, self._cap),
                cap_applied=True,
                decisive_rule=None,
                reason_codes=(_EVALUATION_ERROR, _CAP_APPLIED),
            )
        failed = [r for r in ordered if not r.passed]
        if not failed:
            return CapResult(input_value=value, output_value=value, cap_applied=False)
        codes = tuple(dict.fromkeys(c for r in failed for c in r.reason_codes if c != _CAP_APPLIED))
        return CapResult(
            input_value=value,
            output_value=min(value, self._cap),
            cap_applied=True,
            decisive_rule=decisive_rule(ordered),
            reason_codes=(*codes, _CAP_APPLIED),
        )


def apply_cap(
    aggregate: float, results: Iterable[HardGateResult], settings: DagSettings
) -> CapResult:
    """Convenience wrapper: ``CriticalFailureCap(settings).apply(...)``."""
    return CriticalFailureCap(settings).apply(aggregate, results)
