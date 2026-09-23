"""DAG-2026 gate outcomes (CR-012 §4.1).

The five outcomes a Decision Assurance Gate evaluation can return.

``GateOutcome`` is PRIVATE to :mod:`graqle.assurance`. It is deliberately NOT an
extension of :class:`graqle.governance.trace_schema.Decision`: the governance
package must never import the assurance package (CR-012 AC-21), and the two
vocabularies answer different questions. ``Decision`` records what a governance
gate did (PASS/BLOCK/WARN); ``GateOutcome`` records what the caller must do
next. A trace carries the outcome as a plain string via ``GateVerdictRef``.
"""

# -- graqle:intelligence --
# module: graqle.assurance.outcomes
# risk: LOW (impact radius: 0 modules -- new file, no existing callers)
# dependencies: enum
# constraints: never imported by graqle.governance.*
# -- /graqle:intelligence --

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

__all__ = ["GateOutcome", "OUTCOME_SEVERITY", "worst"]


class GateOutcome(str, Enum):
    """What the caller must do with the action the gate just evaluated.

    ``str``-valued so it serialises without a custom JSON encoder.
    """

    EXECUTE = "EXECUTE"
    REPLAN = "REPLAN"
    HOLD = "HOLD"
    REJECT = "REJECT"
    ESCALATE = "ESCALATE"

    @property
    def terminal(self) -> bool:
        """True when the outcome ends the decision loop for this action.

        ``REJECT`` and ``ESCALATE`` are terminal: the action is refused, or it
        has left the automated path for a human. ``REPLAN`` is explicitly NOT
        terminal -- it is a retry outcome that re-enters the gate with a new
        candidate, and CR-015's circuit breaker (not this flag) is what stops
        an unproductive replan loop. ``HOLD`` is not terminal either: it waits
        on recomputation and is re-evaluated.
        """
        return self in (GateOutcome.REJECT, GateOutcome.ESCALATE)


#: Severity order used by CR-015 when composing multiple signals (worst wins).
#: The ordering is by distance from proceeding, not by how bad the underlying
#: failure is: ESCALATE ranks below REJECT because a human may still authorise
#: the action, whereas REJECT is final.
OUTCOME_SEVERITY: dict[GateOutcome, int] = {
    GateOutcome.EXECUTE: 0,
    GateOutcome.REPLAN: 1,
    GateOutcome.HOLD: 2,
    GateOutcome.ESCALATE: 3,
    GateOutcome.REJECT: 4,
}


def worst(outcomes: Iterable[GateOutcome]) -> GateOutcome:
    """Return the highest-severity outcome (worst wins).

    NOTE: the result may be NON-TERMINAL. ``worst([HOLD, HOLD])`` is ``HOLD``,
    whose :attr:`GateOutcome.terminal` is ``False`` -- a caller using
    ``worst(...).terminal`` as a halt condition will not halt, which is correct
    (a HOLD is re-evaluated) but easy to misread. Use :func:`worst_terminal`
    when you specifically need the worst terminal outcome.

    Raises:
        ValueError: if ``outcomes`` is empty. A gate that produced no outcome
            at all is a programming error, not an implicit EXECUTE -- returning
            a default here would be a fail-open path.
    """
    ranked = sorted(outcomes, key=lambda o: OUTCOME_SEVERITY[o], reverse=True)
    if not ranked:
        raise ValueError("worst() requires at least one GateOutcome")
    return ranked[0]


def worst_terminal(outcomes: Iterable[GateOutcome]) -> GateOutcome | None:
    """Return the highest-severity TERMINAL outcome, or ``None`` if none is.

    Companion to :func:`worst` for callers whose control flow branches on
    "does this end the decision loop?" rather than "how bad is it?".
    """
    terminal = [o for o in outcomes if o.terminal]
    if not terminal:
        return None
    return worst(terminal)
