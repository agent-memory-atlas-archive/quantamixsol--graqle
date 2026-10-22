"""Reasoning-support provider (CR-014 section 5.3).

Partial signal: DRACE pillar presence and the observer's activation confidence.
Activation confidence originates from model rounds, so a value derived from it is
``probabilistic`` and MUST carry the measured inter-run variance (I-CV-2); a
missing variance fails the dimension closed rather than inventing one.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.reasoning
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.confidence_vector
# constraints: deterministic given inputs
# -- /graqle:intelligence --

from graqle.assurance.confidence_vector import (
    Availability,
    Candidate,
    EvaluationContext,
    ProviderSignal,
)
from graqle.assurance.providers._common import not_available, signal_source

__all__ = ["ReasoningSupportProvider", "f_rsn"]

_PILLARS = ("dependency", "reasoning", "auditability", "constraint", "explainability")


def f_rsn(presence_ratio: float | None, activation: float | None) -> float:
    """Mean of the signals that exist; at least one is required."""
    parts = [v for v in (presence_ratio, activation) if v is not None]
    if not parts:
        raise ValueError("no reasoning signal")
    return sum(parts) / len(parts)


class ReasoningSupportProvider:
    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        drace = ctx.drace_score
        act = ctx.activation_confidence
        if drace is None and act is None:
            return not_available("provider=reasoning_support", "drace=absent", "activation=absent")
        presence = (
            sum(1 for p in _PILLARS if getattr(drace, p) > 0) / len(_PILLARS)
            if drace is not None
            else None
        )
        raw = f_rsn(presence, act)
        payload = {"presence_ratio": presence, "activation_confidence": act}
        probabilistic = act is not None
        return ProviderSignal(
            availability=Availability.AVAILABLE,
            raw=raw,
            probabilistic=probabilistic,
            variance=ctx.activation_variance if probabilistic else None,
            inputs=payload,
            sources=(
                signal_source(
                    "reasoning.drace_activation",
                    "graqle.intelligence.governance.drace",
                    payload,
                    probabilistic=probabilistic,
                ),
            ),
            decisive_conditions=(
                f"drace={'present' if drace is not None else 'absent'}",
                f"activation={'present' if act is not None else 'absent'}",
            ),
        )
