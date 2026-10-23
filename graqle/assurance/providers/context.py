"""Context-fit provider: instrumentation interface (CR-014 section 5.3).

Interface: ``ContextFitScorer.score(candidate, decision_context) -> (fit,
probabilistic, variance)``. With no scorer configured the dimension is
``NOT_AVAILABLE``.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.context
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.providers._common
# constraints: stub unless a scorer is injected
# -- /graqle:intelligence --

from graqle.assurance.confidence_vector import (
    Availability,
    Candidate,
    EvaluationContext,
    ProviderSignal,
)
from graqle.assurance.providers._common import not_available, signal_source

__all__ = ["ContextFitProvider"]


class ContextFitProvider:
    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        scorer = ctx.context_fit_scorer
        if scorer is None:
            return not_available("provider=context_fit.stub")
        fit, probabilistic, variance = scorer.score(candidate, ctx.decision_context)
        payload = {"fit": fit, "probabilistic": probabilistic, "variance": variance}
        return ProviderSignal(
            availability=Availability.AVAILABLE,
            raw=fit,
            probabilistic=probabilistic,
            variance=variance,
            inputs=payload,
            sources=(
                signal_source(
                    "assurance.context_fit.scorer",
                    "graqle.assurance.providers.context",
                    payload,
                    probabilistic=probabilistic,
                ),
            ),
            decisive_conditions=("provider=context_fit.scorer",),
        )
