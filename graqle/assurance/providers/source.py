"""Source-reliability provider: instrumentation interface only (CR-014 section 5.3).

Interface: ``SourceReputationRegistry.lookup(source_identity) -> SourceReputation``.
Until a scoring rule is wired the dimension is ``NOT_AVAILABLE``, with or without a
registry; the projection then refuses admission for classes where it is mandatory.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.source
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.providers._common
# constraints: stub; never returns a value
# -- /graqle:intelligence --

from graqle.assurance.confidence_vector import Candidate, EvaluationContext, ProviderSignal
from graqle.assurance.providers._common import not_available

__all__ = ["SourceReliabilityProvider"]


class SourceReliabilityProvider:
    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        if ctx.source_reputation_registry is None:
            return not_available("provider=source_reliability.stub")
        return not_available("provider=source_reliability.scoring_unwired")
