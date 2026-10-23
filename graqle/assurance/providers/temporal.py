"""Temporal-validity provider (CR-014 sections 2.5, 5.3).

``decay(e) = 2 ** (-age / H_class)`` with the half-life read from configuration per
source class; superseded evidence decays to zero; the weakest mandatory evidence
governs. A missing or future timestamp makes the dimension ``NOT_AVAILABLE`` -- no
default age is ever substituted.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.temporal
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.confidence_vector
# constraints: half-lives only from configuration; unknown class fails closed
# -- /graqle:intelligence --

from graqle.assurance.confidence_vector import (
    Availability,
    Candidate,
    CvConfig,
    EvaluationContext,
    ProviderSignal,
)
from graqle.assurance.providers._common import not_available, signal_source

__all__ = ["TemporalValidityProvider"]


class TemporalValidityProvider:
    def __init__(self, config: CvConfig) -> None:
        self._config = config

    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        evidence = sorted(ctx.mandatory_evidence, key=lambda e: e.id)
        if not evidence:
            return not_available("provider=temporal_validity", "mandatory_evidence=absent")
        live = [e for e in evidence if not ctx.resolutions.is_superseded(e)]
        for e in live:
            if e.asserted_at_unix is None:
                return not_available("provider=temporal_validity", "timestamp=missing")
            if e.asserted_at_unix > ctx.decision_time_unix:
                return not_available("provider=temporal_validity", "timestamp=in_future")
        decays = [0.0] * (len(evidence) - len(live))
        for e in live:
            half_life = self._config.half_life_seconds[e.source_class]  # KeyError fails closed
            age = ctx.decision_time_unix - float(e.asserted_at_unix or 0.0)
            decays.append(2.0 ** (-age / half_life))
        payload = {
            "evidence": [
                [e.id, e.source_class, e.asserted_at_unix, e not in live] for e in evidence
            ],
            "decision_time_unix": ctx.decision_time_unix,
        }
        return ProviderSignal(
            availability=Availability.AVAILABLE,
            raw=min(decays),
            inputs=payload,
            sources=(
                signal_source(
                    "assurance.temporal.decay", "graqle.assurance.providers.temporal", payload
                ),
            ),
            decisive_conditions=(
                f"mandatory_evidence={len(evidence)}",
                f"superseded={len(evidence) - len(live)}",
            ),
        )
