"""Operational-reliability provider (CR-014 section 5.3).

Inputs: governance failure features over the trace history, near-miss density and
the top predicted failure-chain probability. Without a trace history, a near-miss
store, or at least ``_MIN_TRACES`` traces the dimension is ``NOT_AVAILABLE``
(fail closed); it is never defaulted.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.operational
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.governance.failure_features, graqle.governance.failure_predictor
# constraints: assurance may import governance, never the reverse; deterministic
# -- /graqle:intelligence --

from graqle.assurance.confidence_vector import (
    Availability,
    Candidate,
    EvaluationContext,
    ProviderSignal,
)
from graqle.assurance.providers._common import not_available, signal_source
from graqle.governance.failure_features import extract_features
from graqle.governance.failure_predictor import _MIN_TRACES, predict_governance_failures

__all__ = ["OperationalReliabilityProvider", "f_ops"]


def _clamp01(x: float) -> float:
    return min(1.0, max(0.0, x))


def f_ops(
    failure_rate: float, blocked_rate: float, near_miss_density: float, top_probability: float
) -> float:
    """Geometric combination of survival terms: any one collapse dominates."""
    out = 1.0
    for risk in (failure_rate, blocked_rate, near_miss_density, top_probability):
        out *= 1.0 - _clamp01(risk)
    return out


class OperationalReliabilityProvider:
    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        traces = ctx.recent_traces
        if traces is None:
            return not_available("provider=operational", "recent_traces=absent")
        if ctx.near_miss_store is None:
            return not_available("provider=operational", "near_miss_store=absent")
        if len(traces) < _MIN_TRACES:
            return not_available("provider=operational", f"trace_count={len(traces)}", "min_traces_met=False")
        feats = extract_features(ctx.topology_edges, traces)
        nm_density = _clamp01(ctx.near_miss_store.corpus_size() / max(len(traces), 1))
        prediction = predict_governance_failures(ctx.topology_edges, traces)
        top = max((p.probability for p in prediction.predictions), default=0.0)
        raw = f_ops(feats.tool.failure_rate, feats.tool.blocked_rate, nm_density, top)
        payload = {
            "feature_vector": [float(v) for v in feats.to_vector()],
            "trace_count": len(traces),
            "near_miss_density": nm_density,
            "top_probability": top,
        }
        return ProviderSignal(
            availability=Availability.AVAILABLE,
            raw=raw,
            inputs=payload,
            sources=(
                signal_source(
                    "governance.failure_features.tool",
                    "graqle.governance.failure_features",
                    payload,
                ),
                signal_source(
                    "governance.near_miss_store",
                    "graqle.governance.near_miss_store",
                    payload,
                ),
            ),
            decisive_conditions=(
                f"trace_count={len(traces)}",
                "min_traces_met=True",
            ),
        )
