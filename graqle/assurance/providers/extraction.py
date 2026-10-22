"""Extraction-reliability provider (CR-014 section 5.3).

Baseline: chunk coverage of the evidence nodes backing the candidate (the same
arithmetic as ``Graqle.validate`` chunk coverage). When an evidence-state snapshot
hook is present its completeness ratio multiplies the coverage; when absent the
coverage alone is used and the condition ``snapshot=absent`` is recorded.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.extraction
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.confidence_vector, graqle.assurance.providers._common
# constraints: deterministic; no tuned values
# -- /graqle:intelligence --

from graqle.assurance.confidence_vector import (
    Availability,
    Candidate,
    EvaluationContext,
    ProviderSignal,
)
from graqle.assurance.providers._common import signal_source

__all__ = ["ExtractionReliabilityProvider"]

_SIGNAL_ID = "core.graph.validate.chunk_coverage"
_SOURCE_MODULE = "graqle.core.graph"


class ExtractionReliabilityProvider:
    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        nodes = ctx.evidence_nodes
        with_chunks = sum(1 for n in nodes if n.has_chunks)
        coverage = with_chunks / len(nodes) if nodes else 0.0
        snapshot = ctx.evidence_state_snapshot
        if snapshot is None:
            raw = coverage
            conds = ("snapshot=absent", f"coverage_nodes={len(nodes)}")
        else:
            raw = coverage * snapshot.completeness_ratio()
            conds = ("snapshot=present", f"coverage_nodes={len(nodes)}")
        payload = {"node_ids": sorted(n.id for n in nodes), "with_chunks": with_chunks}
        return ProviderSignal(
            availability=Availability.AVAILABLE,
            raw=raw,
            inputs=payload,
            sources=(signal_source(_SIGNAL_ID, _SOURCE_MODULE, payload),),
            decisive_conditions=conds,
        )
