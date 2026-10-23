"""Corroboration provider (CR-014 sections 2.4, 2.4.1, 5.3).

``raw_COR = f_COR(independent sources, unresolved contradictions)``: monotone
increasing in the first argument, decreasing in the second, saturating at the
configured source saturation. Duplicated evidence shares a connected component, so
it cannot raise the value (I-CV-7).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers.corroboration
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.source_identity, graqle.scanner.dedup.contradictions
# constraints: deterministic; saturation read from configuration only
# -- /graqle:intelligence --

import json

from graqle.assurance.confidence_vector import (
    Availability,
    Candidate,
    CvConfig,
    EvaluationContext,
    ProviderSignal,
)
from graqle.assurance.providers._common import signal_source
from graqle.assurance.source_identity import independent_source_count, source_identity
from graqle.scanner.dedup.contradictions import detect_contradictions

__all__ = ["CorroborationProvider", "f_cor"]

CODE_IDENTITY_UNRESOLVED = "DAG-CV-009-SOURCE_INDEPENDENCE_UNRESOLVED"
CODE_GENERATOR_CORRELATED = "DAG-CV-004-GENERATOR_CORRELATED"


def f_cor(independent: int, unresolved_contradictions: int, saturation: int) -> float:
    """Saturating in sources, hyperbolically discounted by unresolved contradictions."""
    if saturation < 1:
        raise ValueError("source saturation must be at least one")
    if independent < 0 or unresolved_contradictions < 0:
        raise ValueError("counts must be non-negative")
    support = min(independent, saturation) / saturation
    return support / (1 + unresolved_contradictions)


class CorroborationProvider:
    def __init__(self, config: CvConfig) -> None:
        self._config = config

    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal:
        cfg = self._config
        result = independent_source_count(
            ctx.evidence, ctx.dependency_pairs, cfg.same_bundle_seconds
        )
        contras = [
            r
            for r in detect_contradictions(
                {k: dict(v) for k, v in ctx.evidence_node_dicts.items()}
            )
            if not ctx.resolutions.is_resolved(r)
        ]
        raw = f_cor(result.count, len(contras), cfg.source_saturation)
        codes: list[str] = []
        if result.identity_unresolved:
            codes.append(CODE_IDENTITY_UNRESOLVED)
        if result.generator_collapsed:
            codes.append(CODE_GENERATOR_CORRELATED)
        payload = {
            "source_ids": sorted({source_identity(e) for e in ctx.evidence}),
            "contradictions": sorted(
                json.dumps(r, sort_keys=True, default=str) for r in contras
            ),
        }
        return ProviderSignal(
            availability=Availability.AVAILABLE,
            raw=raw,
            inputs=payload,
            sources=(
                signal_source(
                    "assurance.corroboration.independent_sources",
                    "graqle.assurance.source_identity",
                    payload,
                ),
            ),
            decisive_conditions=(
                f"independent_sources={result.count}",
                f"unresolved_contradictions={len(contras)}",
            ),
            reason_codes=tuple(codes),
        )
