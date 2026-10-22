"""Synthetic, non-inferential fixtures for the CR-014 PR-014b tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from graqle.assurance.confidence_vector import (
    Candidate,
    ConfidenceVectorBuilder,
    DimensionName,
    EntityClass,
    EvaluationContext,
    EvidenceNode,
)
from graqle.assurance.providers import (
    ContextFitProvider,
    CorroborationProvider,
    ExtractionReliabilityProvider,
    OperationalReliabilityProvider,
    ReasoningSupportProvider,
    SourceReliabilityProvider,
    TemporalValidityProvider,
)
from graqle.assurance.source_identity import EvidenceRef, GeneratorRef

NOW = 1_000_000.0


@dataclass
class FakeConfig:
    """Test-only configuration; values are arbitrary placeholders, not tuned ones."""

    config_version: str = "cfg-test"
    config_provenance: dict[str, str] = field(default_factory=lambda: {"weights": "SAFE_DEFAULT"})
    calibrator_ttl_seconds: int = 10
    max_divergence: float = 0.5
    half_life_seconds: dict[str, int] = field(default_factory=lambda: {"document": 7})
    source_saturation: int = 3
    same_bundle_seconds: int = 1


def evidence(
    i: int,
    *,
    content: str | None = None,
    authority: str | None = None,
    locator: str | None = None,
    at: float | None = None,
    generator: GeneratorRef | None = None,
    origin_class: str = "document",
) -> EvidenceRef:
    return EvidenceRef(
        id=f"e{i}",
        origin_class=origin_class,
        origin_authority_id=authority or f"auth{i}",
        locator=locator or f"https://x{i}.example/doc",
        content_sha256=(content or f"{i:064x}"),
        source_class="document",
        asserted_at_unix=at,
        generator=generator,
    )


def candidate() -> Candidate:
    return Candidate(id="c1", entity_class=EntityClass.ENTITY)


def context(**kw) -> EvaluationContext:
    base = dict(
        domain="d",
        decision_time_unix=NOW,
        evidence_nodes=(EvidenceNode("n1", True), EvidenceNode("n2", False)),
    )
    base.update(kw)
    return EvaluationContext(**base)


def providers(cfg: FakeConfig) -> dict[DimensionName, object]:
    return {
        DimensionName.SOURCE_RELIABILITY: SourceReliabilityProvider(),
        DimensionName.EXTRACTION_RELIABILITY: ExtractionReliabilityProvider(),
        DimensionName.CORROBORATION: CorroborationProvider(cfg),
        DimensionName.TEMPORAL_VALIDITY: TemporalValidityProvider(cfg),
        DimensionName.CONTEXT_FIT: ContextFitProvider(),
        DimensionName.REASONING_SUPPORT: ReasoningSupportProvider(),
        DimensionName.OPERATIONAL_RELIABILITY: OperationalReliabilityProvider(),
    }


def builder(cfg: FakeConfig | None = None, calibrators=None, overrides=None):
    cfg = cfg or FakeConfig()
    provs = providers(cfg)
    provs.update(overrides or {})
    return ConfidenceVectorBuilder(cfg, provs, lambda: NOW, calibrators)
