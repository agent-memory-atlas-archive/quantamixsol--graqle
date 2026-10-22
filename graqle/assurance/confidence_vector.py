"""DAG-2026 ConfidenceVector (CR-014 sections 2.1, 4, 5.2; PR-014b).

Seven causally distinct uncertainty dimensions, each carrying raw and calibrated
values side by side (I-CV-4). A dimension whose instrumentation is absent is
``NOT_AVAILABLE``; a provider that raises yields ``PROVIDER_ERROR``. Neither ever
carries a value, and neither is ever defaulted (I-CV-1, fail closed).

Calibration here is applied through a small lookup protocol so this module does not
depend on the registry, projection or settings model of PR-014c. All weights,
thresholds, half-lives and bounds are read from the supplied configuration object
and never appear as literals.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.confidence_vector
# risk: LOW (impact radius: 0 modules -- new file, no existing callers)
# dependencies: pydantic, graqle.assurance._hashing, graqle.assurance.source_identity
# constraints: never imported by graqle.governance.*; public_view() carries no private tuning keys
# -- /graqle:intelligence --

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from graqle.assurance._hashing import inputs_hash
from graqle.assurance.reason_codes import validate as _validate_codes
from graqle.assurance.source_identity import EvidenceRef

__all__ = [
    "CODE_DIVERGENCE",
    "CODE_NOT_AVAILABLE",
    "CODE_PROVIDER_ERROR",
    "CODE_STALE",
    "RULE_VERSION_DIM",
    "Availability",
    "CalibrationLookup",
    "Candidate",
    "ConfidenceVector",
    "ConfidenceVectorBuilder",
    "CvConfig",
    "Dimension",
    "DimensionName",
    "DimensionProvider",
    "EntityClass",
    "EvaluationContext",
    "EvidenceNode",
    "NoResolutions",
    "ProviderSignal",
    "SignalSource",
]

RULE_VERSION_DIM = "1"

CODE_NOT_AVAILABLE = "DAG-CV-001-DIM_NOT_AVAILABLE"
CODE_STALE = "DAG-CV-002-CALIBRATION_STALE"
CODE_DIVERGENCE = "DAG-CV-003-DIVERGENCE_EXCEEDED"
CODE_PROVIDER_ERROR = "DAG-CV-007-PROVIDER_ERROR"

_UNCALIBRATED = "uncalibrated"

#: Keys that must never appear in a serialised view (section 4, Senior chain 4).
_PRIVATE_KEYS = frozenset(
    {"weights", "penalties", "half_life", "policy_threshold", "max_divergence", "ttl"}
)


class DimensionName(str, Enum):
    SOURCE_RELIABILITY = "source_reliability"
    EXTRACTION_RELIABILITY = "extraction_reliability"
    CORROBORATION = "corroboration"
    TEMPORAL_VALIDITY = "temporal_validity"
    CONTEXT_FIT = "context_fit"
    REASONING_SUPPORT = "reasoning_support"
    OPERATIONAL_RELIABILITY = "operational_reliability"


class Availability(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    PROVIDER_ERROR = "PROVIDER_ERROR"


class EntityClass(str, Enum):
    ENTITY = "entity"
    RELATION = "relation"
    ABSTRACTION = "abstraction"
    DECISION = "decision"


class SignalSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_id: str
    source_module: str
    inputs_hash: str
    probabilistic: bool = False


class Dimension(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: DimensionName
    availability: Availability
    raw: float | None = Field(default=None, ge=0.0, le=1.0)
    calibrated: float | None = Field(default=None, ge=0.0, le=1.0)
    calibrator_version: str = _UNCALIBRATED
    probabilistic: bool = False
    variance: float | None = Field(default=None, ge=0.0)
    signal_sources: tuple[SignalSource, ...] = ()
    calibration_stale: bool = False
    divergence_exceeded: bool = False
    reason_codes: tuple[str, ...] = ()
    rule_id: str = "DAG-CV-DIM"
    rule_version: str
    config_version: str
    decisive_conditions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _invariants(self) -> Dimension:
        if self.availability is not Availability.AVAILABLE and (
            self.raw is not None or self.calibrated is not None
        ):
            raise ValueError("I-CV-1: unavailable dimension must carry no values")
        if self.availability is Availability.AVAILABLE and self.raw is None:
            raise ValueError("I-CV-1: available dimension must carry a raw value")
        if self.probabilistic and self.variance is None:
            raise ValueError("I-CV-2: probabilistic dimension must report variance")
        if self.calibrated is not None and self.calibrator_version == _UNCALIBRATED:
            raise ValueError("I-CV-3: calibrated value requires calibrator_version")
        _validate_codes(list(self.reason_codes))
        return self


class ConfidenceVector(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "cv-1"
    candidate_id: str
    entity_class: EntityClass
    domain: str
    decision_time_unix: float
    dims: dict[DimensionName, Dimension]
    calibration_stale: bool
    any_not_available: bool
    any_provider_error: bool
    inputs_hash: str
    config_version: str
    config_provenance: dict[str, str]

    @model_validator(mode="after")
    def _seven(self) -> ConfidenceVector:
        if set(self.dims) != set(DimensionName):
            raise ValueError("ConfidenceVector must contain all 7 dimensions")
        for key, dim in self.dims.items():
            if dim.name is not key:
                raise ValueError("dimension key must equal dimension name")
        return self

    def public_view(self) -> dict[str, Any]:
        """Serialisable view for traces and anchors.

        Carries raw/calibrated values, versions, availability and reason codes.
        NEVER carries weights, thresholds, half-lives, penalties, divergence bounds
        or TTLs. ``config_provenance`` is reduced to a single boolean.
        """
        dims: dict[str, Any] = {}
        for name, d in self.dims.items():
            dims[name.value] = {
                "availability": d.availability.value,
                "raw": d.raw,
                "calibrated": d.calibrated,
                "calibrator_version": d.calibrator_version,
                "probabilistic": d.probabilistic,
                "variance": d.variance,
                "calibration_stale": d.calibration_stale,
                "divergence_exceeded": d.divergence_exceeded,
                "reason_codes": list(d.reason_codes),
                "rule_id": d.rule_id,
                "rule_version": d.rule_version,
                "decisive_conditions": [
                    c for c in d.decisive_conditions if not _is_private(c)
                ],
                "signal_ids": [s.signal_id for s in d.signal_sources],
            }
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "entity_class": self.entity_class.value,
            "domain": self.domain,
            "decision_time_unix": self.decision_time_unix,
            "dims": dims,
            "calibration_stale": self.calibration_stale,
            "any_not_available": self.any_not_available,
            "any_provider_error": self.any_provider_error,
            "inputs_hash": self.inputs_hash,
            "config_version": self.config_version,
            "uses_safe_defaults": any(
                v == "SAFE_DEFAULT" for v in self.config_provenance.values()
            ),
        }


def _is_private(text: str) -> bool:
    lowered = text.lower()
    return any(k in lowered for k in _PRIVATE_KEYS)


# ---------------------------------------------------------------------------
# Inputs to providers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Candidate:
    id: str
    entity_class: EntityClass


@dataclass(frozen=True, slots=True)
class EvidenceNode:
    """A graph node backing a candidate, reduced to what extraction needs."""

    id: str
    has_chunks: bool


class NoResolutions:
    """Default resolution log: nothing resolved, nothing superseded."""

    def is_resolved(self, record: Mapping[str, Any]) -> bool:
        return False

    def is_superseded(self, evidence: EvidenceRef) -> bool:
        return False


@dataclass(frozen=True)
class EvaluationContext:
    """Everything a provider may read. Absent instrumentation is ``None``/empty."""

    domain: str
    decision_time_unix: float
    evidence_nodes: tuple[EvidenceNode, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    mandatory_evidence: tuple[EvidenceRef, ...] = ()
    dependency_pairs: tuple[tuple[str, str], ...] = ()
    #: node-id -> node dict, in the shape ``detect_contradictions`` consumes.
    evidence_node_dicts: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    resolutions: Any = field(default_factory=NoResolutions)
    evidence_state_snapshot: Any = None
    topology_edges: list[dict[str, Any]] | None = None
    recent_traces: list[dict[str, Any]] | None = None
    near_miss_store: Any = None
    drace_score: Any = None
    activation_confidence: float | None = None
    activation_variance: float | None = None
    source_reputation_registry: Any = None
    context_fit_scorer: Any = None
    decision_context: Any = None


class CvConfig(Protocol):
    """The configuration surface the providers and builder read (PR-014c supplies it)."""

    config_version: str
    config_provenance: Mapping[str, str]
    calibrator_ttl_seconds: int
    max_divergence: float
    half_life_seconds: Mapping[str, int]
    source_saturation: int
    same_bundle_seconds: int


class CalibrationRecordLike(Protocol):
    calibrator_version: str
    fitted_at_unix: float


class CalibrationLookup(Protocol):
    """Strict calibrator access. ``apply`` raises on any version/parameter mismatch."""

    def lookup(
        self, dimension: DimensionName, entity_class: EntityClass, domain: str
    ) -> CalibrationRecordLike | None: ...

    def apply(self, record: CalibrationRecordLike, raw: float) -> float: ...


@dataclass(frozen=True)
class ProviderSignal:
    availability: Availability = Availability.AVAILABLE
    raw: float | None = None
    probabilistic: bool = False
    variance: float | None = None
    sources: tuple[SignalSource, ...] = ()
    inputs: Mapping[str, Any] = field(default_factory=dict)
    decisive_conditions: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()


class DimensionProvider(Protocol):
    def compute(self, candidate: Candidate, ctx: EvaluationContext) -> ProviderSignal: ...


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class ConfidenceVectorBuilder:
    """Builds a :class:`ConfidenceVector`; never raises on a provider failure."""

    def __init__(
        self,
        config: CvConfig,
        providers: Mapping[DimensionName, DimensionProvider],
        clock: Callable[[], float],
        calibrators: CalibrationLookup | None = None,
    ) -> None:
        if set(providers) != set(DimensionName):
            from graqle.config.exceptions import ConfigurationError

            raise ConfigurationError("DAG-CV-008: one provider per dimension required")
        self._config = config
        self._providers = dict(providers)
        self._clock = clock
        self._calibrators = calibrators

    def build(self, candidate: Candidate, ctx: EvaluationContext) -> ConfidenceVector:
        cfg = self._config
        dims: dict[DimensionName, Dimension] = {}
        all_inputs: dict[str, Any] = {}
        for name in DimensionName:
            try:
                dims[name], dim_inputs = self._one(name, candidate, ctx)
                all_inputs[name.value] = dim_inputs
            except Exception as exc:  # noqa: BLE001 - fail closed on any provider fault
                dims[name] = self._error_dimension(name, exc)
                all_inputs[name.value] = {"error": type(exc).__name__}
        return ConfidenceVector(
            candidate_id=candidate.id,
            entity_class=candidate.entity_class,
            domain=ctx.domain,
            decision_time_unix=self._clock(),
            dims=dims,
            calibration_stale=any(d.calibration_stale for d in dims.values()),
            any_not_available=any(
                d.availability is Availability.NOT_AVAILABLE for d in dims.values()
            ),
            any_provider_error=any(
                d.availability is Availability.PROVIDER_ERROR for d in dims.values()
            ),
            inputs_hash=inputs_hash(all_inputs),
            config_version=cfg.config_version,
            config_provenance=dict(cfg.config_provenance),
        )

    def _one(
        self, name: DimensionName, candidate: Candidate, ctx: EvaluationContext
    ) -> tuple[Dimension, Any]:
        cfg = self._config
        sig = self._providers[name].compute(candidate, ctx)
        dim_inputs = dict(sig.inputs)
        inputs_hash({"i": dim_inputs})  # determinism record must be canonicalisable
        if sig.availability is not Availability.AVAILABLE:
            codes = tuple(dict.fromkeys((*sig.reason_codes, CODE_NOT_AVAILABLE)))
            if sig.availability is Availability.PROVIDER_ERROR:
                codes = (CODE_PROVIDER_ERROR,)
            return (
                Dimension(
                    name=name,
                    availability=sig.availability,
                    reason_codes=codes,
                    rule_version=RULE_VERSION_DIM,
                    config_version=cfg.config_version,
                    decisive_conditions=sig.decisive_conditions,
                ),
                dim_inputs,
            )
        if sig.raw is None:
            raise ValueError("available signal without raw value")
        cal, version, stale, diverged, cal_codes = self._calibrate(
            name, candidate.entity_class, ctx.domain, sig.raw
        )
        return (
            Dimension(
                name=name,
                availability=Availability.AVAILABLE,
                raw=sig.raw,
                calibrated=cal,
                calibrator_version=version,
                probabilistic=sig.probabilistic,
                variance=sig.variance,
                signal_sources=sig.sources,
                calibration_stale=stale,
                divergence_exceeded=diverged,
                reason_codes=tuple(dict.fromkeys((*sig.reason_codes, *cal_codes))),
                rule_version=RULE_VERSION_DIM,
                config_version=cfg.config_version,
                decisive_conditions=sig.decisive_conditions,
            ),
            dim_inputs,
        )

    def _calibrate(
        self, name: DimensionName, entity_class: EntityClass, domain: str, raw: float
    ) -> tuple[float | None, str, bool, bool, tuple[str, ...]]:
        if self._calibrators is None:
            return None, _UNCALIBRATED, False, False, ()
        rec = self._calibrators.lookup(name, entity_class, domain)
        if rec is None:
            return None, _UNCALIBRATED, False, False, ()
        age = self._clock() - rec.fitted_at_unix
        # A record fitted "in the future" (clock skew or tampering) is not trusted.
        stale = age < 0 or age > self._config.calibrator_ttl_seconds
        cal: float | None = self._calibrators.apply(rec, raw)
        diverged = abs(cal - raw) > self._config.max_divergence
        codes: list[str] = []
        if stale:
            codes.append(CODE_STALE)
        if diverged:
            codes.append(CODE_DIVERGENCE)
            cal = None
        return cal, rec.calibrator_version, stale, diverged, tuple(codes)

    def _error_dimension(self, name: DimensionName, exc: Exception) -> Dimension:
        # Only the exception class name is recorded: messages may echo private values.
        return Dimension(
            name=name,
            availability=Availability.PROVIDER_ERROR,
            reason_codes=(CODE_PROVIDER_ERROR,),
            rule_version=RULE_VERSION_DIM,
            config_version=self._config.config_version,
            decisive_conditions=(f"error={type(exc).__name__}",),
        )
