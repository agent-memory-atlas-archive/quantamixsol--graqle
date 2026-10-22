"""Synthetic, non-inferential fixtures for the projection / registry / settings tests.

Every number here is an arbitrary test substitute, not a tuned value.
"""

from __future__ import annotations

from dataclasses import dataclass

from graqle.assurance.confidence_vector import (
    Availability,
    ConfidenceVector,
    Dimension,
    DimensionName,
    EntityClass,
)
from graqle.assurance.cv_settings import (
    SOURCE_CLASSES,
    ConfidenceVectorSettings,
    load_confidence_vector_settings,
)
from graqle.assurance.projection import (
    HardGateSummary,
    PenaltyInputs,
    ProjectionStrategyName,
)
from graqle.assurance.settings import DagSettings

FLAG = "GRAQLE_DAG_ENABLED"
MANDATORY = (DimensionName.CORROBORATION, DimensionName.TEMPORAL_VALIDITY)


@dataclass(frozen=True)
class FakeCap:
    cap_applied: bool = False
    output_value: float = 1.0


def passed() -> HardGateSummary:
    return HardGateSummary(all_passed=True)


def failed(*ids: str) -> HardGateSummary:
    return HardGateSummary(all_passed=False, failed_gate_ids=ids or ("HG-01",))


def no_penalty() -> PenaltyInputs:
    return PenaltyInputs(unresolved_contradictions=0, staleness=0.0, dependency_penalty=0.0)


def dim(
    name: DimensionName,
    raw: float | None = 0.5,
    *,
    calibrated: float | None = None,
    availability: Availability = Availability.AVAILABLE,
    stale: bool = False,
    diverged: bool = False,
) -> Dimension:
    if availability is not Availability.AVAILABLE:
        raw = calibrated = None
    return Dimension(
        name=name,
        availability=availability,
        raw=raw,
        calibrated=calibrated,
        calibrator_version="v-test" if calibrated is not None else "uncalibrated",
        calibration_stale=stale,
        divergence_exceeded=diverged,
        reason_codes=(),
        rule_version="1",
        config_version="cfg-test",
    )


def vector(
    values: dict[DimensionName, Dimension] | None = None,
    *,
    entity_class: EntityClass = EntityClass.DECISION,
    default: float = 0.5,
) -> ConfidenceVector:
    dims = {d: dim(d, default) for d in DimensionName}
    dims.update(values or {})
    return ConfidenceVector(
        candidate_id="c1",
        entity_class=entity_class,
        domain="d",
        decision_time_unix=1_000.0,
        dims=dims,
        calibration_stale=any(x.calibration_stale for x in dims.values()),
        any_not_available=any(x.availability is Availability.NOT_AVAILABLE for x in dims.values()),
        any_provider_error=any(x.availability is Availability.PROVIDER_ERROR for x in dims.values()),
        inputs_hash="sha256:" + "0" * 64,
        config_version="cfg-test",
        config_provenance={"weights": "SAFE_DEFAULT"},
    )


def cv_env(registry_dir: str, **overrides: str) -> dict[str, str]:
    """A complete, valid environment for the loader (arbitrary placeholder values)."""
    env: dict[str, str] = {
        FLAG: "true",
        "GRAQLE_DAG_CV_CALIBRATOR_TTL_SECONDS": "100",
        "GRAQLE_DAG_CV_MAX_DIVERGENCE": "0.4",
        "GRAQLE_DAG_CV_CALIBRATOR_REGISTRY_PATH": registry_dir,
    }
    for c in EntityClass:
        env[f"GRAQLE_DAG_CV_POLICY_THRESHOLD_{c.name}"] = "0.3"
        env[f"GRAQLE_DAG_CV_MANDATORY_DIMS_{c.name}"] = ",".join(d.value for d in MANDATORY)
    for s in SOURCE_CLASSES:
        env[f"GRAQLE_DAG_CV_HALF_LIFE_SECONDS_{s.upper()}"] = "50"
    for d in MANDATORY:
        env[f"GRAQLE_DAG_CV_RULE_FLOOR_{d.name}"] = "0.2"
    env.update(overrides)
    return env


def settings(
    registry_dir: str,
    strategy: ProjectionStrategyName = ProjectionStrategyName.LINEAR,
    **env_overrides: str,
) -> ConfidenceVectorSettings:
    env = cv_env(registry_dir, GRAQLE_DAG_CV_PROJECTION_STRATEGY=strategy.value, **env_overrides)
    return load_confidence_vector_settings(environ=env, secrets={}, dag=DagSettings())
