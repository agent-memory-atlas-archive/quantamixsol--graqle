"""Confidence-vector settings: the typed home of every vector symbol.

Re-exported from :mod:`graqle.assurance.settings` (lazily, so importing the
settings module never loads the vector). Gate-relevant values are required when
the flag is on and have no default; weights and penalties have non-zero
placeholders that are stamped ``SAFE_DEFAULT`` in ``config_provenance`` so a
deployment running on them is auditable. Every check raises
:class:`ConfigurationError`, and zero is rejected everywhere.

Resolution order: environment ``GRAQLE_DAG_CV_*`` > the private file's
``assurance.confidence_vector`` section > placeholder (where one exists).
Error messages name symbols, never values.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.cv_settings
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.settings, graqle.assurance.projection
# constraints: imported lazily from settings; no tuned value in this file
# -- /graqle:intelligence --
import json
import logging
import math
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from graqle.assurance import settings as _s
from graqle.assurance.confidence_vector import DimensionName, EntityClass
from graqle.assurance.projection import Penalties, ProjectionStrategyName
from graqle.config.exceptions import ENV_FLAG, ConfigurationError

logger = logging.getLogger(__name__)

__all__ = [
    "CV_ENV_PREFIX",
    "SOURCE_CLASSES",
    "BootstrapSettings",
    "ConfidenceVectorSettings",
    "cv_env_names",
    "load_confidence_vector_settings",
]

#: Environment prefix of every confidence-vector symbol.
CV_ENV_PREFIX = _s.ENV_PREFIX + "CV_"

#: Source classes that carry a half-life (the origin-class vocabulary).
SOURCE_CLASSES: tuple[str, ...] = (
    "code",
    "api_spec",
    "json_config",
    "user_taught",
    "document",
    "tool_result",
    "web",
)

_ConfigSource = Literal["ENV", "SECRETS_YAML", "SAFE_DEFAULT"]
_SECONDS_PER_HOUR = 3600

# Non-inferential placeholders. They are NOT tuned values: they exist so a
# deployment without private weights is auditable rather than silently running
# on an invented tuning.
_PLACEHOLDER_UNIT = 1.0 / len(DimensionName)
_SAFE_DEFAULT_N_SAT = 3
_SAFE_DEFAULT_TAU_BUNDLE = 1
_SAFE_DEFAULT_EDGES: tuple[int, ...] = (1, 2, 4)
_SAFE_DEFAULT_RESAMPLES = 200


class _BootstrapDefaults(BaseModel):
    """Typed home of the placeholder bootstrap significance level."""

    model_config = ConfigDict(frozen=True)

    alpha: float = Field(default=0.05)


_SAFE_DEFAULT_ALPHA = _BootstrapDefaults().alpha
_SAFE_DEFAULT_SEED = 0
_WEIGHT_SUM_EPS = 1e-6


def _safe_default_weights() -> dict[DimensionName, float]:
    """Non-inferential placeholder, replaced at load by the private weights."""
    return {d: _PLACEHOLDER_UNIT for d in DimensionName}


def _safe_default_penalties() -> Penalties:
    """Non-inferential placeholder, replaced at load by the private penalties."""
    return Penalties(
        contradiction=_PLACEHOLDER_UNIT, staleness=_PLACEHOLDER_UNIT, dependency=_PLACEHOLDER_UNIT
    )


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _in_open_unit(value: object) -> bool:
    return _is_number(value) and 0.0 < value < 1.0  # type: ignore[operator]


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


class BootstrapSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resamples: int = _SAFE_DEFAULT_RESAMPLES
    alpha: float = _SAFE_DEFAULT_ALPHA
    seed: int = _SAFE_DEFAULT_SEED

    @model_validator(mode="after")
    def _valid(self) -> BootstrapSettings:
        if not _is_positive_int(self.resamples):
            raise ConfigurationError("DAG-CV config bootstrap resamples must be positive")
        if not _in_open_unit(self.alpha):
            raise ConfigurationError("DAG-CV config bootstrap alpha must be inside (0, 1)")
        return self


def _check_knots(dim: DimensionName, knots: tuple[tuple[float, float], ...]) -> None:
    if len(knots) < 2 or not all(_is_number(v) for pair in knots for v in pair):
        raise ConfigurationError(f"DAG-CV knots for {dim.value} are malformed")
    xs, ys = [k[0] for k in knots], [k[1] for k in knots]
    if any(b <= a for a, b in zip(xs, xs[1:])) or any(b < a for a, b in zip(ys, ys[1:])):
        raise ConfigurationError(f"DAG-CV knots for {dim.value} must be monotone")
    if min(xs) < 0.0 or max(xs) > 1.0 or min(ys) < 0.0 or max(ys) > 1.0:
        raise ConfigurationError(f"DAG-CV knots for {dim.value} leave the unit interval")


class ConfidenceVectorSettings(BaseModel):
    """Every confidence-vector symbol, typed and validated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_thresholds: dict[EntityClass, float]
    calibrator_ttl_seconds: int
    max_divergence: float
    half_life_seconds: dict[str, int]
    mandatory_dims: dict[EntityClass, frozenset[DimensionName]]
    calibrator_registry_path: Path
    projection_strategy: ProjectionStrategyName = ProjectionStrategyName.RULE_ONLY
    weights: dict[DimensionName, float] = Field(default_factory=_safe_default_weights)
    penalties: Penalties = Field(default_factory=_safe_default_penalties)
    source_saturation: int = _SAFE_DEFAULT_N_SAT
    same_bundle_seconds: int = _SAFE_DEFAULT_TAU_BUNDLE
    tc_ece_position_edges: tuple[int, ...] = _SAFE_DEFAULT_EDGES
    bootstrap: BootstrapSettings = Field(default_factory=BootstrapSettings)
    # Private strategy artefacts (values never in the repository).
    rule_floors: dict[DimensionName, float] = Field(default_factory=dict)
    monotonic_knots: dict[DimensionName, tuple[tuple[float, float], ...]] = Field(
        default_factory=dict
    )
    tree_path: Path | None = None
    tree_max_depth: int | None = None
    config_version: str
    config_provenance: dict[str, _ConfigSource]

    @model_validator(mode="after")
    def _reject_zero_and_bad_sums(self) -> ConfidenceVectorSettings:
        if set(self.policy_thresholds) != set(EntityClass):
            raise ConfigurationError("DAG-CV policy thresholds must cover every entity class")
        for cls_, v in self.policy_thresholds.items():
            if not _in_open_unit(v):
                raise ConfigurationError(
                    f"DAG-CV policy threshold {cls_.value} must be inside (0, 1)"
                )
        if not _is_positive_int(self.calibrator_ttl_seconds):
            raise ConfigurationError("DAG-CV calibrator ttl must be positive")
        if not _in_open_unit(self.max_divergence):
            raise ConfigurationError("DAG-CV max divergence must be inside (0, 1)")
        if set(self.half_life_seconds) != set(SOURCE_CLASSES):
            raise ConfigurationError("DAG-CV half-lives must cover every source class")
        for name, v in self.half_life_seconds.items():
            if not _is_positive_int(v):
                raise ConfigurationError(f"DAG-CV half-life {name} must be positive")
        if set(self.mandatory_dims) != set(EntityClass) or not all(self.mandatory_dims.values()):
            raise ConfigurationError(
                "DAG-CV mandatory dimensions must be non-empty for every class"
            )
        if set(self.weights) != set(DimensionName):
            raise ConfigurationError("DAG-CV weights must cover all dimensions")
        for dim, w in self.weights.items():
            if not _is_number(w) or w <= 0.0:
                raise ConfigurationError(f"DAG-CV weight {dim.value} must be positive")
        if abs(sum(self.weights.values()) - 1.0) > _WEIGHT_SUM_EPS:
            raise ConfigurationError("DAG-CV weights must sum to 1")
        if not _is_positive_int(self.source_saturation):
            raise ConfigurationError("DAG-CV source saturation must be at least 1")
        if not _is_positive_int(self.same_bundle_seconds):
            raise ConfigurationError("DAG-CV same-bundle window must be positive")
        edges = self.tc_ece_position_edges
        if (
            not edges
            or not all(_is_positive_int(e) for e in edges)
            or any(b <= a for a, b in zip(edges, edges[1:]))
        ):
            raise ConfigurationError("DAG-CV position edges must be positive and increasing")
        for dim, floor in self.rule_floors.items():
            if not _is_number(floor) or not 0.0 < floor <= 1.0:
                raise ConfigurationError(f"DAG-CV rule floor {dim.value} must be inside (0, 1]")
        for dim, knots in self.monotonic_knots.items():
            _check_knots(dim, knots)
        if self.tree_max_depth is not None and not _is_positive_int(self.tree_max_depth):
            raise ConfigurationError("DAG-CV tree depth bound must be positive")
        if not self.config_version.strip():
            raise ConfigurationError("DAG-CV config version must be set")
        self._require_strategy_artefacts()
        return self

    def _require_strategy_artefacts(self) -> None:
        """The chosen strategy must be runnable: its private artefact must exist."""
        strategy = self.projection_strategy
        if strategy is ProjectionStrategyName.RULE_ONLY:
            needed = set().union(*self.mandatory_dims.values())
            if not needed <= set(self.rule_floors):
                raise ConfigurationError(
                    "DAG-CV rule_only needs a floor for every mandatory dimension"
                )
        elif strategy is ProjectionStrategyName.MONOTONIC:
            if set(self.monotonic_knots) != set(DimensionName):
                raise ConfigurationError("DAG-CV monotonic needs knots for every dimension")
        elif strategy is ProjectionStrategyName.CALIBRATED_TREE:
            if self.tree_path is None or self.tree_max_depth is None:
                raise ConfigurationError(
                    "DAG-CV calibrated_tree needs a tree path and a depth bound"
                )


def _cv_suffixes() -> list[str]:
    """Every environment-variable suffix under ``GRAQLE_DAG_CV_``."""
    fixed = [
        "CALIBRATOR_TTL_SECONDS", "MAX_DIVERGENCE", "PROJECTION_STRATEGY",
        "PENALTY_CONTRADICTION", "PENALTY_STALENESS", "PENALTY_DEPENDENCY",
        "SOURCE_SATURATION", "SAME_BUNDLE_SECONDS", "CALIBRATOR_REGISTRY_PATH",
        "TC_ECE_POSITION_EDGES", "BOOTSTRAP_RESAMPLES", "BOOTSTRAP_ALPHA", "BOOTSTRAP_SEED",
        "KNOTS_PATH", "TREE_PATH", "TREE_MAX_DEPTH",
    ]
    return (
        fixed
        + [f"POLICY_THRESHOLD_{c.name}" for c in EntityClass]
        + [f"MANDATORY_DIMS_{c.name}" for c in EntityClass]
        + [f"HALF_LIFE_SECONDS_{c.upper()}" for c in SOURCE_CLASSES]
        + [f"WEIGHT_{d.name}" for d in DimensionName]
        + [f"RULE_FLOOR_{d.name}" for d in DimensionName]
    )


def cv_env_names() -> set[str]:
    """Full names of every recognised confidence-vector variable."""
    return {CV_ENV_PREFIX + suffix for suffix in _cv_suffixes()}


class _CvReader:
    """Env-over-private-file lookup with provenance; errors name symbols only."""

    def __init__(self, environ: Mapping[str, str], private: Mapping[str, Any]) -> None:
        self._env = {k.upper(): v for k, v in environ.items()}
        self._private = {str(k).strip().upper(): v for k, v in private.items()}
        unknown = sorted(set(self._private) - set(_cv_suffixes()))
        if unknown:
            raise ConfigurationError(
                "unknown keys in assurance.confidence_vector: " + ", ".join(unknown)
            )
        # A few DagSettings fields also start with the vector prefix; they are not ours.
        dag_names = {_s.env_name(f).upper() for f in _s.DagSettings.model_fields}
        unknown_env = sorted(
            k
            for k in self._env
            if k.startswith(CV_ENV_PREFIX) and k not in cv_env_names() and k not in dag_names
        )
        if unknown_env:
            raise ConfigurationError("unknown DAG-CV environment variables: " + ", ".join(unknown_env))
        self.provenance: dict[str, _ConfigSource] = {}

    def raw(self, suffix: str, group: str | None = None) -> Any:
        """Value or ``None``; records provenance under ``group`` (default: the suffix)."""
        label = (group or suffix).lower()
        env_key = CV_ENV_PREFIX + suffix
        if env_key in self._env:
            self.provenance[label] = "ENV"
            return self._env[env_key]
        if suffix in self._private:
            self.provenance[label] = "SECRETS_YAML"
            return self._private[suffix]
        return None

    def mark_default(self, group: str) -> None:
        self.provenance.setdefault(group, "SAFE_DEFAULT")

    @staticmethod
    def _fail(suffix: str, what: str) -> ConfigurationError:
        return ConfigurationError(f"{CV_ENV_PREFIX}{suffix} {what}")

    def number(self, suffix: str, group: str | None = None) -> float | None:
        raw = self.raw(suffix, group)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None
        try:
            if isinstance(raw, bool):
                raise ValueError
            value = float(raw.strip() if isinstance(raw, str) else raw)
        except (TypeError, ValueError):
            raise self._fail(suffix, "must be a number") from None
        if not math.isfinite(value):
            raise self._fail(suffix, "must be a finite number")
        return value

    def integer(self, suffix: str, group: str | None = None) -> int | None:
        raw = self.raw(suffix, group)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None
        try:
            if isinstance(raw, bool) or (isinstance(raw, float) and not raw.is_integer()):
                raise ValueError
            return int(raw.strip() if isinstance(raw, str) else raw)
        except (TypeError, ValueError):
            raise self._fail(suffix, "must be a whole number") from None

    def items(self, suffix: str, group: str | None = None) -> list[str] | None:
        raw = self.raw(suffix, group)
        if raw is None:
            return None
        parts = raw.split(",") if isinstance(raw, str) else raw
        if not isinstance(parts, (list, tuple)):
            raise self._fail(suffix, "must be a comma-separated list")
        return [str(p).strip() for p in parts if str(p).strip()]


def _required(value: Any, suffix: str) -> Any:
    if value is None:
        raise ConfigurationError(f"{CV_ENV_PREFIX}{suffix} is required when {ENV_FLAG} is on")
    return value


def _load_knots(path_text: str) -> dict[DimensionName, tuple[tuple[float, float], ...]]:
    try:
        data = json.loads(Path(path_text).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigurationError(
            f"{CV_ENV_PREFIX}KNOTS_PATH could not be loaded ({type(exc).__name__})"
        ) from None
    if not isinstance(data, dict):
        raise ConfigurationError(f"{CV_ENV_PREFIX}KNOTS_PATH must hold a mapping")
    out: dict[DimensionName, tuple[tuple[float, float], ...]] = {}
    for name, pairs in data.items():
        try:
            out[DimensionName(name)] = tuple((float(a), float(b)) for a, b in pairs)
        except (ValueError, TypeError):
            raise ConfigurationError(f"{CV_ENV_PREFIX}KNOTS_PATH is malformed") from None
    return out


def _resolve_ttl(
    r: _CvReader, env: Mapping[str, str], dag: _s.DagSettings
) -> int:
    """Canonical seconds name, or the deprecated hours name read through."""
    ttl = r.integer("CALIBRATOR_TTL_SECONDS", "calibrator_ttl_seconds")
    legacy_name = _s.env_name("calibrator_ttl_hours")
    legacy: Any = env.get(legacy_name)
    from_env = legacy is not None
    if legacy is None and "calibrator_ttl_hours" in dag.model_fields_set:
        legacy = dag.calibrator_ttl_hours  # explicitly supplied via the private file
    if legacy is not None:
        if ttl is not None:
            raise ConfigurationError(
                f"{legacy_name} and {CV_ENV_PREFIX}CALIBRATOR_TTL_SECONDS are both set; "
                "remove the deprecated hours name"
            )
        logger.warning(
            "%s is deprecated; use %sCALIBRATOR_TTL_SECONDS (seconds)", legacy_name, CV_ENV_PREFIX
        )
        try:
            ttl = int(str(legacy).strip()) * _SECONDS_PER_HOUR
        except ValueError:
            raise ConfigurationError(f"{legacy_name} must be a whole number") from None
        r.provenance["calibrator_ttl_seconds"] = "ENV" if from_env else "SECRETS_YAML"
    if ttl is None:
        raise ConfigurationError(
            f"{CV_ENV_PREFIX}CALIBRATOR_TTL_SECONDS is required when {ENV_FLAG} is on"
        )
    return ttl


def load_confidence_vector_settings(
    *,
    environ: Mapping[str, str] | None = None,
    secrets: Mapping[str, Any] | None = None,
    dag: _s.DagSettings | None = None,
) -> ConfidenceVectorSettings:
    """Build :class:`ConfidenceVectorSettings`.

    Only meaningful with the flag on; with it off this raises, so flag-off code can
    never construct (or accidentally rely on) confidence-vector settings. ``dag``
    supplies ``config_version``; by default it is loaded with
    :func:`graqle.assurance.settings.load_dag_settings`, which also makes the
    private file's ``assurance.confidence_vector`` section available.
    """
    env: Mapping[str, str] = os.environ if environ is None else environ
    if env.get(ENV_FLAG, "").strip().lower() not in _s._TRUTHY:
        raise ConfigurationError(f"confidence-vector settings need {ENV_FLAG}=true")
    dag_settings = dag if dag is not None else _s.load_dag_settings()
    with _s._cache_lock:
        private_section = dict(_s._private_assurance.get("confidence_vector") or {})
    r = _CvReader(env, secrets if secrets is not None else private_section)

    thresholds: dict[EntityClass, float] = {}
    mandatory: dict[EntityClass, frozenset[DimensionName]] = {}
    for c in EntityClass:
        thresholds[c] = _required(
            r.number(f"POLICY_THRESHOLD_{c.name}", "policy_thresholds"),
            f"POLICY_THRESHOLD_{c.name}",
        )
        names = _required(
            r.items(f"MANDATORY_DIMS_{c.name}", "mandatory_dims"), f"MANDATORY_DIMS_{c.name}"
        )
        try:
            mandatory[c] = frozenset(DimensionName(n) for n in names)
        except ValueError:
            raise ConfigurationError(
                f"{CV_ENV_PREFIX}MANDATORY_DIMS_{c.name} names an unknown dimension"
            ) from None
    half_lives = {
        s: _required(
            r.integer(f"HALF_LIFE_SECONDS_{s.upper()}", "half_life_seconds"),
            f"HALF_LIFE_SECONDS_{s.upper()}",
        )
        for s in SOURCE_CLASSES
    }
    ttl = _resolve_ttl(r, env, dag_settings)
    max_div = _required(r.number("MAX_DIVERGENCE", "max_divergence"), "MAX_DIVERGENCE")
    registry = _required(
        r.raw("CALIBRATOR_REGISTRY_PATH", "calibrator_registry_path"), "CALIBRATOR_REGISTRY_PATH"
    )

    strategy_text = r.raw("PROJECTION_STRATEGY", "projection_strategy")
    if strategy_text is None:
        r.mark_default("projection_strategy")
        strategy = ProjectionStrategyName.RULE_ONLY
    else:
        try:
            strategy = ProjectionStrategyName(str(strategy_text).strip())
        except ValueError:
            raise ConfigurationError(
                f"{CV_ENV_PREFIX}PROJECTION_STRATEGY is not one of the allowed values"
            ) from None

    kwargs: dict[str, Any] = {}
    given = {d: r.number(f"WEIGHT_{d.name}", "weights") for d in DimensionName}
    if any(v is not None for v in given.values()):
        if any(v is None for v in given.values()):
            raise ConfigurationError("DAG-CV weights must be given for every dimension or none")
        kwargs["weights"] = given
    else:
        r.mark_default("weights")
    pen = {
        "contradiction": r.number("PENALTY_CONTRADICTION", "penalties"),
        "staleness": r.number("PENALTY_STALENESS", "penalties"),
        "dependency": r.number("PENALTY_DEPENDENCY", "penalties"),
    }
    if any(v is not None for v in pen.values()):
        if any(v is None for v in pen.values()):
            raise ConfigurationError("DAG-CV penalties must be given for all three or none")
        kwargs["penalties"] = Penalties(**pen)  # type: ignore[arg-type]
    else:
        r.mark_default("penalties")
    for field_name, suffix in (
        ("source_saturation", "SOURCE_SATURATION"),
        ("same_bundle_seconds", "SAME_BUNDLE_SECONDS"),
    ):
        value = r.integer(suffix, field_name)
        if value is None:
            r.mark_default(field_name)
        else:
            kwargs[field_name] = value
    edges = r.items("TC_ECE_POSITION_EDGES", "tc_ece_position_edges")
    if edges is None:
        r.mark_default("tc_ece_position_edges")
    else:
        try:
            kwargs["tc_ece_position_edges"] = tuple(int(e) for e in edges)
        except ValueError:
            raise ConfigurationError(
                f"{CV_ENV_PREFIX}TC_ECE_POSITION_EDGES must be whole numbers"
            ) from None
    boot: dict[str, Any] = {}
    for key, suffix, reader in (
        ("resamples", "BOOTSTRAP_RESAMPLES", r.integer),
        ("alpha", "BOOTSTRAP_ALPHA", r.number),
        ("seed", "BOOTSTRAP_SEED", r.integer),
    ):
        value = reader(suffix, "bootstrap")
        if value is not None:
            boot[key] = value
    if not boot:
        r.mark_default("bootstrap")
    kwargs["bootstrap"] = BootstrapSettings(**boot)

    floors = {d: r.number(f"RULE_FLOOR_{d.name}", "rule_floors") for d in DimensionName}
    kwargs["rule_floors"] = {d: v for d, v in floors.items() if v is not None}
    knots_path = r.raw("KNOTS_PATH", "monotonic_knots")
    if knots_path is not None:
        kwargs["monotonic_knots"] = _load_knots(str(knots_path))
    tree_path = r.raw("TREE_PATH", "tree_path")
    if tree_path is not None:
        kwargs["tree_path"] = Path(str(tree_path))
    depth = r.integer("TREE_MAX_DEPTH", "tree_max_depth")
    if depth is not None:
        kwargs["tree_max_depth"] = depth

    try:
        return ConfidenceVectorSettings(
            policy_thresholds=thresholds,
            calibrator_ttl_seconds=ttl,
            max_divergence=max_div,
            half_life_seconds=half_lives,
            mandatory_dims=mandatory,
            calibrator_registry_path=Path(str(registry)),
            projection_strategy=strategy,
            config_version=_s.config_version(dag_settings),
            config_provenance=dict(r.provenance),
            **kwargs,
        )
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e.get('loc', ()))}: "
            f"{_s._TYPE_HINTS.get(str(e.get('type')), str(e.get('type')))}"
            for e in exc.errors(include_url=False, include_input=False, include_context=False)
        )
        raise ConfigurationError(f"DAG-CV settings invalid: {details}") from None
