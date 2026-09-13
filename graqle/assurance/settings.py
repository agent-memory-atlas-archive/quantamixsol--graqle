"""DAG-2026 Decision Assurance Gate — single-source feature flag and typed settings.

CR-012 §4.5 / §5.1 (PR-012a). This module is the ONLY place the DAG feature
flag is parsed and the ONLY typed home for every DAG configuration symbol used
by CR-013 … CR-019. Later CRs *consume* fields declared here; they never add a
second parse of ``GRAQLE_DAG_ENABLED`` (brief §6.1) or a second config surface
(Senior chain 1).

Semantics (CR-012 §2.1):

* ``INV-FLAG-1`` — ``GraqleConfig.assurance.enabled`` is derived from
  :func:`is_dag_enabled`; it is never a settable input.
* ``INV-FLAG-3`` — with the flag off nothing in this module changes SDK
  behaviour; :class:`~graqle.core.governance.GovernanceMiddleware` is untouched.
* ``INV-FLAG-4`` — with the flag on, any absent required value raises
  :class:`ConfigurationError` at the first load. There is no placeholder
  fallback for a security-critical value.

Trade-secret rule (CR-012 §12, brief §13): every threshold, cap, weight,
half-life, retry budget and window is a SYMBOL here. The only numeric literals
in this file are non-zero *operational* safe defaults (timeouts, TTL, SLA,
depth, key max age, bench seed), which brief §13.2 permits. Gate thresholds and
the cap have no default at all. Validators reject ``0`` (lesson R5).

Resolution order (pydantic-settings): explicit init kwargs > environment >
field default. :func:`load_dag_settings` therefore drops every private-file key
whose environment variable is present *before* constructing the model, so the
environment always wins over the private file (brief §8.3).
"""

from __future__ import annotations

# ── graqle:intelligence ──
# module: graqle.assurance.settings
# risk: LOW (impact radius: 1 module — graqle.config.settings lazy imports only)
# dependencies: graqle.config.exceptions, pydantic, pydantic_settings, yaml
# constraints: MUST NOT import graqle.config.settings (it lazily imports this
#   module); MUST NOT import graqle.governance at module level (assurance ->
#   governance is the allowed direction, but the canonicaliser is loaded lazily
#   inside config_version() to keep flag-off import cost at zero).
# ── /graqle:intelligence ──
import hashlib
import hmac
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from graqle.config.exceptions import GraqleConfigError

logger = logging.getLogger(__name__)

__all__ = [
    "ENV_FLAG",
    "ENV_PREFIX",
    "DEFAULT_SECRETS_PATH",
    "ConfigurationError",
    "DagSettings",
    "REQUIRED_WHEN_ENABLED",
    "SECRET_VALUED_FIELDS",
    "config_provenance",
    "config_version",
    "env_name",
    "is_dag_enabled",
    "load_dag_settings",
    "reset_dag_settings_cache",
    "validate_flag_consistency",
]

#: The single feature flag. Positive allowlist; anything else is OFF.
ENV_FLAG = "GRAQLE_DAG_ENABLED"
#: Prefix shared by every DAG setting (``GRAQLE_DAG_<FIELD>``).
ENV_PREFIX = "GRAQLE_DAG_"
#: Default location of the gitignored private-values file (brief §8.3).
DEFAULT_SECRETS_PATH = ".graqle/graqle_secrets.yaml"

_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})

#: Fields that MUST be present when the flag is on (CR-012 §4.5, blueprint B2).
REQUIRED_WHEN_ENABLED: tuple[str, ...] = (
    "cap_value",                    # CR-013
    "hg05_poisoning_threshold",     # CR-013 (blueprint B4)
    "hg07_materiality_threshold",   # CR-013
    "calibrator_version",           # CR-014
    "trajectory_estimator",         # CR-015 (blueprint M2)
    "max_retry_budget",             # CR-015 (blueprint M5)
    "circuit_breaker_window",       # CR-015
    "signing_key_id",               # CR-018 (blueprint B3)
    "signing_key_version",          # CR-018 (blueprint B3)
)

#: TS-2/TS-3 valued fields. Their VALUES never enter a log, trace, anchor or
#: fingerprint in clear (Senior chain 4); see :func:`config_version`.
SECRET_VALUED_FIELDS: frozenset[str] = frozenset({
    "cap_value",
    "hg05_poisoning_threshold",
    "hg07_materiality_threshold",
    "cv_max_raw_cal_divergence",
    "temporal_halflife_days",
    "max_retry_budget",
    "circuit_breaker_window",
})

# Domain-separation label for the joint commitment over secret-valued fields.
_SECRETS_DIGEST_LABEL = b"graqle.assurance.config_version.secrets.v1"

_ImpactTier = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ConfigurationError(GraqleConfigError):
    """Raised on flag mismatch, on missing required DAG config while the flag is
    on, or on an invalid value. Never a silent placeholder fallback.

    Messages carry setting NAMES only — never the offending value — so a
    rejected private value cannot leak through logs (Senior chain 4).
    """


def env_name(field: str) -> str:
    """Environment-variable name for a :class:`DagSettings` field."""
    return ENV_PREFIX + field.upper()


def is_dag_enabled() -> bool:
    """Pure environment read of :data:`ENV_FLAG`.

    ``"1" | "true" | "yes" | "on"`` (any case, padded) ⇒ ``True``; unset or any
    other value ⇒ ``False``. A positive allowlist was chosen over the resolver's
    negative list (``config/resolver.py:78``) so an unrecognised value fails
    CLOSED (CR-012 §2.1, Article 14 precedent).
    """
    return os.environ.get(ENV_FLAG, "").strip().lower() in _TRUTHY


class DagSettings(BaseSettings):
    """Every DAG configuration symbol, typed, in one place (CR-012 §4.5).

    Values come from the environment (``GRAQLE_DAG_<FIELD>``) or from the
    private file at ``GRAQLE_DAG_SECRETS_PATH``; the environment wins. The model
    is frozen and forbids unknown fields.
    """

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        extra="forbid",
        frozen=True,
        case_sensitive=False,
        validate_default=True,
    )

    # ── CR-012 ────────────────────────────────────────────────────────────
    enabled: bool = False
    secrets_path: str | None = None

    # ── CR-013 hard gates + cap (values TS-3; 0 rejected; no default) ─────
    cap_value: float | None = Field(default=None, gt=0.0, lt=1.0)
    hg05_poisoning_threshold: float | None = Field(default=None, gt=0.0, le=1.0)
    hg07_materiality_threshold: float | None = Field(default=None, gt=0.0, le=1.0)
    hg03_impact_tier_min: _ImpactTier = "HIGH"
    rbac_timeout_ms: int = Field(default=1500, gt=0)      # operational safe default
    gate_timeout_ms: int = Field(default=2000, gt=0)      # operational safe default

    # ── CR-014 confidence vector ──────────────────────────────────────────
    calibrator_version: str | None = None
    calibrator_ttl_hours: int = Field(default=720, gt=0)  # operational safe default
    cv_weights_ref: str = "cv_weights_v1"                 # key NAME in the private file, not values
    cv_max_raw_cal_divergence: float | None = Field(default=None, gt=0.0, le=1.0)
    temporal_halflife_days: int | None = Field(default=None, gt=0)

    # ── CR-015 trajectory / replan / escalation ───────────────────────────
    trajectory_estimator: str | None = None               # validated against the registry in CR-015
    max_retry_budget: int | None = Field(default=None, gt=0)
    circuit_breaker_window: int | None = Field(default=None, gt=0)
    escalation_role: str = "lead"                         # must be a core.rbac.ROLE_PERMISSIONS key
    escalation_sla_minutes: int = Field(default=240, gt=0)  # operational safe default

    # ── CR-016 / CR-017 ontology + propagation ────────────────────────────
    ontology_shapes_path: str | None = None
    prov_export_enabled: bool = False
    propagation_max_depth: int = Field(default=8, gt=0, le=64)  # operational safe default
    recompute_queue_path: str = ".graqle/dag/recompute_queue.jsonl"

    # ── CR-018 provenance event + action binding ──────────────────────────
    signing_key_id: str | None = None
    signing_key_version: str | None = None
    signing_key_max_age_days: int = Field(default=90, gt=0)  # operational safe default
    args_hash_algo: Literal["sha256"] = "sha256"
    provenance_merkle_batch: bool = False

    # ── CR-019 benchmark harness ──────────────────────────────────────────
    bench_results_dir: str = ".graqle/dag/bench"
    bench_seed: int = 20260911                            # operational safe default

    @field_validator("enabled", mode="before")
    @classmethod
    def _parse_flag(cls, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in _TRUTHY

    @field_validator("escalation_role")
    @classmethod
    def _role_known(cls, value: str) -> str:
        from graqle.core.rbac import ROLE_PERMISSIONS  # lazy: rbac is a stdlib leaf

        if value not in ROLE_PERMISSIONS:
            raise ValueError(
                f"escalation_role {value!r} is not a key of core.rbac.ROLE_PERMISSIONS"
            )
        return value

    @model_validator(mode="after")
    def _required_when_enabled(self) -> DagSettings:
        # Read-only: the model is frozen; this validator never assigns.
        if not self.enabled:
            return self
        missing = [f for f in REQUIRED_WHEN_ENABLED if getattr(self, f) is None]
        if missing:
            # Non-ValueError exceptions propagate unwrapped from pydantic
            # validators, so callers see ConfigurationError directly (AC-3).
            raise ConfigurationError(
                f"{ENV_FLAG}=true but required DAG settings are absent: "
                + ", ".join(env_name(m) for m in missing)
                + f". Set them in the environment or in {ENV_PREFIX}SECRETS_PATH. "
                "No placeholder fallback exists."
            )
        return self


# ── private-file layering ────────────────────────────────────────────────────

_cache: DagSettings | None = None
_provenance: dict[str, str] = {}


def _secrets_path() -> Path:
    raw = os.environ.get(ENV_PREFIX + "SECRETS_PATH", "").strip() or DEFAULT_SECRETS_PATH
    return Path(raw).expanduser()


def _load_secrets_file(path: Path) -> dict[str, Any]:
    """Read the optional private-values yaml into ``{field_name: value}``.

    Missing file ⇒ ``{}``. Keys may be bare field names or ``GRAQLE_DAG_``
    prefixed names (either case). Error messages name the file and the
    exception class only — never file content (parse-error oracle).
    """
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise ConfigurationError(
            f"DAG private config {path} is not valid YAML{where}: {type(exc).__name__}"
        ) from None
    except OSError as exc:
        raise ConfigurationError(
            f"DAG private config {path} could not be read: {type(exc).__name__}"
        ) from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigurationError(
            f"DAG private config {path} must be a mapping of setting names to values"
        )
    out: dict[str, Any] = {}
    for key, value in data.items():
        name = str(key).strip()
        if name.upper().startswith(ENV_PREFIX):
            name = name[len(ENV_PREFIX):]
        out[name.lower()] = value
    return out


def _unknown_prefixed_env_vars() -> list[str]:
    """Drift lock: every ``GRAQLE_DAG_*`` variable must map to exactly one field.

    pydantic-settings silently ignores unknown prefixed variables even under
    ``extra="forbid"`` (verified against pydantic-settings 2.13), so the check
    is explicit here. Returns NAMES only.
    """
    known = {env_name(f).upper() for f in DagSettings.model_fields}
    return sorted(
        k for k in os.environ
        if k.upper().startswith(ENV_PREFIX) and k.upper() not in known
    )


def load_dag_settings(*, force: bool = False) -> DagSettings:
    """Load (and cache) :class:`DagSettings`.

    Precedence: environment > private file > field default. The cache is only
    assigned on success (AC-3: no partial object is ever cached) and is
    invalidated automatically if the flag's environment value changes.

    Raises:
        ConfigurationError: on any invalid or missing-required value. The
            message carries setting names, never values.
    """
    global _cache, _provenance

    if _cache is not None and not force and _cache.enabled == is_dag_enabled():
        return _cache

    unknown = _unknown_prefixed_env_vars()
    if unknown:
        raise ConfigurationError(
            "unknown DAG environment variables (one name must map to exactly one "
            f"DagSettings field): {', '.join(unknown)}"
        )

    file_values = _load_secrets_file(_secrets_path())
    if "enabled" in file_values:
        raise ConfigurationError(
            f"{ENV_FLAG} is environment-only; remove 'enabled' from the DAG private config"
        )
    unknown_keys = sorted(k for k in file_values if k not in DagSettings.model_fields)
    if unknown_keys:
        raise ConfigurationError(
            "unknown keys in DAG private config: " + ", ".join(unknown_keys)
        )

    # Environment wins: pydantic-settings ranks init kwargs ABOVE env, so any
    # file key that also has an env var is dropped before construction.
    overrides = {k: v for k, v in file_values.items() if env_name(k) not in os.environ}

    try:
        settings = DagSettings(**overrides)
    except ValidationError as exc:
        # Do not chain (`from exc`): the pydantic error object carries the
        # rejected input value and would leak through __context__ (chain 4).
        details = "; ".join(
            f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('type')}"
            for e in exc.errors(include_url=False, include_input=False, include_context=False)
        )
        raise ConfigurationError(f"DAG settings invalid: {details}") from None

    if settings.enabled != is_dag_enabled():  # pragma: no cover — defensive (single source)
        raise ConfigurationError(
            f"DagSettings.enabled disagrees with {ENV_FLAG}; single source violated"
        )

    provenance: dict[str, str] = {}
    for name in DagSettings.model_fields:
        if env_name(name) in os.environ:
            provenance[name] = "ENV"
        elif name in overrides:
            provenance[name] = "SECRETS_FILE"
        elif getattr(settings, name) is not None:
            provenance[name] = "SAFE_DEFAULT"
        else:
            provenance[name] = "UNSET"

    _provenance = provenance
    _cache = settings
    logger.info(
        "dag.settings.loaded enabled=%s config_version=%s",
        settings.enabled,
        config_version(settings)[:23],
    )
    return settings


def reset_dag_settings_cache() -> None:
    """Drop the cached settings and provenance (tests, ``graq serve`` reload)."""
    global _cache, _provenance
    _cache = None
    _provenance = {}


def config_provenance() -> Mapping[str, str]:
    """Per-field source of the last successful load: ``ENV`` | ``SECRETS_FILE``
    | ``SAFE_DEFAULT`` | ``UNSET``. Empty until :func:`load_dag_settings` ran.
    Names and sources only — never values (brief §13.2 ``SAFE_DEFAULT`` stamp).
    """
    return MappingProxyType(dict(_provenance))


# ── deterministic fingerprint ────────────────────────────────────────────────

def _config_version_payload(settings: DagSettings) -> dict[str, Any]:
    """Public projection used by :func:`config_version`.

    Non-secret fields enter in clear. Secret-valued fields enter ONLY as (a) the
    sorted list of names that are set and (b) ONE joint HMAC-SHA256 whose key is
    the canonical encoding of all set secret values. A joint commitment is used
    instead of the CR's per-field ``sha256(repr(value))`` because a lone
    threshold in ``(0, 1)`` with a few decimals is brute-forceable from its own
    hash in milliseconds (sentinel B1, 2026-09-13); the joint form requires
    guessing every set value at once. Residual risk (attacker who already knows
    all but one value) is recorded in the PR and left for the Research Team
    ruling on a deployment salt (CR-018 signing key).
    """
    from graqle.governance.tamper_evidence.canonicalize import (
        canon,  # lazy: assurance -> governance
    )

    dumped = settings.model_dump(mode="json")
    public = {k: v for k, v in dumped.items() if k not in SECRET_VALUED_FIELDS}
    secret_items = {
        k: dumped[k] for k in sorted(SECRET_VALUED_FIELDS) if dumped.get(k) is not None
    }
    digest: str | None = None
    if secret_items:
        key = canon(secret_items)
        digest = hmac.new(key, _SECRETS_DIGEST_LABEL, hashlib.sha256).hexdigest()
    public["_secret_fields_set"] = sorted(secret_items)
    public["_secrets_digest"] = digest
    return public


def config_version(settings: DagSettings) -> str:
    """``"sha256:<hex>"`` fingerprint of the settings for
    ``DeterminismRecord.config_version`` (CR-012 §4.3) and run logs.

    Deterministic across processes for the same configuration; secret values
    never appear in clear (see :func:`_config_version_payload`). Any
    canonicalisation failure is fail-closed — never coerced.
    """
    try:
        from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

        data = canon(_config_version_payload(settings))
    except ConfigurationError:
        raise
    except Exception as exc:  # TamperEvidenceError, ImportError, ...
        raise ConfigurationError(
            f"config_version could not be computed: {type(exc).__name__}"
        ) from None
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ── startup validator (blueprint B1) ─────────────────────────────────────────

def validate_flag_consistency(cfg: Any) -> None:
    """Fatal on any disagreement between the environment flag and the config
    object; when the flag is on, eagerly loads settings so a missing required
    value is a startup error (INV-FLAG-4), never a request-time surprise.

    Called from ``GraqleConfig.from_yaml()`` and from MCP server boot. With the
    flag off this is a single environment read.
    """
    env_on = is_dag_enabled()
    assurance = getattr(cfg, "assurance", None)
    if assurance is None:
        raise ConfigurationError(
            "config object has no 'assurance' section; cannot validate the DAG flag"
        )
    cfg_on = bool(getattr(assurance, "enabled", False))
    if env_on != cfg_on:  # only reachable via monkey-patching; still fatal
        raise ConfigurationError(
            f"assurance.enabled={cfg_on} but {ENV_FLAG}={env_on}; single source violated"
        )
    if env_on:
        settings = load_dag_settings()  # raises ConfigurationError if incomplete
        from graqle.__version__ import __version__

        # Truncated prefix: enough for operators to correlate, not a durable
        # copy of the full fingerprint in every log sink (sentinel B4).
        logger.warning(
            "DAG enabled — DecisionAssuranceGate components active (v%s); config_version=%s…",
            __version__,
            config_version(settings)[:23],
        )
