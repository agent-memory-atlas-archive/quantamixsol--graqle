"""ProvenanceSettings: CR-018 provenance / signing configuration (PR-018b, spec 3.3).

Every field reads ``GRAQLE_DAG_<FIELD>`` from the environment. Nothing here is
read from yaml: the signing key path is secret-class and env-only, and while
``GRAQLE_DAG_ENABLED`` is off the model is never constructed (flag-off
byte-identical, AC-1).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.provenance_settings
# risk: LOW (new module; consumers are the PR-018b recorder and signer)
# dependencies: pydantic, pydantic_settings, graqle.config.exceptions
# constraints: env-only; defaults are operational safe defaults, no TS values
# -- /graqle:intelligence --
import os
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from graqle.config.exceptions import ENV_FLAG, ConfigurationError

__all__ = [
    "ProvenanceSettings",
    "load_provenance_settings",
    "provenance_env_names",
    "K_MAX_AGE_DEFAULT",
    "K_OVERLAP_DEFAULT",
    "R_SEQ_RETRY_DEFAULT",
    "SKEW_DEFAULT",
]

# Operational safe defaults (symbolic names; the loader rejects zero).
K_MAX_AGE_DEFAULT = 90
K_OVERLAP_DEFAULT = 7
R_SEQ_RETRY_DEFAULT = 5
SKEW_DEFAULT = 5

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_REQUIRED_WHEN_ENABLED = (
    "signing_key_id",
    "signing_key_version",
    "signing_key_path",
    "coverage_policy_path",
)


class ProvenanceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GRAQLE_DAG_",
        extra="forbid",
        frozen=True,
        case_sensitive=False,
        validate_default=True,
        populate_by_name=True,
    )

    merkle_batch: bool = Field(
        default=False,
        validation_alias=AliasChoices("merkle_batch", "GRAQLE_DAG_PROVENANCE_MERKLE_BATCH"),
    )
    signing_key_id: str | None = None
    signing_key_version: int | None = Field(default=None, ge=1)
    signing_key_path: str | None = None  # SECRET-CLASS, env-only
    key_manifest_path: str = ".graqle/dag/key_manifest.json"
    key_max_age_days: int = Field(default=K_MAX_AGE_DEFAULT, ge=1)
    key_overlap_days: int = Field(default=K_OVERLAP_DEFAULT, ge=1)
    args_hash_algo: Literal["sha256-jcs-v1"] = "sha256-jcs-v1"
    sequencer: Literal["neo4j", "file"] = "file"
    seq_retry_budget: int = Field(default=R_SEQ_RETRY_DEFAULT, ge=1)
    salt_escrow: Literal["file", "neo4j"] = "file"
    salt_escrow_dir: str = ".graqle/dag/salts/"
    coverage_policy_path: str | None = None
    clock_skew_tolerance_s: int = Field(default=SKEW_DEFAULT, ge=1)

    @model_validator(mode="after")
    def _overlap_before_retirement(self) -> ProvenanceSettings:
        # A key would retire before its successor overlaps.
        if self.key_max_age_days <= self.key_overlap_days:
            raise ValueError("key_max_age_days must exceed key_overlap_days")
        return self


def provenance_env_names() -> frozenset[str]:
    """Upper-case ``GRAQLE_DAG_*`` names this sub-model owns.

    ``load_dag_settings`` merges these into its drift-lock allow-list, so one
    environment name still maps to exactly one owner (CR-018 spec R3).
    """
    return frozenset(
        "GRAQLE_DAG_" + name.upper() for name in ProvenanceSettings.model_fields
    ) | {"GRAQLE_DAG_PROVENANCE_MERKLE_BATCH"}


def _blank(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def load_provenance_settings(*, force_enabled: bool | None = None) -> ProvenanceSettings | None:
    """Return the settings, or ``None`` when the DAG flag is off.

    Flag on and any of key id / version / path / coverage policy path missing
    or blank raises :class:`ConfigurationError` naming the setting (never the
    value). Fail closed: an invalid value also raises ``ConfigurationError``.
    """
    enabled = (
        force_enabled
        if force_enabled is not None
        else os.environ.get(ENV_FLAG, "").strip().lower() in _TRUTHY
    )
    if not enabled:
        return None
    try:
        settings = ProvenanceSettings()
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        errors = exc.errors() if hasattr(exc, "errors") else []
        names = sorted({str(e["loc"][0]) for e in errors if e.get("loc")})
        raise ConfigurationError(
            f"invalid provenance settings: {', '.join(names) or 'model'}"
        ) from None
    missing = [n for n in _REQUIRED_WHEN_ENABLED if _blank(getattr(settings, n))]
    if missing:
        env_names = ", ".join("GRAQLE_DAG_" + n.upper() for n in missing)
        raise ConfigurationError(f"required when {ENV_FLAG} is set: {env_names}")
    return settings
