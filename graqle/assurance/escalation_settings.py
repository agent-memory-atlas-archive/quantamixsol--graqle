"""DAG-2026 escalation settings (CR-015 section 3.3, PR-015c).

Per-tier review deadlines (seconds), reviewer roles and the queue adapter.
Deadlines are required with no fallback: a missing, zero or malformed one raises
``ConfigurationError``. Roles default to a conservative pair (``senior`` for LOW and
MEDIUM, ``lead`` for HIGH and CRITICAL) and must hold the DAG-ESCALATE permission.

Kept beside ``routing_settings`` so importing ``graqle.assurance.settings`` never
loads the gate (flag-off isolation).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.escalation_settings
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015c escalation router)
# dependencies: os, pathlib, pydantic, graqle.assurance.gate, graqle.assurance.settings, graqle.core.rbac
# constraints: never imported by graqle.governance.*; no deadline value in this file
# -- /graqle:intelligence --
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from graqle.assurance.gate import ImpactTier
from graqle.assurance.settings import ENV_PREFIX, ConfigurationError

__all__ = ["EscalationSettings"]

_SLA_PREFIX = ENV_PREFIX + "ESCALATION_SLA_"
_SLA_SUFFIX = "_SECONDS"
_ROLE_PREFIX = ENV_PREFIX + "ESCALATION_ROLE_"
_QUEUE = ENV_PREFIX + "ESCALATION_QUEUE"
_QUEUE_PATH = ENV_PREFIX + "ESCALATION_QUEUE_PATH"

_DEFAULT_ROLE: dict[ImpactTier, str] = {
    ImpactTier.LOW: "senior",
    ImpactTier.MEDIUM: "senior",
    ImpactTier.HIGH: "lead",
    ImpactTier.CRITICAL: "lead",
}
_DEFAULT_QUEUE_PATH = Path(".graqle/assurance/escalations")


def _require_escalation_role(role: str, where: str) -> None:
    try:
        from graqle.core.rbac import DAG_ESCALATE_TIER, ROLE_PERMISSIONS  # lazy: stdlib leaf
    except ImportError as exc:
        raise ConfigurationError(f"core.rbac unavailable ({type(exc).__name__}); cannot validate {where}") from None
    if DAG_ESCALATE_TIER not in ROLE_PERMISSIONS.get(role, frozenset()):
        raise ConfigurationError(f"{where}: role {role!r} cannot receive escalations")


class EscalationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sla_seconds: dict[ImpactTier, int]
    role: dict[ImpactTier, str]
    queue: Literal["jsonl", "memory", "custom"] = "jsonl"
    queue_path: Path = _DEFAULT_QUEUE_PATH

    @model_validator(mode="after")
    def _complete(self) -> EscalationSettings:
        if set(self.sla_seconds) != set(ImpactTier) or set(self.role) != set(ImpactTier):
            raise ConfigurationError("DAG escalation: sla_seconds and role must define every impact tier")
        for tier, seconds in self.sla_seconds.items():
            if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0:
                raise ConfigurationError(f"DAG escalation: SLA for {tier.value} must be a positive integer")
        for tier, name in self.role.items():
            _require_escalation_role(name, f"{_ROLE_PREFIX}{tier.value}")
        return self

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> EscalationSettings:
        """Load every value; an absent or malformed deadline fails closed."""
        env = os.environ if environ is None else environ
        missing: list[str] = []
        sla: dict[ImpactTier, int] = {}
        roles: dict[ImpactTier, str] = {}
        for tier in ImpactTier:
            name = f"{_SLA_PREFIX}{tier.value}{_SLA_SUFFIX}"
            raw = env.get(name, "").strip()
            if not raw:
                missing.append(name)
            else:
                try:
                    sla[tier] = int(raw)
                except ValueError:
                    raise ConfigurationError(f"{name} is not an integer") from None
            roles[tier] = env.get(_ROLE_PREFIX + tier.value, "").strip() or _DEFAULT_ROLE[tier]
        if missing:
            raise ConfigurationError(
                "DAG escalation settings absent: " + ", ".join(missing) + ". No fallback deadline exists."
            )
        queue = env.get(_QUEUE, "").strip().lower() or "jsonl"
        if queue not in ("jsonl", "memory", "custom"):
            raise ConfigurationError(f"{_QUEUE} must be 'jsonl', 'memory' or 'custom'")
        path_raw = env.get(_QUEUE_PATH, "").strip()
        return cls(
            sla_seconds=sla,
            role=roles,
            queue=queue,  # type: ignore[arg-type]
            queue_path=Path(path_raw) if path_raw else _DEFAULT_QUEUE_PATH,
        )
