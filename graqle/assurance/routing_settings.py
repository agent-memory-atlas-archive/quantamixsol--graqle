"""DAG-2026 routing settings (CR-015 §3.3, PR-015b).

Floors, budgets and the automation ceiling are private-config symbols: this
module names the environment variables and validates them; it never carries a
value. Kept beside ``settings`` (as ``trajectory_settings`` is) so importing
``graqle.assurance.settings`` never loads the gate (flag-off isolation).

Fail closed: a missing or unusable required value raises ``ConfigurationError``;
there is no default for any floor, budget or ceiling.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.routing_settings
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015b gate/adapter)
# dependencies: math, os, pydantic, graqle.assurance.gate, graqle.assurance.settings
# constraints: never imported by graqle.governance.*; no configured value
# -- /graqle:intelligence --
import math
import os
from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from graqle.assurance.gate import ImpactTier
from graqle.assurance.settings import ENV_PREFIX, ConfigurationError

__all__ = [
    "BASELINE_TIER_AUTOMATION_MAX",
    "BaselineRoutingSettings",
    "RoutingSettings",
]

#: Public symbolic ceiling for the baseline admission rule: only LOW risk is admitted.
BASELINE_TIER_AUTOMATION_MAX = ImpactTier.LOW

_FLOOR_PREFIX = ENV_PREFIX + "TRAJECTORY_FLOOR_"
_BUDGET_PREFIX = ENV_PREFIX + "RESIDUAL_RISK_BUDGET_"
_AUTOMATION_MAX = ENV_PREFIX + "TIER_AUTOMATION_MAX"
_COMBINATOR = ENV_PREFIX + "RESIDUAL_RISK_COMBINATOR"


def _open_unit(value: object) -> bool:
    return (
        isinstance(value, float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 < value < 1.0
    )


class BaselineRoutingSettings(BaseModel):
    """Public symbolic settings for DAG-RT-BASELINE-ADMIT only (CR-DAG-087-1 PR-B).

    Deliberately NOT a :class:`RoutingSettings` and carries no floor or budget: the numeric
    routing path (DAG-RT-17 and every MEDIUM+ path) keeps requiring ``RoutingSettings.from_env()``
    and never sees these defaults. The ceiling may be overridden through the environment.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier_automation_max: ImpactTier = BASELINE_TIER_AUTOMATION_MAX

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> BaselineRoutingSettings:
        env = os.environ if environ is None else environ
        raw = env.get(_AUTOMATION_MAX, "").strip().upper()
        if not raw:
            return cls()
        try:
            return cls(tier_automation_max=ImpactTier(raw))
        except ValueError:
            raise ConfigurationError(f"{_AUTOMATION_MAX} is not an impact tier") from None


class RoutingSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    trajectory_floor: dict[ImpactTier, float]
    residual_risk_budget: dict[ImpactTier, float]
    tier_automation_max: ImpactTier
    residual_risk_combinator: Literal["max", "private"] = "max"

    @model_validator(mode="after")
    def _complete(self) -> RoutingSettings:
        for name, table in (
            ("trajectory_floor", self.trajectory_floor),
            ("residual_risk_budget", self.residual_risk_budget),
        ):
            if set(table) != set(ImpactTier):
                raise ConfigurationError(f"DAG routing: {name} must define every impact tier")
            if not all(_open_unit(v) for v in table.values()):
                raise ConfigurationError(f"DAG routing: {name} entries must lie strictly in (0, 1)")
        return self

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> RoutingSettings:
        """Load every required value; any absent or malformed one fails closed."""
        env = os.environ if environ is None else environ
        missing: list[str] = []
        floors: dict[ImpactTier, float] = {}
        budgets: dict[ImpactTier, float] = {}
        for tier in ImpactTier:
            for prefix, table in ((_FLOOR_PREFIX, floors), (_BUDGET_PREFIX, budgets)):
                raw = env.get(prefix + tier.value, "").strip()
                if not raw:
                    missing.append(prefix + tier.value)
                    continue
                try:
                    table[tier] = float(raw)
                except ValueError:
                    raise ConfigurationError(f"{prefix}{tier.value} is not a number") from None
        ceiling_raw = env.get(_AUTOMATION_MAX, "").strip().upper()
        if not ceiling_raw:
            missing.append(_AUTOMATION_MAX)
        if missing:
            raise ConfigurationError(
                "DAG routing settings absent: " + ", ".join(missing) + ". No placeholder fallback exists."
            )
        try:
            ceiling = ImpactTier(ceiling_raw)
        except ValueError:
            raise ConfigurationError(f"{_AUTOMATION_MAX} is not an impact tier") from None
        combinator = env.get(_COMBINATOR, "max").strip().lower() or "max"
        if combinator not in ("max", "private"):
            raise ConfigurationError(f"{_COMBINATOR} must be 'max' or 'private'")
        return cls(
            trajectory_floor=floors,
            residual_risk_budget=budgets,
            tier_automation_max=ceiling,
            residual_risk_combinator=combinator,  # type: ignore[arg-type]
        )
