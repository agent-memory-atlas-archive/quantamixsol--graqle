"""DAG-2026 replan settings (CR-015 section 3.3, PR-015c).

The retry budget is a private, required value: this module names the environment
variable and validates it; it never carries a value. A missing, zero, negative,
boolean or non-integer budget raises ``ConfigurationError`` (no fallback).

Kept beside ``routing_settings`` so importing ``graqle.assurance.settings`` never
loads the gate (flag-off isolation).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.replan_settings
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-015c replan controller wiring)
# dependencies: os, pydantic, graqle.assurance.settings
# constraints: never imported by graqle.governance.*; no budget value in this file
# -- /graqle:intelligence --
import os
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

from graqle.assurance.settings import ENV_PREFIX, ConfigurationError

__all__ = ["ReplanSettings"]

_MAX_RETRY_BUDGET = ENV_PREFIX + "MAX_RETRY_BUDGET"


class ReplanSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_retry_budget: int

    @model_validator(mode="before")
    @classmethod
    def _positive(cls, data: Any) -> Any:
        # Before-mode: pydantic would otherwise coerce ``True`` to 1 and ``"3"`` to 3.
        budget = data.get("max_retry_budget") if isinstance(data, dict) else None
        if isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0:
            raise ConfigurationError(f"{_MAX_RETRY_BUDGET} must be a positive integer")
        return data

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ReplanSettings:
        """Load the budget; an absent, zero or malformed value fails closed."""
        env = os.environ if environ is None else environ
        raw = env.get(_MAX_RETRY_BUDGET, "").strip()
        if not raw:
            raise ConfigurationError(
                f"DAG replan settings absent: {_MAX_RETRY_BUDGET}. No fallback budget exists."
            )
        try:
            budget = int(raw)
        except ValueError:
            raise ConfigurationError(f"{_MAX_RETRY_BUDGET} is not an integer") from None
        return cls(max_retry_budget=budget)
