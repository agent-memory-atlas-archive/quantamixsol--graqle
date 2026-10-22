"""DAG-2026 causal baselines (CR-014 §2.7, PR-014a).

Five deterministic baselines, each mapping ONE feature that is available at a
checkpoint to a score in [0, 1], and their geometric combination:

* ``b_steps``  — elapsed steps           (non-increasing)
* ``b_retry``  — retry count             (non-increasing)
* ``b_contra`` — unresolved contradictions (non-increasing)
* ``b_fresh``  — evidence freshness      (non-decreasing)
* ``b_tool``   — tool failure history    (non-increasing)
* ``b_combined`` — product of the five, each raised to a positive exponent, so
  a collapse of any one baseline dominates the combination.

They are the E2 comparison arms and the input of CR-015's
``CausalBaselineEstimator``. None of them reads future length, final outcome or
anything after the checkpoint; CR-015's frozen ``HistoryView`` enforces that.

Configuration rule (CR-014 §12): the per-feature maps and the exponents
are PRIVATE. This module contains no values for them and no defaults. They
arrive as a :class:`CausalBaselineParams` built from private configuration
(CR-014 PR-014c); its ``repr`` is redacted, and results carry only a keyed
commitment to it (``config_version``), never its content.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.causal_baselines
# risk: LOW (impact radius: 0 existing callers -- consumed by CR-014d / CR-015)
# dependencies: hashlib, hmac, math, numpy, pydantic, graqle.assurance.settings,
#   graqle.governance.tamper_evidence.canonicalize (lazy)
# constraints: never imported by graqle.governance.*; no numeric literal for
#   any map knot or exponent (private formula)
# -- /graqle:intelligence --
import hashlib
import hmac
import math
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, model_validator

from graqle.assurance.settings import ConfigurationError, DagSettings, config_version

__all__ = [
    "BASELINE_NAMES",
    "RULE_VERSION",
    "CausalBaselineInput",
    "CausalBaselineParams",
    "CausalBaselineScores",
    "MonotoneMap",
    "baseline_scores",
]

RULE_VERSION = "1"

#: The five baselines, in a fixed order.
BASELINE_NAMES: tuple[str, ...] = ("steps", "retry", "contra", "fresh", "tool")

#: Required direction of each map: larger input ⇒ lower score, except freshness.
_DIRECTION: dict[str, Literal["non_increasing", "non_decreasing"]] = {
    "steps": "non_increasing",
    "retry": "non_increasing",
    "contra": "non_increasing",
    "fresh": "non_decreasing",
    "tool": "non_increasing",
}

_PARAMS_COMMITMENT_LABEL = b"graqle.assurance.causal_baselines.params.v1"


class CausalBaselineInput(BaseModel):
    """Checkpoint-available features for one decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    elapsed_steps: int = Field(ge=0)
    retry_count: int = Field(ge=0)
    unresolved_contradictions: int = Field(ge=0)
    #: raw temporal validity over accepted evidence, [0, 1]
    evidence_freshness: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    #: failure rate over the history window, [0, 1]
    tool_failure_history: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)


class MonotoneMap(BaseModel):
    """Piecewise-linear map through private knots, clamped at both ends.

    ``knots_x`` strictly increasing and non-negative; ``knots_y`` in [0, 1].
    Direction is checked by :class:`CausalBaselineParams`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    knots_x: tuple[float, ...]
    knots_y: tuple[float, ...]

    @model_validator(mode="after")
    def _shape(self) -> MonotoneMap:
        xs, ys = self.knots_x, self.knots_y
        if len(xs) < 2 or len(xs) != len(ys):
            raise ValueError("a monotone map needs at least two knots, x and y of equal length")
        if not all(math.isfinite(v) for v in (*xs, *ys)):
            raise ValueError("map knots must be finite")
        if xs[0] < 0 or any(b <= a for a, b in zip(xs, xs[1:])):
            raise ValueError("knots_x must be non-negative and strictly increasing")
        if any(not 0.0 <= y <= 1.0 for y in ys):
            raise ValueError("knots_y must lie in [0, 1]")
        return self

    def __call__(self, x: float) -> float:
        return float(np.interp(x, self.knots_x, self.knots_y))

    def is_monotone(self, direction: Literal["non_increasing", "non_decreasing"]) -> bool:
        pairs = list(zip(self.knots_y, self.knots_y[1:]))
        if direction == "non_increasing":
            return all(b <= a for a, b in pairs)
        return all(b >= a for a, b in pairs)

    def __repr__(self) -> str:  # never print private knots
        return "MonotoneMap(<private>)"

    __str__ = __repr__


class CausalBaselineParams(BaseModel):
    """PRIVATE map knots and exponents. Built from private configuration only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    maps: dict[str, MonotoneMap]
    exponents: dict[str, float]

    @model_validator(mode="after")
    def _complete_and_monotone(self) -> CausalBaselineParams:
        names = set(BASELINE_NAMES)
        if set(self.maps) != names or set(self.exponents) != names:
            raise ValueError(f"maps and exponents must cover exactly {sorted(names)}")
        for name in BASELINE_NAMES:
            if not self.maps[name].is_monotone(_DIRECTION[name]):
                raise ValueError(f"map {name!r} must be {_DIRECTION[name].replace('_', '-')}")
            rho = self.exponents[name]
            if not (math.isfinite(rho) and rho > 0):
                raise ValueError(f"exponent {name!r} must be finite and > 0")
        return self

    def __repr__(self) -> str:  # never print private knots or exponents
        return "CausalBaselineParams(<private>)"

    __str__ = __repr__


class CausalBaselineScores(BaseModel):
    """Baseline scores plus their determinism record. Carries no parameter values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    b_steps: float = Field(ge=0.0, le=1.0)
    b_retry: float = Field(ge=0.0, le=1.0)
    b_contra: float = Field(ge=0.0, le=1.0)
    b_fresh: float = Field(ge=0.0, le=1.0)
    b_tool: float = Field(ge=0.0, le=1.0)
    b_combined: float = Field(ge=0.0, le=1.0)
    inputs_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    rule_version: str
    config_version: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")


def baseline_scores(
    inp: CausalBaselineInput, *, params: CausalBaselineParams, settings: DagSettings
) -> CausalBaselineScores:
    """Compute the five baselines and their combination, deterministically.

    ``params`` and ``settings`` are keyword-only: until PR-014c introduces the
    confidence-vector settings, a caller written against the spec signature
    must fail loudly rather than pass arguments in the wrong positions.

    ``config_version`` is an HMAC (keyed by the deployment salt) over the DAG
    settings fingerprint and the private parameters, so two deployments can
    tell whether they ran the same baselines without either seeing the values.
    Raises :class:`ConfigurationError` when no salt is configured.
    """
    features = {
        "steps": float(inp.elapsed_steps),
        "retry": float(inp.retry_count),
        "contra": float(inp.unresolved_contradictions),
        "fresh": inp.evidence_freshness,
        "tool": inp.tool_failure_history,
    }
    b = {name: min(1.0, max(0.0, params.maps[name](features[name]))) for name in BASELINE_NAMES}
    combined = 1.0
    for name in BASELINE_NAMES:
        combined *= b[name] ** params.exponents[name]
    return CausalBaselineScores(
        b_steps=b["steps"],
        b_retry=b["retry"],
        b_contra=b["contra"],
        b_fresh=b["fresh"],
        b_tool=b["tool"],
        b_combined=min(1.0, max(0.0, combined)),
        inputs_hash=_sha256(inp.model_dump()),
        rule_version=RULE_VERSION,
        config_version=_params_commitment(params, settings),
    )


def _canon(record: dict[str, Any]) -> bytes:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return canon(record)


def _sha256(record: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canon(record)).hexdigest()


def _params_commitment(params: CausalBaselineParams, settings: DagSettings) -> str:
    salt = settings.config_salt.get_secret_value() if settings.config_salt else ""
    if not salt.strip():
        raise ConfigurationError(
            "causal baselines need GRAQLE_DAG_CONFIG_SALT for a keyed parameter commitment"
        )
    payload = {
        "settings": config_version(settings),
        "maps": {
            name: {"x": list(m.knots_x), "y": list(m.knots_y)} for name, m in params.maps.items()
        },
        "exponents": dict(params.exponents),
    }
    mac = hmac.new(salt.encode("utf-8"), _PARAMS_COMMITMENT_LABEL + _canon(payload), hashlib.sha256)
    return "hmac-sha256:" + mac.hexdigest()
