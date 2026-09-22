"""Single resolver for governance thresholds (CR-012 PR-012c, AC-9..AC-11).

The defect this closes: ``GraqleConfig.governance`` (a ``GovernancePolicyConfig``
parsed from ``graqle.yaml``) and ``GovernanceConfig`` (the dataclass
``GovernanceMiddleware`` actually runs on) declare the SAME eight threshold keys
independently, and nothing ever copied one into the other.
``GovernanceMiddleware.__init__`` did ``config or GovernanceConfig()``, so an
operator who set ``governance.review_threshold`` in ``graqle.yaml`` got the
hard-coded default and no warning. The yaml keys were inert.

Two rules govern this module:

* **Defaults are byte-identical.** With no yaml present, ``resolve_governance_config()``
  returns exactly ``GovernanceConfig()``. AC-9's 64-case golden — generated on the
  v0.83.0 tag — pins that: flag-off behaviour must not move.
* **Values never reach a log.** A threshold is TS-3 tuning. When yaml overrides a
  default this module logs the KEY NAME only, once, at WARNING. Never the value,
  never the default it replaced.
"""

# ── graqle:intelligence ──
# module: graqle.core.governance_thresholds
# risk: LOW (new leaf; one caller — core/governance.py:__init__)
# dependencies: graqle.core.governance (GovernanceConfig)
# constraints: never logs a threshold VALUE (TS-3); defaults byte-identical to v0.83.0
# ── /graqle:intelligence ──

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("graqle.core.governance_thresholds")

#: The keys BOTH config shapes declare. AC-10's drift lock asserts this set
#: stays in sync with the two classes — if either grows a shared key and this
#: tuple is not updated, the resolver would silently ignore it.
SHARED_KEYS: tuple[str, ...] = (
    "ts_hard_block",
    "ts_patterns_file",
    "review_threshold",
    "block_threshold",
    "auto_pass_max_radius",
    "auto_pass_max_risk",
    "cumulative_radius_cap",
    "cumulative_window_hours",
)

#: Warn once per key per process. A gate runs on every tool call; repeating the
#: warning would bury it.
_warned: set[str] = set()


def _reset_warned_for_tests() -> None:
    """Clear the warn-once memo. Test-support only."""
    _warned.clear()


def resolve_governance_config(policy: Any = None) -> Any:
    """Build the ``GovernanceConfig`` the middleware should run on.

    Args:
        policy: a ``GovernancePolicyConfig`` (from ``GraqleConfig.governance``),
            or ``None`` to load it from the resolved ``graqle.yaml``. Anything
            that raises while loading yields plain defaults — a governance gate
            must never fail to construct because config is unreadable.

    Returns:
        ``GovernanceConfig``. With no yaml and no overrides this is exactly
        ``GovernanceConfig()`` (AC-9).
    """
    from graqle.core.governance import GovernanceConfig

    defaults = GovernanceConfig()

    if policy is None:
        policy = _load_policy_from_yaml()
    if policy is None:
        return defaults

    # A governance gate must construct even when the config object misbehaves.
    # `hasattr` only swallows AttributeError — a property that raises anything
    # else (RuntimeError from a config backend, say) would propagate and take
    # the gate down with it. Guard the whole read.
    overrides: dict[str, Any] = {}
    try:
        for key in SHARED_KEYS:
            try:
                value = getattr(policy, key)
            except Exception:  # noqa: BLE001 — one bad key must not lose the rest
                logger.debug("governance.%s unreadable; keeping the default", key)
                continue
            if value is None:
                continue
            if value != getattr(defaults, key, None):
                overrides[key] = value
    except Exception:  # noqa: BLE001 — defaults are always a safe answer
        logger.debug("governance policy unreadable; using defaults")
        return defaults

    if not overrides:
        return defaults

    # TS-3: names only. Never the value, never the default it replaced.
    for key in sorted(overrides):
        if key not in _warned:
            _warned.add(key)
            logger.warning(
                "governance.%s from graqle.yaml overrides the built-in default; "
                "this threshold was previously ignored (CR-012 PR-012c)",
                key,
            )

    return GovernanceConfig(**{**{k: getattr(defaults, k) for k in SHARED_KEYS}, **overrides})


def _load_policy_from_yaml() -> Any:
    """Best-effort ``GraqleConfig.governance``. Never raises."""
    try:
        from graqle.config.settings import GraqleConfig

        loader = getattr(GraqleConfig, "from_yaml", None)
        if loader is None:
            return None
        return getattr(loader("graqle.yaml"), "governance", None)
    except Exception:  # noqa: BLE001 — the gate must construct regardless
        logger.debug("governance policy not loadable from yaml; using defaults")
        return None
