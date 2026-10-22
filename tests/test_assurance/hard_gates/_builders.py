"""Builders for the CR-013 hard-gate tests.

Thresholds are the TEST SUBSTITUTES already used by ``test_settings.py``
(CR-013 §12) — never deployed values.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from graqle.assurance.hard_gates import GateContext, PolicyRef
from graqle.assurance.settings import DagSettings

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
HG05_SUB = 0.61
HG07_SUB = 0.51

SUBSTITUTE_SETTINGS: dict[str, Any] = {
    "config_salt": "test-substitute-salt-0123456789abcdef-XYZ",
    "cap_value": 0.31,
    "hg05_poisoning_threshold": HG05_SUB,
    "hg07_materiality_threshold": HG07_SUB,
}


def leaks(secret: float, text: str) -> bool:
    """True if ``repr(secret)`` occurs in ``text`` as a whole numeric token.

    A bare substring test false-positives on unrelated digits (e.g. 0.31 inside
    a measured ``duration_ms=0.3131...``), which made the leak guards flaky.
    """
    return re.search(rf"(?<![\d.]){re.escape(repr(secret))}(?![\d])", text) is not None


def make_settings(**overrides: Any) -> DagSettings:
    return DagSettings(**{**SUBSTITUTE_SETTINGS, **overrides})


def make_ctx(**overrides: Any) -> GateContext:
    """A context on which every LIVE gate passes; each test flips one condition."""
    base: dict[str, Any] = {
        "now": NOW,
        "governance_scope": "repo:graqle/path:core/**",
        "policy": PolicyRef(
            policy_id="policy-core",
            valid_from=NOW - timedelta(days=30),
            valid_until=NOW + timedelta(days=30),
        ),
        "risk_level": "LOW",
        "poisoning_severity": 0.0,
        "actor_id": "alice",
        "required_tier": "T1",
    }
    base.update(overrides)
    return GateContext(**base)
