"""CR-013 AC-3 — HG-01 mandatory policy, retrieved by scope (C04, C05)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from graqle.assurance.hard_gates import HG01MandatoryPolicy, PolicyRef

from ._builders import NOW, make_ctx

GATE = HG01MandatoryPolicy()


def test_passes_with_policy_in_force(settings) -> None:  # type: ignore[no-untyped-def]
    r = GATE.evaluate(make_ctx(), settings)
    assert r.passed and r.reason_codes == () and r.error is None


@pytest.mark.parametrize(
    ("overrides", "condition", "code"),
    [
        ({"policy": None}, "policy_missing", "DAG-HG01-POLICY_MISSING"),
        (
            {"policy": PolicyRef(policy_id="p", valid_until=NOW - timedelta(seconds=1))},
            "policy_expired",
            "DAG-HG01-POLICY_EXPIRED",
        ),
        (
            {"policy": PolicyRef(policy_id="p", valid_from=NOW + timedelta(seconds=1))},
            "policy_not_yet_valid",
            "DAG-HG01-POLICY_EXPIRED",
        ),
        (
            {"policy": PolicyRef(policy_id="p", open_contradiction_ids=("p-other",))},
            "policy_unresolved",
            "DAG-HG01-POLICY_UNRESOLVED",
        ),
        ({"policy_violations": ("rule-7",)}, "policy_violated", "DAG-HG01-POLICY_VIOLATED"),
    ],
)
def test_each_condition_fires_its_code(overrides, condition, code, settings) -> None:  # type: ignore[no-untyped-def]
    r = GATE.evaluate(make_ctx(**overrides), settings)
    assert not r.passed
    assert r.decisive_conditions == (condition,)
    assert r.reason_codes == (code,)
    assert r.severity == "CRITICAL"


def test_expiry_boundary_is_strict(settings) -> None:  # type: ignore[no-untyped-def]
    at_expiry = make_ctx(policy=PolicyRef(policy_id="p", valid_until=NOW))
    assert GATE.evaluate(at_expiry, settings).passed


def test_multiple_conditions_are_all_reported(settings) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(
        policy=PolicyRef(
            policy_id="p", valid_until=NOW - timedelta(days=1), open_contradiction_ids=("q",)
        ),
        policy_violations=("v",),
    )
    r = GATE.evaluate(ctx, settings)
    assert r.decisive_conditions == ("policy_expired", "policy_unresolved", "policy_violated")
    assert r.reason_codes == (
        "DAG-HG01-POLICY_EXPIRED",
        "DAG-HG01-POLICY_UNRESOLVED",
        "DAG-HG01-POLICY_VIOLATED",
    )


def test_c04_scope_resolved_policy_counts_regardless_of_wording(settings) -> None:  # type: ignore[no-untyped-def]
    """C04: a policy whose id/wording shares nothing with the scope still governs.

    The gate never compares text; resolution by scope is the caller's contract.
    """
    ctx = make_ctx(
        governance_scope="repo:graqle/path:core/**",
        policy=PolicyRef(policy_id="zz-unrelated-wording-9f3"),
    )
    assert GATE.evaluate(ctx, settings).passed
