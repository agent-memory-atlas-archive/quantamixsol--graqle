"""CR-013 AC-4 — HG-03 provenance for high-impact actions."""

from __future__ import annotations

import pytest

from graqle.assurance.hard_gates import _RISK_ORDER, HG03ProvenanceForHighImpact

from ._builders import make_ctx, make_settings

GATE = HG03ProvenanceForHighImpact()
TIERS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@pytest.mark.parametrize("tier_min", TIERS)
@pytest.mark.parametrize("risk", TIERS)
def test_tier_comparison_over_every_pair(risk: str, tier_min: str) -> None:
    s = make_settings(hg03_impact_tier_min=tier_min)
    no_prov = GATE.evaluate(make_ctx(risk_level=risk), s)
    with_prov = GATE.evaluate(
        make_ctx(risk_level=risk, provenance_event_ids=("e1",), provenance_source_ids=("s1",)), s
    )
    assert with_prov.passed
    if _RISK_ORDER[risk] < _RISK_ORDER[tier_min]:
        assert no_prov.passed  # below the minimum ⇒ PASS regardless of provenance
    else:
        assert not no_prov.passed
        assert no_prov.reason_codes == ("DAG-HG03-PROVENANCE_MISSING",)


@pytest.mark.parametrize("risk", [None, "", "unknown", "severe", "  high  "])
def test_unknown_risk_is_treated_as_critical(risk: str | None) -> None:
    s = make_settings(hg03_impact_tier_min="CRITICAL")
    r = GATE.evaluate(make_ctx(risk_level=risk), s)
    expected_pass = risk is not None and risk.strip().upper() == "HIGH"
    assert r.passed is expected_pass


@pytest.mark.parametrize(
    ("events", "sources"),
    [((), ()), (("e1",), ()), ((), ("s1",)), (("e1", "e1", "e1"), ())],
)
def test_events_and_sources_are_both_required(events, sources, settings) -> None:  # type: ignore[no-untyped-def]
    r = GATE.evaluate(
        make_ctx(risk_level="CRITICAL", provenance_event_ids=events, provenance_source_ids=sources),
        settings,
    )
    assert not r.passed


def test_tier_min_is_committed_by_config_version_not_projected() -> None:
    """The projection omits the tier minimum; config_version must still move with it."""
    ctx = make_ctx(risk_level="HIGH")
    a = GATE.evaluate(ctx, make_settings(hg03_impact_tier_min="HIGH"))
    b = GATE.evaluate(ctx, make_settings(hg03_impact_tier_min="CRITICAL"))
    assert a.inputs_hash == b.inputs_hash
    assert a.config_version != b.config_version
    assert "tier" not in GATE.project(ctx)


def test_risk_order_mirrors_core_governance() -> None:
    """CR-013 OQ-2: copied, not imported — this parity test keeps the copy honest."""
    from graqle.core.governance import GovernanceConfig

    core = GovernanceConfig()
    assert _RISK_ORDER == core._RISK_ORDER
    for junk in (None, "", "unknown", 3):
        assert core.risk_to_int(junk) == _RISK_ORDER["CRITICAL"]
