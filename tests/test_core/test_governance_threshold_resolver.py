"""CR-012 PR-012c — AC-9, AC-10, AC-11: the single governance threshold resolver.

Before this, `GraqleConfig.governance` (parsed from graqle.yaml) and
`GovernanceConfig` (what the middleware runs on) declared the same eight keys
independently, and nothing copied one into the other. An operator who set
`governance.review_threshold` in graqle.yaml got the hard-coded default, with no
warning. The yaml keys were inert.

AC-9  — flag-off behaviour is byte-identical. The 64-case golden was generated
        ON THE v0.83.0 TAG by `scripts/gen_gate_result_golden.py`, not by this
        branch; a golden produced by the code under test would prove nothing.
        sha256: f724ff4e125eac46d6993b6b2afbe10dfd3c18a29a3156311edb4114b2735af4
AC-10 — the two config shapes agree on their shared keys (drift lock).
AC-11 — a yaml override is honoured, and a WARNING is logged once.

TS review focus: a threshold is TS-3 tuning. The resolver logs KEY NAMES only.
`test_warning_never_contains_a_threshold_value` is the guard.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest

from graqle.core.governance import GateResult, GovernanceConfig, GovernanceMiddleware
from graqle.core.governance_thresholds import (
    SHARED_KEYS,
    _reset_warned_for_tests,
    resolve_governance_config,
)

_GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "gate_result_golden_v0830.json"
_GOLDEN_SHA256 = "f724ff4e125eac46d6993b6b2afbe10dfd3c18a29a3156311edb4114b2735af4"


@pytest.fixture(autouse=True)
def _isolate_state() -> None:
    """Reset both process-global memos this module touches.

    `_warned` is the resolver's warn-once set; `_cumulative` is
    GovernanceMiddleware's class-level anti-gaming ledger. Leaving either
    populated leaks into sibling tests.
    """
    _reset_warned_for_tests()
    GovernanceMiddleware._cumulative.clear()


class TestAC9GoldenUnchanged:
    """Flag-off behaviour must not move."""

    def test_golden_fixture_is_the_v0830_artifact(self) -> None:
        # Pin the fixture itself: if someone regenerates it on the branch under
        # test, the golden stops being evidence and this test says so.
        digest = hashlib.sha256(_GOLDEN.read_bytes()).hexdigest()
        assert digest == _GOLDEN_SHA256, (
            "the golden fixture no longer matches the sha256 recorded in the "
            "PR description; it must be generated on the v0.83.0 tag"
        )

    def test_current_output_matches_the_v0830_golden(self) -> None:
        cases = json.loads(_GOLDEN.read_text(encoding="utf-8"))
        assert len(cases) == 64

        mismatches: list[str] = []
        for case in cases:
            payload = case["in"]
            # The replay MUST mirror the generator's isolation exactly.
            # `_cumulative` is a CLASS attribute persisted to
            # .graqle/gov_cumulative.json and loaded once per process
            # (`_state_loaded`), so a fresh instance is NOT enough: state leaks
            # across cases and across runs, and each row would depend on every
            # prior row. Clear the class dict and short-circuit the disk read.
            GovernanceMiddleware._cumulative.clear()
            GovernanceMiddleware._state_loaded = True
            middleware = GovernanceMiddleware(config=GovernanceConfig())
            result = middleware.check(
                diff=payload["diff"],
                file_path="src/mod.py",
                risk_level=payload["risk"],
                impact_radius=payload["radius"],
                approved_by=payload["approved_by"],
                action="edit",
                actor=payload["actor"],
            )
            if result.to_dict() != case["out"]:
                mismatches.append(
                    f"{payload} -> {result.to_dict()} != {case['out']}"
                )
        assert not mismatches, "flag-off output drifted from v0.83.0:\n" + "\n".join(
            mismatches[:5]
        )

    def test_defaults_are_untouched_without_yaml(self, tmp_path: Path, monkeypatch) -> None:
        # No graqle.yaml at all -> exactly GovernanceConfig().
        monkeypatch.chdir(tmp_path)
        assert resolve_governance_config() == GovernanceConfig()

    def test_gate_result_shape_is_unchanged(self) -> None:
        # The golden compares to_dict(); pin the key set so a field addition is
        # a deliberate act, not a silent golden rewrite.
        result = GateResult(tier="T1", blocked=False, requires_approval=False,
                            gate_score=0.0, reason="")
        assert set(result.to_dict()) == {
            "tier", "blocked", "requires_approval", "gate_score", "reason",
            "warnings", "bypass_allowed", "risk_level", "impact_radius",
        }


class TestAC10DriftLock:
    """The two config shapes must keep agreeing on their shared keys."""

    def test_shared_keys_exist_on_both_shapes(self) -> None:
        from graqle.config.settings import GovernancePolicyConfig

        policy_fields = set(GovernancePolicyConfig.model_fields)
        governance_fields = set(GovernanceConfig().__dict__)
        for key in SHARED_KEYS:
            assert key in policy_fields, f"{key} missing from GovernancePolicyConfig"
            assert key in governance_fields, f"{key} missing from GovernanceConfig"

    def test_shared_key_defaults_agree(self) -> None:
        from graqle.config.settings import GovernancePolicyConfig

        policy = GovernancePolicyConfig()
        governance = GovernanceConfig()
        drift = {
            key: (getattr(policy, key), getattr(governance, key))
            for key in SHARED_KEYS
            if getattr(policy, key) != getattr(governance, key)
        }
        assert not drift, f"shared-key defaults have drifted: {drift}"

    def test_shared_keys_is_not_silently_incomplete(self) -> None:
        # If BOTH shapes grow the same new key, SHARED_KEYS must learn about it
        # or the resolver will ignore it — the exact defect this PR closes.
        from graqle.config.settings import GovernancePolicyConfig

        common = set(GovernancePolicyConfig.model_fields) & set(GovernanceConfig().__dict__)
        missing = common - set(SHARED_KEYS)
        assert not missing, (
            f"these keys exist on both config shapes but are absent from "
            f"SHARED_KEYS, so the resolver ignores them: {sorted(missing)}"
        )


class TestAC11YamlIsHonoured:
    """A yaml override must reach the middleware, and say so once."""

    def _policy(self, **overrides):
        from graqle.config.settings import GovernancePolicyConfig

        return GovernancePolicyConfig(**overrides)

    def test_override_is_applied(self) -> None:
        resolved = resolve_governance_config(self._policy(review_threshold=0.31))
        assert resolved.review_threshold == 0.31

    def test_untouched_keys_keep_their_defaults(self) -> None:
        resolved = resolve_governance_config(self._policy(review_threshold=0.31))
        defaults = GovernanceConfig()
        assert resolved.block_threshold == defaults.block_threshold
        assert resolved.ts_hard_block == defaults.ts_hard_block

    def test_warning_is_logged_for_an_override(self, caplog) -> None:
        with caplog.at_level(logging.WARNING):
            resolve_governance_config(self._policy(review_threshold=0.31))
        warnings = [r for r in caplog.records if "review_threshold" in r.getMessage()]
        assert warnings, "an override that was previously ignored must be announced"

    def test_warning_is_logged_only_once(self, caplog) -> None:
        with caplog.at_level(logging.WARNING):
            resolve_governance_config(self._policy(review_threshold=0.31))
            resolve_governance_config(self._policy(review_threshold=0.31))
        warnings = [r for r in caplog.records if "review_threshold" in r.getMessage()]
        assert len(warnings) == 1, "the gate runs per tool call; do not repeat"

    def test_warning_never_contains_a_threshold_value(self, caplog) -> None:
        # TS-3: names only. A value in a log line is a leak.
        with caplog.at_level(logging.WARNING):
            resolve_governance_config(self._policy(review_threshold=0.31))
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "0.31" not in text
        assert "0.70" not in text

    def test_no_warning_when_yaml_matches_the_default(self, caplog) -> None:
        with caplog.at_level(logging.WARNING):
            resolve_governance_config(self._policy())
        assert not [r for r in caplog.records if "overrides" in r.getMessage()]

    def test_explicit_config_still_wins(self) -> None:
        # An explicitly-passed config must not be second-guessed by yaml.
        explicit = GovernanceConfig(review_threshold=0.37)
        assert GovernanceMiddleware(config=explicit).config is explicit

    def test_resolver_never_raises_on_bad_config(self, monkeypatch) -> None:
        class _Exploding:
            def __getattr__(self, name: str):
                raise RuntimeError("config backend down")

        # A governance gate must construct even when config is unreadable.
        assert resolve_governance_config(_Exploding()) is not None
