"""CR-012 / PR-012b — the closed reason-code registry (CR-012 §4.2, R1 + R2).

AC-8: every seeded code matches the grammar; hard-gate codes are FAIL/CRITICAL;
REGISTRY is immutable; the grammar accepts exactly the specified language
(Hypothesis fuzz).

INV-RC-2 (append-only): the seed-code snapshot below is a MERGE GATE. A code may
be ADDED, never removed and never re-spelled — CR-014/015/017/018 register
through REGISTRY, and a re-spelled code silently breaks their reason references.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from graqle.assurance.reason_codes import (
    CODE_PATTERN,
    REGISTRY,
    ReasonCode,
    Severity,
    max_severity,
    resolvable,
    validate,
)

# INV-RC-2 append-only snapshot. ADD to this list; never delete, never re-spell.
_SEEDED_AT_0_85_0 = {
    "DAG-CV-BELOW_PROJECTION",
    "DAG-CV-CALIBRATOR_STALE",
    "DAG-CV-DIM_MISSING",
    "DAG-CV-RAW_CAL_DIVERGENCE",
    "DAG-HG01-POLICY_EXPIRED",
    "DAG-HG01-POLICY_MISSING",
    "DAG-HG01-POLICY_UNRESOLVED",
    "DAG-HG01-POLICY_VIOLATED",
    "DAG-HG02-EVIDENCE_INVALIDATED",
    "DAG-HG02-RECOMPUTE_INCOMPLETE",
    "DAG-HG03-PROVENANCE_MISSING",
    "DAG-HG04-ARGS_HASH_ALGO_MISMATCH",
    "DAG-HG04-ARGS_HASH_MISMATCH",
    "DAG-HG04-BINDING_ABSENT",
    "DAG-HG05-POISONING_DETECTED",
    "DAG-HG06-ACTOR_UNAUTHORIZED",
    "DAG-HG06-RBAC_UNAVAILABLE",
    "DAG-HG07-CONTRADICTION_UNRESOLVED",
    "DAG-PV-CHAIN_BREAK",
    "DAG-PV-SEQUENCE_GAP",
    "DAG-RP-CAP_APPLIED",
    "DAG-RP-EVALUATION_ERROR",
    "DAG-RP-RETRY_BUDGET_EXHAUSTED",
    "DAG-RP-UNCHANGED_REASON",
    "DAG-TR-EARLY_ERROR",
    "DAG-TR-RELIABILITY_LOW",
}


class TestAppendOnly:
    def test_no_seeded_code_was_removed_or_respelled(self) -> None:
        missing = sorted(_SEEDED_AT_0_85_0 - set(REGISTRY))
        assert not missing, (
            f"INV-RC-2 violated — codes removed or re-spelled: {missing}. "
            "Reason codes are append-only across versions."
        )

    def test_registry_is_immutable(self) -> None:
        with pytest.raises(TypeError):
            REGISTRY["DAG-CV-NEW"] = None  # type: ignore[index]


class TestGrammarAndSeverity:
    def test_every_seeded_code_matches_the_grammar(self) -> None:
        assert not [c for c in REGISTRY if not CODE_PATTERN.match(c)]

    def test_hard_gate_codes_are_never_advisory(self) -> None:
        # INV-RC-3
        advisory = [
            c
            for c, rc in REGISTRY.items()
            if rc.owner_gate.startswith("HG-")
            and rc.severity in (Severity.INFO, Severity.WARN)
        ]
        assert not advisory

    def test_hg02_is_seeded_at_fail_per_oq4(self) -> None:
        assert REGISTRY["DAG-HG02-EVIDENCE_INVALIDATED"].severity is Severity.FAIL
        assert REGISTRY["DAG-HG02-RECOMPUTE_INCOMPLETE"].severity is Severity.FAIL

    def test_remediation_hints_state_no_numbers(self) -> None:
        # Hints are PUBLIC strings; a threshold must never appear (CR-012 §12).
        numeric = re.compile(r"\d")
        offenders = {
            c: rc.remediation_hint
            for c, rc in REGISTRY.items()
            if numeric.search(rc.remediation_hint)
        }
        assert not offenders, offenders

    def test_construction_rejects_a_bad_spelling(self) -> None:
        with pytest.raises(ValueError, match="grammar"):
            ReasonCode("BAD-CODE", Severity.FAIL, "CV", "hint", "0.85.0")

    def test_construction_rejects_an_advisory_hard_gate_code(self) -> None:
        # The suffix must be >= 2 chars, otherwise the GRAMMAR check fires first
        # and INV-RC-3 is never reached. "XX" is well-formed, so this test
        # actually exercises the severity invariant.
        with pytest.raises(ValueError, match="INV-RC-3"):
            ReasonCode("DAG-HG01-XX", Severity.WARN, "HG-01", "hint", "0.85.0")

    def test_grammar_is_checked_before_severity(self) -> None:
        # A malformed code fails on grammar even when it is also advisory.
        with pytest.raises(ValueError, match="grammar"):
            ReasonCode("DAG-HG01-X", Severity.WARN, "HG-01", "hint", "0.85.0")


class TestGrammarFuzz:
    """AC-8 — the grammar accepts exactly the specified language."""

    @given(
        namespace=st.sampled_from(
            ["HG01", "HG02", "HG03", "HG04", "HG05", "HG06", "HG07", "CV", "TR", "PV", "RP"]
        ),
        suffix=st.text(
            alphabet=st.sampled_from(list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")),
            min_size=2,
            max_size=48,
        ),
    )
    @settings(max_examples=200, deadline=None)
    def test_well_formed_codes_are_accepted(self, namespace: str, suffix: str) -> None:
        assert CODE_PATTERN.match(f"DAG-{namespace}-{suffix}")

    @given(st.text(max_size=60))
    @settings(max_examples=300, deadline=None)
    def test_arbitrary_text_is_accepted_only_if_it_matches(self, raw: str) -> None:
        # The regex is the single source of truth; this asserts no other
        # acceptance path exists.
        expected = bool(
            re.match(r"^DAG-(HG0[1-7]|CV|TR|PV|RP)-[A-Z0-9_-]{2,48}$", raw)
        )
        assert bool(CODE_PATTERN.match(raw)) is expected

    @given(st.sampled_from(["DAG-HG08-X", "DAG-XX-YY", "dag-cv-lower", "DAG-CV-A", ""]))
    def test_known_bad_shapes_are_rejected(self, raw: str) -> None:
        assert not CODE_PATTERN.match(raw)


class TestValidateAndSeverityHelpers:
    def test_unknown_codes_fail_closed(self) -> None:
        with pytest.raises(ValueError, match="unregistered"):
            validate(["DAG-XX-NOPE"])

    def test_order_preserved_and_duplicates_removed(self) -> None:
        codes = ["DAG-CV-DIM_MISSING", "DAG-TR-EARLY_ERROR", "DAG-CV-DIM_MISSING"]
        assert validate(codes) == ["DAG-CV-DIM_MISSING", "DAG-TR-EARLY_ERROR"]

    def test_max_severity(self) -> None:
        assert (
            max_severity(["DAG-CV-DIM_MISSING", "DAG-HG01-POLICY_MISSING"])
            is Severity.CRITICAL
        )
        assert max_severity([]) is None

    def test_resolvable_follows_ruling_r2(self) -> None:
        # INFO/WARN -> resolvable; FAIL with a hint -> resolvable; CRITICAL -> never.
        assert resolvable("DAG-CV-BELOW_PROJECTION") is True
        assert resolvable("DAG-HG02-EVIDENCE_INVALIDATED") is True
        assert resolvable("DAG-HG01-POLICY_MISSING") is False

    def test_resolvable_rejects_an_unregistered_code(self) -> None:
        with pytest.raises(ValueError, match="unregistered"):
            resolvable("DAG-XX-NOPE")
