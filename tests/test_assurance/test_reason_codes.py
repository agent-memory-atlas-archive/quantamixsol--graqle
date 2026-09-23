"""CR-012 / PR-012b — the closed reason-code registry (CR-012 §4.2, R1 + R2).

AC-8: every seeded code matches the grammar; hard-gate codes are FAIL/CRITICAL;
REGISTRY is immutable; the grammar accepts exactly the specified language
(Hypothesis fuzz).

INV-RC-2 (append-only): a code may be ADDED, never removed and never re-spelled —
CR-014/015/017/018 register through REGISTRY, and a re-spelled code silently
breaks their reason references. This release ships an empty seed, so the
invariant is asserted structurally rather than against a code snapshot; the
snapshot test returns with the seeding that begins in CR-013.

Registry-dependent behaviour (validate/max_severity/resolvable) is exercised
against a local fixture registry built in-test, so these tests do not depend on
which codes the shipped seed happens to contain.
"""

from __future__ import annotations

import re
from types import MappingProxyType

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from graqle.assurance import reason_codes
from graqle.assurance.reason_codes import (
    CODE_PATTERN,
    REGISTRY,
    ReasonCode,
    Severity,
    max_severity,
    resolvable,
    validate,
)

# Fixture registry. Synthetic codes only: these exercise registry-dependent
# behaviour without asserting which codes the shipped seed contains.
_FIXTURE: tuple[ReasonCode, ...] = (
    ReasonCode("DAG-CV-AA", Severity.WARN, "CV", "Advisory; re-run to refresh.", "0.84.1"),
    ReasonCode("DAG-TR-BB", Severity.INFO, "TR", "Informational only.", "0.84.1"),
    ReasonCode("DAG-HG01-CC", Severity.CRITICAL, "HG-01", "", "0.84.1"),
    ReasonCode("DAG-HG02-DD", Severity.FAIL, "HG-02", "Re-run with fresh evidence.", "0.84.1"),
)
_FIXTURE_REGISTRY = {rc.code: rc for rc in _FIXTURE}


@pytest.fixture
def fixture_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the registry-reading helpers at the synthetic fixture set."""
    monkeypatch.setattr(
        reason_codes, "REGISTRY", MappingProxyType(_FIXTURE_REGISTRY)
    )


class TestAppendOnly:
    def test_seed_is_empty_at_this_version(self) -> None:
        # 0.84.1 ships the grammar and the invariants; seeding begins in CR-013.
        # Appending to an empty seed is a plain append, so INV-RC-2 is intact.
        assert dict(REGISTRY) == {}

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

    def test_hard_gate_fail_severity_is_constructible_per_oq4(self) -> None:
        # OQ-4: an HG-02 code is seeded at FAIL (resolvable), not CRITICAL.
        # Asserted on the invariant rather than on a seeded code, since this
        # version ships an empty seed.
        rc = ReasonCode(
            "DAG-HG02-DD", Severity.FAIL, "HG-02", "Re-run with fresh evidence.", "0.84.1"
        )
        assert rc.severity is Severity.FAIL

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

    def test_order_preserved_and_duplicates_removed(
        self, fixture_registry: None
    ) -> None:
        codes = ["DAG-CV-AA", "DAG-TR-BB", "DAG-CV-AA"]
        assert validate(codes) == ["DAG-CV-AA", "DAG-TR-BB"]

    def test_max_severity(self, fixture_registry: None) -> None:
        assert max_severity(["DAG-CV-AA", "DAG-HG01-CC"]) is Severity.CRITICAL
        assert max_severity([]) is None

    def test_resolvable_follows_ruling_r2(self, fixture_registry: None) -> None:
        # INFO/WARN -> resolvable; FAIL with a hint -> resolvable; CRITICAL -> never.
        assert resolvable("DAG-CV-AA") is True
        assert resolvable("DAG-HG02-DD") is True
        assert resolvable("DAG-HG01-CC") is False

    def test_resolvable_rejects_an_unregistered_code(self) -> None:
        with pytest.raises(ValueError, match="unregistered"):
            resolvable("DAG-XX-NOPE")
