"""CR-012 / PR-012b — ``graqle.assurance.outcomes`` (CR-012 §4.1).

Pins the five-member vocabulary, the terminal predicate and the severity order
CR-015 composes with. No numeric threshold appears here (CR-012 §12).
"""

from __future__ import annotations

import pytest

from graqle.assurance.outcomes import OUTCOME_SEVERITY, GateOutcome, worst


class TestVocabulary:
    def test_exactly_five_members(self) -> None:
        assert [o.value for o in GateOutcome] == [
            "EXECUTE",
            "REPLAN",
            "HOLD",
            "REJECT",
            "ESCALATE",
        ]

    def test_str_valued_so_it_serialises_without_an_encoder(self) -> None:
        import json

        assert json.dumps({"o": GateOutcome.HOLD}) == '{"o": "HOLD"}'

    def test_does_not_extend_governance_decision(self) -> None:
        # Senior Q1 unanimous: GateOutcome is a separate vocabulary.
        from graqle.governance.trace_schema import Decision

        assert not issubclass(GateOutcome, Decision)
        assert {o.value for o in GateOutcome}.isdisjoint({d.value for d in Decision})


class TestTerminal:
    @pytest.mark.parametrize("outcome", [GateOutcome.REJECT, GateOutcome.ESCALATE])
    def test_terminal_outcomes(self, outcome: GateOutcome) -> None:
        assert outcome.terminal is True

    @pytest.mark.parametrize(
        "outcome", [GateOutcome.EXECUTE, GateOutcome.HOLD, GateOutcome.REPLAN]
    )
    def test_non_terminal_outcomes(self, outcome: GateOutcome) -> None:
        assert outcome.terminal is False

    def test_replan_is_explicitly_not_terminal(self) -> None:
        # REPLAN re-enters the gate; CR-015's circuit breaker stops the loop,
        # not this flag. Regression guard for the spec's explicit statement.
        assert GateOutcome.REPLAN.terminal is False


class TestSeverityOrder:
    def test_every_member_is_ranked(self) -> None:
        assert set(OUTCOME_SEVERITY) == set(GateOutcome)

    def test_execute_is_least_severe_and_reject_most(self) -> None:
        assert OUTCOME_SEVERITY[GateOutcome.EXECUTE] == min(OUTCOME_SEVERITY.values())
        assert OUTCOME_SEVERITY[GateOutcome.REJECT] == max(OUTCOME_SEVERITY.values())

    def test_escalate_ranks_below_reject(self) -> None:
        # A human may still authorise an ESCALATE; REJECT is final.
        assert (
            OUTCOME_SEVERITY[GateOutcome.ESCALATE]
            < OUTCOME_SEVERITY[GateOutcome.REJECT]
        )

    def test_worst_wins(self) -> None:
        assert (
            worst([GateOutcome.EXECUTE, GateOutcome.REJECT, GateOutcome.HOLD])
            is GateOutcome.REJECT
        )
        assert worst([GateOutcome.EXECUTE]) is GateOutcome.EXECUTE

    def test_worst_refuses_an_empty_iterable(self) -> None:
        # Returning a default here would be a fail-open path.
        with pytest.raises(ValueError):
            worst([])


class TestWorstTerminal:
    """Companion to ``worst`` for callers branching on "does this end the loop?"."""

    def test_returns_the_worst_terminal_outcome(self) -> None:
        from graqle.assurance.outcomes import worst_terminal

        assert (
            worst_terminal([GateOutcome.ESCALATE, GateOutcome.REJECT])
            is GateOutcome.REJECT
        )

    def test_returns_none_when_nothing_is_terminal(self) -> None:
        from graqle.assurance.outcomes import worst_terminal

        assert worst_terminal([GateOutcome.EXECUTE, GateOutcome.HOLD]) is None

    def test_ignores_non_terminal_outcomes(self) -> None:
        from graqle.assurance.outcomes import worst_terminal

        assert (
            worst_terminal([GateOutcome.REJECT, GateOutcome.HOLD, GateOutcome.EXECUTE])
            is GateOutcome.REJECT
        )

    def test_worst_may_return_a_non_terminal_outcome(self) -> None:
        # The trap worst_terminal exists to avoid: worst() of two HOLDs is a
        # HOLD, which is NOT terminal.
        assert worst([GateOutcome.HOLD, GateOutcome.HOLD]) is GateOutcome.HOLD
        assert worst([GateOutcome.HOLD, GateOutcome.HOLD]).terminal is False

    def test_empty_is_none_not_an_error(self) -> None:
        from graqle.assurance.outcomes import worst_terminal

        assert worst_terminal([]) is None
