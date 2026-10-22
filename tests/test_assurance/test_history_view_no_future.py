"""CR-015 PR-015a — AC-3: no-post-outcome rule (poisoned future checkpoints)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st

from graqle.assurance.trajectory import HistoryView, TrajectoryHistory
from tests.test_assurance._traj_fakes import cp, estimator

_future = st.lists(
    st.tuples(st.integers(0, 6), st.integers(0, 6), st.booleans(), st.integers(0, 4)),
    min_size=1,
    max_size=6,
)


def test_poisoned_next_checkpoint_does_not_change_the_estimate() -> None:
    h = TrajectoryHistory(session_id="s1")
    for i in range(3):
        h.append(cp(i))
    est = estimator()
    view = h.view_until(2)
    before = est.estimate(view)
    h.append(cp(3, errors=9, calls=9, is_retry=True, unresolved_conflict_ids=("x",), evidence_freshness=0.0))
    assert est.estimate(view) == before
    assert est.estimate(h.view_until(2)) == before
    assert est.estimate(h.view_until(3)).reliability < before.reliability


@h_settings(max_examples=100, deadline=None)
@given(future=_future)
def test_estimate_of_v_t_is_bit_identical_after_any_random_future(
    future: list[tuple[int, int, bool, int]],
) -> None:
    h = TrajectoryHistory(session_id="s1")
    for i in range(3):
        h.append(cp(i))
    est = estimator()
    view = h.view_until(2)
    before = est.estimate(view)
    for k, (errors, calls, retry, conflicts) in enumerate(future, start=3):
        h.append(
            cp(
                k,
                errors=errors,
                calls=calls,
                is_retry=retry,
                unresolved_conflict_ids=tuple(f"c{j}" for j in range(conflicts)),
            )
        )
    assert est.estimate(view) == before
    assert est.estimate(h.view_until(2)) == before


def test_view_exposes_only_prefix_accessors() -> None:
    public = {n for n in dir(HistoryView) if not n.startswith("_") and callable(getattr(HistoryView, n))}
    pydantic_api = {n for n in dir(HistoryView.__mro__[1]) if not n.startswith("_")}
    feature_methods = public - pydantic_api
    assert feature_methods == {
        "elapsed_steps",
        "retry_count",
        "unresolved_contradictions",
        "evidence_freshness",
        "tool_failure_history",
        "prior_gate_outcomes",
        "fingerprints_seen",
    }, "a new HistoryView accessor is a Research-Team review item (CR-015 handoff note 8)"


def test_view_does_not_see_checkpoints_appended_later() -> None:
    h = TrajectoryHistory(session_id="s1")
    h.append(cp(0))
    view = h.view_until(0)
    h.append(cp(1))
    assert len(view.checkpoints) == 1
    assert view.elapsed_steps() == 0
