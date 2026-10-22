"""CR-015 PR-015a — AC-1 (ordering + hash chain), AC-2 (prefix validator)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.trajectory import (
    HistoryView,
    PriorGateOutcome,
    TrajectoryHistory,
    TrajectoryMonitor,
)
from tests.test_assurance._traj_fakes import cp, estimator, history


def test_append_rejects_out_of_order_step_index() -> None:
    h = history(2)
    with pytest.raises(ValueError, match="out-of-order"):
        h.append(cp(5))
    with pytest.raises(ValueError, match="out-of-order"):
        h.append(cp(1))
    assert len(h.checkpoints) == 2


def test_append_rejects_foreign_session() -> None:
    with pytest.raises(ValueError, match="session"):
        TrajectoryHistory(session_id="s1").append(cp(0, session="other"))


def test_hash_chain_links_and_verifies() -> None:
    h = history(4)
    cps = h.checkpoints
    assert cps[0].prev_checkpoint_hash is None
    for prev, cur in zip(cps, cps[1:]):
        assert cur.prev_checkpoint_hash == prev.checkpoint_hash
    assert all(c.checkpoint_hash.startswith("sha256:") for c in cps)
    assert len({c.checkpoint_hash for c in cps}) == 4
    assert h.verify_chain()


def test_tampered_history_fails_verification() -> None:
    h = history(3)
    h.checkpoints[1] = h.checkpoints[1].model_copy(update={"path_depth": 9})
    assert not h.verify_chain()


def test_append_rejects_wrong_prev_hash() -> None:
    h = history(1)
    with pytest.raises(ValueError, match="prev_checkpoint_hash"):
        h.append(cp(1, prev_checkpoint_hash="sha256:" + "0" * 64))


def test_view_until_rejects_out_of_range() -> None:
    h = history(2)
    for t in (-1, 2):
        with pytest.raises(ValueError):
            h.view_until(t)
    with pytest.raises(ValueError):
        TrajectoryHistory(session_id="s1").view_until(0)


def test_history_view_rejects_non_prefix() -> None:
    cps = tuple(history(3).checkpoints)
    with pytest.raises(ValidationError):  # too long for t
        HistoryView(session_id="s1", t=1, checkpoints=cps)
    with pytest.raises(ValidationError):  # too short for t
        HistoryView(session_id="s1", t=3, checkpoints=cps)
    with pytest.raises(ValidationError):  # gap
        HistoryView(session_id="s1", t=1, checkpoints=(cps[0], cps[2]))
    with pytest.raises(ValidationError):  # does not start at 0
        HistoryView(session_id="s1", t=1, checkpoints=(cps[1], cps[2]))
    with pytest.raises(ValidationError):  # empty
        HistoryView(session_id="s1", t=0, checkpoints=())


def test_history_view_rejects_foreign_session_checkpoint() -> None:
    with pytest.raises(ValidationError):
        HistoryView(session_id="s2", t=0, checkpoints=(cp(0),))


def test_view_is_frozen_and_has_no_parent_reference() -> None:
    h = history(2)
    v = h.view_until(1)
    with pytest.raises(ValidationError):
        v.t = 0  # type: ignore[misc]
    assert set(HistoryView.model_fields) == {"session_id", "t", "checkpoints"}
    assert not any(isinstance(x, TrajectoryHistory) for x in vars(v).values())


def test_features() -> None:
    h = TrajectoryHistory(session_id="s1")
    h.append(cp(0, errors=1, calls=2))
    h.append(cp(1, is_retry=True, errors=1, calls=2, unresolved_conflict_ids=("c1", "c2")))
    h.append(cp(2, is_retry=True, calls=0, evidence_freshness=None))
    v = h.view_until(2)
    assert v.elapsed_steps() == 2
    assert v.retry_count() == 2
    assert v.unresolved_contradictions() == 0
    assert v.evidence_freshness() is None
    assert v.tool_failure_history(window=2) == 0.5  # 1 error over 2 calls in steps 1..2
    assert v.tool_failure_history(window=3) == 0.5  # 2 errors over 4 calls
    assert h.view_until(1).unresolved_contradictions() == 2
    with pytest.raises(ValueError):
        v.tool_failure_history(window=0)


def test_tool_failure_history_clamped_when_calls_underreported() -> None:
    v = history(1, errors=3, calls=0).view_until(0)
    assert v.tool_failure_history(window=1) == 1.0


def test_monitor_records_outcome_once_on_last_checkpoint_and_rehashes() -> None:
    h = TrajectoryHistory(session_id="s1")
    mon = TrajectoryMonitor(h, estimator(), window=4)
    mon.checkpoint(cp(0))
    v1 = mon.checkpoint(cp(1))
    before = h.checkpoints[1].checkpoint_hash
    out = PriorGateOutcome(step=1, outcome=GateOutcome.HOLD, fingerprint="f1", verdict_id="v1")
    mon.record_outcome(1, out)
    assert h.checkpoints[1].prior_gate_outcome == out
    assert h.checkpoints[1].checkpoint_hash != before
    assert h.verify_chain()
    assert v1.checkpoints[1].prior_gate_outcome is None  # earlier view unchanged
    with pytest.raises(ValueError, match="already recorded"):
        mon.record_outcome(1, out)
    with pytest.raises(ValueError, match="last checkpoint"):
        mon.record_outcome(0, out)
    mon.checkpoint(cp(2))
    assert h.view_until(2).fingerprints_seen() == frozenset({"f1"})
    assert h.view_until(1).fingerprints_seen() == frozenset()  # own outcome not yet known


def test_monitor_rejects_mismatched_outcome_step_and_bad_window() -> None:
    h = history(1)
    mon = TrajectoryMonitor(h, estimator(), window=1)
    with pytest.raises(ValueError, match="outcome.step"):
        mon.record_outcome(
            0, PriorGateOutcome(step=3, outcome=GateOutcome.HOLD, fingerprint="f", verdict_id="v")
        )
    with pytest.raises(ValueError):
        TrajectoryMonitor(h, estimator(), window=0)
