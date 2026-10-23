"""CR-018 PR-018a: trajectory sequencer (AC-4 file backend, AC-20, AC-18 static).

The Neo4j backend is proved in ``test_sequencer_neo4j.py``. Retry budgets and
worker counts here are test-local substitutes, not deployment values.
"""

from __future__ import annotations

import ast
import hashlib
import json
import multiprocessing
import re
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import pytest

from graqle.assurance import provenance_event, salt_escrow, sequencer
from graqle.assurance.provenance_event import GENESIS_HASH
from graqle.assurance.sequencer import (
    FileLockTrajectorySequencer,
    SequenceConflictError,
    append_with_retry,
)

TID = "trj_01J7Q0E9M3W5X7Y9Z1A3B5C7D9"
OTHER_TID = "trj_01J7Q0E9M3W5X7Y9Z1A3B5C7DA"
WORKERS = 64
TEST_BUDGET = 5000


def _h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _worker(args: tuple[str, str, int]) -> tuple[int, str, str]:
    """Module-level so a process pool can pickle it."""
    root, tid, n = args

    def hash_for(seq: int, prev: str) -> str:
        return _h(f"{tid}|{seq}|{prev}|{n}")

    return append_with_retry(FileLockTrajectorySequencer(root), tid, hash_for, TEST_BUDGET)


def _assert_one_contiguous_chain(results: list[tuple[int, str, str]], count: int) -> None:
    by_seq = sorted(results)
    assert [r[0] for r in by_seq] == list(range(count)), "gap or duplicate sequence number"
    assert by_seq[0][2] == GENESIS_HASH
    for prev, cur in zip(by_seq, by_seq[1:]):
        assert cur[2] == prev[1], "previous_event_hash does not link to the prior event"
    assert len({r[2] for r in results}) == count, "two events claim one previous hash (fork)"


class TestFileSequencerBasics:
    def test_new_trajectory_reports_genesis(self, tmp_path: Path) -> None:
        assert FileLockTrajectorySequencer(tmp_path).head(TID) == (-1, GENESIS_HASH)

    def test_advance_walks_the_chain(self, tmp_path: Path) -> None:
        seq = FileLockTrajectorySequencer(tmp_path)
        seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
        assert seq.head(TID) == (0, _h("0"))
        seq.advance(TID, 0, _h("0"), 1, _h("1"))
        assert seq.head(TID) == (1, _h("1"))
        assert FileLockTrajectorySequencer(tmp_path).head(TID) == (1, _h("1"))

    def test_heads_are_per_trajectory(self, tmp_path: Path) -> None:
        seq = FileLockTrajectorySequencer(tmp_path)
        seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
        assert seq.head(OTHER_TID) == (-1, GENESIS_HASH)

    def test_skip_is_refused_before_any_write(self, tmp_path: Path) -> None:
        seq = FileLockTrajectorySequencer(tmp_path)
        with pytest.raises(SequenceConflictError) as exc:
            seq.advance(TID, -1, GENESIS_HASH, 1, _h("1"))
        assert exc.value.reason == "skip"
        assert list(tmp_path.iterdir()) == []  # nothing was written, not even a lock file

    def test_genesis_with_a_non_genesis_head_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SequenceConflictError) as exc:
            FileLockTrajectorySequencer(tmp_path).advance(TID, -1, _h("x"), 0, _h("0"))
        assert exc.value.reason == "bad-genesis"

    def test_stale_expected_head_loses_the_cas(self, tmp_path: Path) -> None:
        seq = FileLockTrajectorySequencer(tmp_path)
        seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
        with pytest.raises(SequenceConflictError) as exc:
            seq.advance(TID, -1, GENESIS_HASH, 0, _h("other"))
        assert exc.value.reason == "cas-lost"
        assert seq.head(TID) == (0, _h("0"))

    def test_fork_on_an_already_used_previous_hash_is_refused(self, tmp_path: Path) -> None:
        """AC-20 (Inv-C3): a second event claiming the same previous hash."""
        seq = FileLockTrajectorySequencer(tmp_path)
        seq.advance(TID, -1, GENESIS_HASH, 0, _h("e0"))
        seq.advance(TID, 0, _h("e0"), 1, _h("e1"))
        with pytest.raises(SequenceConflictError) as exc:
            seq.advance(TID, 0, _h("e0"), 1, _h("fork-of-e1"))
        assert exc.value.reason == "cas-lost"
        # Same sequence number but a wrong head hash is also refused.
        with pytest.raises(SequenceConflictError):
            seq.advance(TID, 1, _h("not-the-head"), 2, _h("e2"))
        assert seq.head(TID) == (1, _h("e1"))

    @pytest.mark.parametrize(
        "bad_tid",
        ["", "../evil", "trj_../../x", "trj_short", TID + "x", TID.lower(), "x/" + TID, TID + "\n"],
    )
    def test_trajectory_id_cannot_escape_the_root(self, tmp_path: Path, bad_tid: str) -> None:
        seq = FileLockTrajectorySequencer(tmp_path / "seq")
        with pytest.raises(ValueError):
            seq.head(bad_tid)
        with pytest.raises(ValueError):
            seq.advance(bad_tid, -1, GENESIS_HASH, 0, _h("0"))
        assert not (tmp_path / "seq").exists()

    @pytest.mark.parametrize(
        "bad_hash", ["", "G" * 64, "a" * 63, "A" * 64, "a" * 64 + "\n"]
    )
    def test_malformed_hashes_are_refused(self, tmp_path: Path, bad_hash: str) -> None:
        seq = FileLockTrajectorySequencer(tmp_path)
        with pytest.raises(ValueError):
            seq.advance(TID, -1, GENESIS_HASH, 0, bad_hash)
        with pytest.raises(ValueError):
            seq.advance(TID, -1, bad_hash, 0, _h("0"))

    @pytest.mark.parametrize(
        "content",
        [
            "not json",
            "[]",
            '{"seq": 1}',
            '{"seq": "1", "head_hash": "' + "a" * 64 + '"}',
            '{"seq": true, "head_hash": "' + "a" * 64 + '"}',
            '{"seq": -1, "head_hash": "' + "a" * 64 + '"}',
            '{"seq": 1, "head_hash": "zz"}',
            "",
        ],
    )
    def test_corrupt_head_fails_closed_never_as_a_new_trajectory(
        self, tmp_path: Path, content: str
    ) -> None:
        (tmp_path / f"{TID}.json").write_text(content, encoding="utf-8")
        seq = FileLockTrajectorySequencer(tmp_path)
        with pytest.raises(SequenceConflictError) as exc:
            seq.head(TID)
        assert exc.value.reason == "corrupt-head"
        with pytest.raises(SequenceConflictError):
            seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
        assert (tmp_path / f"{TID}.json").read_text(encoding="utf-8") == content

    def test_no_temp_files_are_left_behind(self, tmp_path: Path) -> None:
        seq = FileLockTrajectorySequencer(tmp_path)
        seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
        with pytest.raises(SequenceConflictError):
            seq.advance(TID, -1, GENESIS_HASH, 0, _h("1"))
        assert sorted(p.suffix for p in tmp_path.iterdir()) == [".json", ".lock"]


class TestAppendWithRetry:
    class _AlwaysLosing:
        def __init__(self, reason: str) -> None:
            self.reason, self.calls = reason, 0

        def head(self, tid: str) -> tuple[int, str]:
            return (-1, GENESIS_HASH)

        def advance(self, *args: object) -> None:
            self.calls += 1
            raise SequenceConflictError(TID, -1, self.reason)

    def test_budget_exhaustion_raises_instead_of_returning_a_slot(self) -> None:
        losing = self._AlwaysLosing("cas-lost")
        with pytest.raises(SequenceConflictError) as exc:
            append_with_retry(losing, TID, lambda s, p: _h("x"), 3)
        assert exc.value.reason == "retry-budget-exhausted"
        assert losing.calls == 3

    def test_non_race_conflicts_are_not_retried(self) -> None:
        losing = self._AlwaysLosing("corrupt-head")
        with pytest.raises(SequenceConflictError) as exc:
            append_with_retry(losing, TID, lambda s, p: _h("x"), 9)
        assert exc.value.reason == "corrupt-head"
        assert losing.calls == 1

    @pytest.mark.parametrize("budget", [0, -1])
    def test_budget_must_be_positive(self, budget: int) -> None:
        with pytest.raises(ValueError):
            append_with_retry(self._AlwaysLosing("cas-lost"), TID, lambda s, p: _h("x"), budget)

    def test_hash_for_sees_the_slot_it_will_occupy(self, tmp_path: Path) -> None:
        seen: list[tuple[int, str]] = []

        def hash_for(seq: int, prev: str) -> str:
            seen.append((seq, prev))
            return _h(f"e{seq}")

        s = FileLockTrajectorySequencer(tmp_path)
        assert append_with_retry(s, TID, hash_for, 2) == (0, _h("e0"), GENESIS_HASH)
        assert append_with_retry(s, TID, hash_for, 2) == (1, _h("e1"), _h("e0"))
        assert seen == [(0, GENESIS_HASH), (1, _h("e0"))]

    def test_a_losing_attempt_recomputes_the_hash_for_the_new_head(self, tmp_path: Path) -> None:
        s = FileLockTrajectorySequencer(tmp_path)
        calls: list[tuple[int, str]] = []

        def hash_for(seq: int, prev: str) -> str:
            calls.append((seq, prev))
            if len(calls) == 1:  # another writer wins between head() and advance()
                s.advance(TID, -1, GENESIS_HASH, 0, _h("rival"))
            return _h(f"mine{seq}")

        assert append_with_retry(s, TID, hash_for, 3) == (1, _h("mine1"), _h("rival"))
        assert calls == [(0, GENESIS_HASH), (1, _h("rival"))]


class TestConcurrentRecorders:
    """AC-4, file backend: 64 concurrent writers yield one contiguous chain."""

    def test_64_threads_one_chain(self, tmp_path: Path) -> None:
        root = str(tmp_path)
        barrier = threading.Barrier(WORKERS)

        def run(n: int) -> tuple[int, str, str]:
            barrier.wait()
            return _worker((root, TID, n))

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(run, range(WORKERS)))
        _assert_one_contiguous_chain(results, WORKERS)
        assert FileLockTrajectorySequencer(root).head(TID) == (WORKERS - 1, max(results)[1])

    def test_64_processes_one_chain(self, tmp_path: Path) -> None:
        root = str(tmp_path)
        ctx = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=WORKERS, mp_context=ctx) as pool:
            results = list(pool.map(_worker, [(root, TID, n) for n in range(WORKERS)]))
        _assert_one_contiguous_chain(results, WORKERS)
        assert FileLockTrajectorySequencer(root).head(TID) == (WORKERS - 1, max(results)[1])

    def test_threads_and_processes_mixed_on_two_trajectories(self, tmp_path: Path) -> None:
        root = str(tmp_path)
        half = WORKERS // 2
        ctx = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=half, mp_context=ctx) as procs, ThreadPoolExecutor(
            max_workers=half
        ) as threads:
            pf = [procs.submit(_worker, (root, TID, n)) for n in range(half)]
            tf = [threads.submit(_worker, (root, OTHER_TID, n)) for n in range(half)]
            a = [f.result() for f in pf]
            b = [f.result() for f in tf]
        _assert_one_contiguous_chain(a, half)
        _assert_one_contiguous_chain(b, half)


class TestStaticKgWriteSafety:
    """AC-18 (static half): no knowledge-graph file is opened for writing."""

    MODULES = (provenance_event, sequencer, salt_escrow)

    def test_no_graqle_json_path_is_named(self) -> None:
        for mod in self.MODULES:
            src = Path(mod.__file__).read_text(encoding="utf-8")
            assert not re.search(r"graqle[\w.\-]*\.json", src), mod.__name__

    def test_no_convenience_file_writers_are_used(self) -> None:
        """Writes go through os-level temp+replace/link only, never write_text/open('w')."""
        for mod in self.MODULES:
            tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
            names = {
                getattr(n.func, "attr", getattr(n.func, "id", ""))
                for n in ast.walk(tree)
                if isinstance(n, ast.Call)
            }
            assert not ({"write_text", "write_bytes"} & names), mod.__name__
            builtin_open = [
                n
                for n in ast.walk(tree)
                if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open"
            ]
            assert builtin_open == [], mod.__name__

    def test_cypher_writes_run_inside_execute_write(self) -> None:
        src = Path(sequencer.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        # Every tx.run that carries a mutating clause sits in a function passed to execute_write.
        write_fns = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "execute_write":
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        write_fns.add(arg.id)
        assert write_fns == {"_write", "_create"}
        for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            body = ast.get_source_segment(src, fn) or ""
            if re.search(r"\b(MERGE|SET|CREATE)\b", body) and fn.name not in write_fns:
                # Only the owning methods/constants may mention a write clause.
                assert fn.name in {"advance", "ensure_provenance_schema"}, fn.name

    def test_cas_cypher_matches_the_spec(self) -> None:
        src = Path(sequencer.__file__).read_text(encoding="utf-8")
        assert "WHERE h.seq=$es AND h.head_hash=$eh" in src
        assert "new_seq != expected_seq + 1" in src
        assert src.index("new_seq != expected_seq + 1") < src.index("def _write")

    def test_schema_declares_the_unique_trajectory_sequence_constraint(self) -> None:
        joined = " ".join(sequencer.PROVENANCE_SCHEMA_STATEMENTS)
        assert "(e.trajectory_id, e.sequence_number) IS UNIQUE" in joined
        assert "FOR (h:TrajectoryHead) REQUIRE h.trajectory_id IS UNIQUE" in joined
        assert "REQUIRE e.event_id IS UNIQUE" in joined


def test_state_file_is_the_documented_shape(tmp_path: Path) -> None:
    seq = FileLockTrajectorySequencer(tmp_path)
    seq.advance(TID, -1, GENESIS_HASH, 0, _h("0"))
    assert json.loads((tmp_path / f"{TID}.json").read_text()) == {
        "seq": 0,
        "head_hash": _h("0"),
    }
