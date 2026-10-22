"""Atomic per-trajectory sequence allocation (CR-018 PR-018a, spec 5.2).

A trajectory's events form one contiguous, linear chain ``0..N-1`` (Inv-C1,
Inv-C3, Inv-C4). The sequencer owns the *head* ``(seq, head_hash)`` of each
chain and advances it by compare-and-swap, so two writers that read the same
head can never both succeed: the loser gets :class:`SequenceConflictError`.

Two backends:

* :class:`Neo4jTrajectorySequencer` - CAS inside one ``execute_write``
  transaction on a ``:TrajectoryHead`` node (the sanctioned write pattern;
  never a KG file).
* :class:`FileLockTrajectorySequencer` - CAS under an exclusive OS file lock,
  safe across threads and processes.

:func:`append_with_retry` is the bounded retry loop the recorder (PR-018b)
builds on. The retry budget is a required argument: there is no default, so no
tuning value lives in this module.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.sequencer
# risk: LOW (new module, no runtime consumers in PR-018a)
# dependencies: json, os, re, graqle.core.exceptions,
#   graqle.assurance.provenance_event (GENESIS_HASH), neo4j driver (duck-typed)
# constraints: writes only through Session.execute_write or the per-trajectory
#   seq file under the sequencer root; never opens a graqle*.json KG file
# -- /graqle:intelligence --
import contextlib
import json
import os
import re
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from graqle.assurance.provenance_event import GENESIS_HASH
from graqle.core.exceptions import GraqleError

__all__ = [
    "SequenceConflictError",
    "TrajectorySequencer",
    "Neo4jTrajectorySequencer",
    "FileLockTrajectorySequencer",
    "append_with_retry",
    "ensure_provenance_schema",
    "PROVENANCE_SCHEMA_STATEMENTS",
]

# \Z, not $: "$" would also accept a trailing newline.
_TRAJECTORY_ID_RE = re.compile(r"^trj_[0-9A-HJKMNP-TV-Z]{26}\Z")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")

# Conflict reasons that mean "another writer won the race" and are safe to retry.
_RETRYABLE_REASONS = frozenset({"cas-lost", "genesis-race"})

# Store-level backstop for Inv-C4 plus the head node key (spec 4.4).
PROVENANCE_SCHEMA_STATEMENTS: tuple[str, ...] = (
    "CREATE CONSTRAINT prov_event_id IF NOT EXISTS "
    "FOR (e:ProvenanceEvent) REQUIRE e.event_id IS UNIQUE",
    "CREATE CONSTRAINT prov_traj_seq IF NOT EXISTS "
    "FOR (e:ProvenanceEvent) REQUIRE (e.trajectory_id, e.sequence_number) IS UNIQUE",
    "CREATE CONSTRAINT traj_head_id IF NOT EXISTS "
    "FOR (h:TrajectoryHead) REQUIRE h.trajectory_id IS UNIQUE",
    "CREATE INDEX prov_event_canonical_hash IF NOT EXISTS "
    "FOR (e:ProvenanceEvent) ON (e.canonical_hash)",
)


class SequenceConflictError(GraqleError):
    """The head moved, a number was skipped, or the stored head is unreadable."""

    def __init__(self, trajectory_id: str, expected_seq: int, reason: str) -> None:
        super().__init__(
            f"sequence conflict on {trajectory_id}: expected_seq={expected_seq} reason={reason}"
        )
        self.trajectory_id = trajectory_id
        self.expected_seq = expected_seq
        self.reason = reason


class TrajectorySequencer(Protocol):
    def head(self, trajectory_id: str) -> tuple[int, str]:
        """``(last_seq, head_hash)``, or ``(-1, GENESIS_HASH)`` for a new trajectory."""
        ...

    def advance(
        self,
        trajectory_id: str,
        expected_seq: int,
        expected_head: str,
        new_seq: int,
        new_hash: str,
    ) -> None:
        """Compare-and-swap the head; raise :class:`SequenceConflictError` on loss."""
        ...


def _check_args(
    trajectory_id: str, expected_seq: int, expected_head: str, new_seq: int, new_hash: str
) -> None:
    if not _TRAJECTORY_ID_RE.match(trajectory_id):
        raise ValueError("invalid trajectory_id")
    if not (_HEX64_RE.match(expected_head) and _HEX64_RE.match(new_hash)):
        raise ValueError("head hashes must be 64 lowercase hex characters")
    # Inv-C1 is asserted before any write.
    if new_seq != expected_seq + 1:
        raise SequenceConflictError(trajectory_id, expected_seq, "skip")
    if expected_seq == -1 and expected_head != GENESIS_HASH:
        raise SequenceConflictError(trajectory_id, expected_seq, "bad-genesis")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Neo4j backend
# --------------------------------------------------------------------------


def ensure_provenance_schema(driver: Any, database: str | None = None) -> None:
    """Create the provenance constraints and index (idempotent, via execute_write)."""

    def _create(tx: Any) -> None:
        for statement in PROVENANCE_SCHEMA_STATEMENTS:
            tx.run(statement).consume()

    with driver.session(database=database) as session:
        session.execute_write(_create)


class Neo4jTrajectorySequencer:
    """CAS on a ``:TrajectoryHead`` node inside one ``execute_write`` transaction."""

    def __init__(self, driver: Any, database: str | None = None) -> None:
        self._driver = driver
        self._db = database

    def head(self, trajectory_id: str) -> tuple[int, str]:
        if not _TRAJECTORY_ID_RE.match(trajectory_id):
            raise ValueError("invalid trajectory_id")

        def _read(tx: Any) -> Any:
            return tx.run(
                "MATCH (h:TrajectoryHead {trajectory_id:$t}) "
                "RETURN h.seq AS seq, h.head_hash AS hh",
                t=trajectory_id,
            ).single()

        with self._driver.session(database=self._db) as session:
            rec = session.execute_read(_read)
        if rec is None:
            return (-1, GENESIS_HASH)
        return (int(rec["seq"]), str(rec["hh"]))

    def advance(
        self,
        trajectory_id: str,
        expected_seq: int,
        expected_head: str,
        new_seq: int,
        new_hash: str,
    ) -> None:
        _check_args(trajectory_id, expected_seq, expected_head, new_seq, new_hash)

        def _write(tx: Any) -> None:
            if expected_seq == -1:
                r = tx.run(
                    "MERGE (h:TrajectoryHead {trajectory_id:$t}) "
                    "ON CREATE SET h.seq=$ns, h.head_hash=$nh, h.updated_at_iso=$now "
                    "RETURN h.seq AS seq, h.head_hash AS hh",
                    t=trajectory_id,
                    ns=new_seq,
                    nh=new_hash,
                    now=_now(),
                ).single()
                if r is None or r["seq"] != new_seq or r["hh"] != new_hash:
                    raise SequenceConflictError(trajectory_id, expected_seq, "genesis-race")
            else:
                # Under read-committed isolation a bare MATCH..WHERE..SET lets
                # several writers pass the predicate on the same snapshot and
                # all succeed (lost update). The leading SET takes the node's
                # write lock first, so the WHERE after it is evaluated against
                # the latest committed head and exactly one writer matches.
                r = tx.run(
                    "MATCH (h:TrajectoryHead {trajectory_id:$t}) "
                    "SET h.updated_at_iso=$now "
                    "WITH h WHERE h.seq=$es AND h.head_hash=$eh "
                    "SET h.seq=$ns, h.head_hash=$nh "
                    "RETURN count(h) AS n",
                    t=trajectory_id,
                    es=expected_seq,
                    eh=expected_head,
                    ns=new_seq,
                    nh=new_hash,
                    now=_now(),
                ).single()
                if r is None or r["n"] != 1:
                    raise SequenceConflictError(trajectory_id, expected_seq, "cas-lost")

        with self._driver.session(database=self._db) as session:
            session.execute_write(_write)


# --------------------------------------------------------------------------
# File backend
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Blocking exclusive lock on ``lock_path``; cross-process (flock / msvcrt)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":  # pragma: no cover - exercised on Windows CI only
            import msvcrt

            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.005)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":  # pragma: no cover
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class FileLockTrajectorySequencer:
    """``<root>/<trajectory_id>.json`` = ``{"seq", "head_hash"}`` under a file lock.

    ``advance`` takes the lock, re-reads the stored head, compares it with the
    caller's expectation and replaces the file atomically, so the CAS is safe
    across processes (unlike an in-process ``RLock``). The default root is
    ``.graqle/dag/seq``; it is never a knowledge-graph file.
    """

    def __init__(self, root: str | os.PathLike[str] = ".graqle/dag/seq") -> None:
        self._root = Path(root)

    def _state_path(self, trajectory_id: str) -> Path:
        if not _TRAJECTORY_ID_RE.match(trajectory_id):
            raise ValueError("invalid trajectory_id")
        return self._root / f"{trajectory_id}.json"

    def _read_state(self, trajectory_id: str) -> tuple[int, str]:
        path = self._state_path(trajectory_id)
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return (-1, GENESIS_HASH)
        try:
            data = json.loads(raw)
            seq, head_hash = data["seq"], data["head_hash"]
            valid = (
                isinstance(seq, int)
                and not isinstance(seq, bool)
                and seq >= 0
                and isinstance(head_hash, str)
                and bool(_HEX64_RE.match(head_hash))
            )
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            # An unreadable head is never treated as a new trajectory.
            raise SequenceConflictError(trajectory_id, -1, "corrupt-head")
        return (seq, head_hash)

    def head(self, trajectory_id: str) -> tuple[int, str]:
        return self._read_state(trajectory_id)

    def advance(
        self,
        trajectory_id: str,
        expected_seq: int,
        expected_head: str,
        new_seq: int,
        new_hash: str,
    ) -> None:
        _check_args(trajectory_id, expected_seq, expected_head, new_seq, new_hash)
        path = self._state_path(trajectory_id)
        with _exclusive_lock(self._root / f"{trajectory_id}.lock"):
            current = self._read_state(trajectory_id)
            if current != (expected_seq, expected_head):
                raise SequenceConflictError(trajectory_id, expected_seq, "cas-lost")
            fd, tmp = tempfile.mkstemp(dir=str(self._root), prefix=".seq-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump({"seq": new_seq, "head_hash": new_hash}, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
                raise


# --------------------------------------------------------------------------
# Bounded retry
# --------------------------------------------------------------------------


def append_with_retry(
    sequencer: TrajectorySequencer,
    trajectory_id: str,
    hash_for: Callable[[int, str], str],
    retry_budget: int,
) -> tuple[int, str, str]:
    """Allocate the next slot and advance the head, retrying lost races.

    ``hash_for(new_seq, previous_event_hash)`` must return the 64-hex canonical
    hash of the event that will occupy that slot. Returns
    ``(new_seq, new_hash, previous_event_hash)``. Only lost-race conflicts are
    retried; a skip or an unreadable head propagates at once. When the budget
    is spent the call raises (fail closed) instead of returning a slot.
    """
    if retry_budget < 1:
        raise ValueError("retry_budget must be at least 1")
    last_seq = -1
    for _ in range(retry_budget):
        seq, head_hash = sequencer.head(trajectory_id)
        last_seq = seq
        new_seq = seq + 1
        new_hash = hash_for(new_seq, head_hash)
        try:
            sequencer.advance(trajectory_id, seq, head_hash, new_seq, new_hash)
        except SequenceConflictError as exc:
            if exc.reason not in _RETRYABLE_REASONS:
                raise
            continue
        return (new_seq, new_hash, head_hash)
    raise SequenceConflictError(trajectory_id, last_seq, "retry-budget-exhausted")
