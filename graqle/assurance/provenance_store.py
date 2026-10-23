"""ProvenanceStore: persistence for committed provenance events (CR-018 PR-018b).

Two backends: Neo4j (every write through ``Session.execute_write``, spec 4.4)
and a file store (one 0600 JSON file per event, created with an exclusive
atomic link so ``(trajectory_id, sequence_number)`` stays unique). Neither
backend ever opens a ``graqle*.json`` knowledge-graph file (AC-18).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.provenance_store
# risk: LOW (new module; consumer is the PR-018b recorder)
# dependencies: json, os, tempfile, graqle.assurance.provenance_event, neo4j driver (duck-typed)
# constraints: execute_write only; no KG file; files 0600 under a 0700 directory
# -- /graqle:intelligence --
import contextlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Protocol

from graqle.core.exceptions import GraqleError

__all__ = ["ProvenanceStore", "ProvenanceStoreError", "FileProvenanceStore", "Neo4jProvenanceStore"]

_EVENT_ID_RE = re.compile(r"^evt_[0-9A-HJKMNP-TV-Z]{26}\Z")
_TRAJECTORY_ID_RE = re.compile(r"^trj_[0-9A-HJKMNP-TV-Z]{26}\Z")


class ProvenanceStoreError(GraqleError):
    """A provenance event could not be stored (fail closed: never a silent skip)."""


class ProvenanceStore(Protocol):
    def persist(self, committed: dict[str, Any]) -> None:
        """Store the committed form (integrity included); refuse duplicates."""
        ...

    def attach_anchor(self, event_id: str, anchor_ref: dict[str, Any]) -> None:
        """Record the anchor pointer; it sits OUTSIDE ``canonical_hash``."""
        ...


def _check_committed(committed: dict[str, Any]) -> tuple[str, str, int]:
    try:
        event_id = committed["event_id"]
        traj = committed["activity"]["trajectory_id"]
        seq = committed["ordering"]["sequence_number"]
        committed["integrity"]["canonical_hash"]
    except (KeyError, TypeError) as exc:
        raise ProvenanceStoreError("committed event is missing required fields") from exc
    if not (_EVENT_ID_RE.match(str(event_id)) and _TRAJECTORY_ID_RE.match(str(traj))):
        raise ProvenanceStoreError("invalid event or trajectory id")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ProvenanceStoreError("invalid sequence number")
    return str(event_id), str(traj), seq


class FileProvenanceStore:
    def __init__(self, root: str | os.PathLike[str] = ".graqle/dag/events") -> None:
        self._root = Path(root)

    def _path(self, name: str) -> Path:
        return self._root / name

    def persist(self, committed: dict[str, Any]) -> None:
        event_id, traj, seq = _check_committed(committed)
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps(committed, sort_keys=True, separators=(",", ":"))
        fd, tmp = tempfile.mkstemp(dir=str(self._root), prefix=".evt-", suffix=".tmp")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            # Two exclusive links: the (trajectory, seq) slot and the event id.
            slot = self._path(f"{traj}.{seq}.slot.json")
            try:
                os.link(tmp, slot)
            except FileExistsError as exc:
                raise ProvenanceStoreError("sequence slot already occupied") from exc
            try:
                os.link(tmp, self._path(f"{event_id}.json"))
            except FileExistsError as exc:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(slot)
                raise ProvenanceStoreError("event already stored") from exc
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)

    def attach_anchor(self, event_id: str, anchor_ref: dict[str, Any]) -> None:
        if not _EVENT_ID_RE.match(event_id):
            raise ProvenanceStoreError("invalid event_id")
        fd, tmp = tempfile.mkstemp(dir=str(self._root), prefix=".anc-", suffix=".tmp")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(anchor_ref, sort_keys=True, separators=(",", ":")))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path(f"{event_id}.anchor.json"))
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)

    def load(self, event_id: str) -> dict[str, Any]:
        if not _EVENT_ID_RE.match(event_id):
            raise ProvenanceStoreError("invalid event_id")
        try:
            return json.loads(self._path(f"{event_id}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProvenanceStoreError("event not readable") from exc


class Neo4jProvenanceStore:
    """``(:ProvenanceEvent)`` nodes written via ``execute_write`` (spec 4.4)."""

    def __init__(self, driver: Any, database: str | None = None) -> None:
        self._driver = driver
        self._db = database

    def persist(self, committed: dict[str, Any]) -> None:
        event_id, traj, seq = _check_committed(committed)
        integrity = committed["integrity"]
        sig = integrity["signature"]
        committed_json = json.dumps(committed, sort_keys=True, separators=(",", ":"))
        prev = committed["ordering"]["previous_event_hash"]

        def _write(tx: Any) -> None:
            tx.run(
                "CREATE (e:ProvenanceEvent {event_id:$id, event_type:$et, schema_version:$sv, "
                "trajectory_id:$t, checkpoint:$cp, sequence_number:$sn, previous_event_hash:$ph, "
                "canonical_hash:$ch, kid:$kid, key_version:$kv, signed_at:$sa, committed_json:$cj}) "
                "WITH e OPTIONAL MATCH (p:ProvenanceEvent {trajectory_id:$t, sequence_number:$pn}) "
                "FOREACH (_ IN CASE WHEN p IS NULL THEN [] ELSE [1] END | "
                "CREATE (e)-[:PRECEDED_BY]->(p))",
                id=event_id,
                et=committed["event_type"],
                sv=committed["schema_version"],
                t=traj,
                cp=committed["activity"]["checkpoint"],
                sn=seq,
                ph=prev,
                ch=integrity["canonical_hash"],
                kid=sig["kid"],
                kv=sig["key_version"],
                sa=sig["signed_at"],
                cj=committed_json,
                pn=seq - 1,
            )

        try:
            with self._driver.session(database=self._db) as session:
                session.execute_write(_write)
        except Exception as exc:  # constraint violation or driver failure: fail closed
            raise ProvenanceStoreError(f"event not stored ({type(exc).__name__})") from exc

    def attach_anchor(self, event_id: str, anchor_ref: dict[str, Any]) -> None:
        if not _EVENT_ID_RE.match(event_id):
            raise ProvenanceStoreError("invalid event_id")
        anchor_json = json.dumps(anchor_ref, sort_keys=True, separators=(",", ":"))

        def _write(tx: Any) -> None:
            tx.run(
                "MATCH (e:ProvenanceEvent {event_id:$id}) "
                "SET e.anchor_json=$aj, e.record_hash=$rh",
                id=event_id,
                aj=anchor_json,
                rh=anchor_ref.get("leaf_hash"),
            )

        try:
            with self._driver.session(database=self._db) as session:
                session.execute_write(_write)
        except Exception as exc:
            raise ProvenanceStoreError(f"anchor not stored ({type(exc).__name__})") from exc
