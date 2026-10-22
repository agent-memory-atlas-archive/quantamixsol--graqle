"""Salt escrow for redaction-safe field commitments (CR-018 PR-018a, spec 2.4).

An event's redactable fields are hashed with a per-field 32-byte salt, so the
anchored event stays verifiable after the value and its salt are erased. The
escrow keeps the salts. Erasing an event's escrow entry (and the value) is the
redaction; ``canonical_hash`` never changes because it depends only on the
commitments.

This PR ships the :class:`SaltEscrow` protocol and :class:`FileSaltEscrow`.
The Neo4j implementation lands in PR-018b.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.salt_escrow
# risk: LOW (new module, no runtime consumers in PR-018a)
# dependencies: json, os, re, tempfile, graqle.core.exceptions,
#   graqle.assurance.provenance_event (REDACTABLE_FIELDS)
# constraints: escrow files are 0600 in a 0700 directory; put never overwrites;
#   a malformed or over-permissive entry raises instead of being used
# -- /graqle:intelligence --
import contextlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Protocol

from graqle.assurance.provenance_event import REDACTABLE_FIELDS
from graqle.core.exceptions import GraqleError

__all__ = ["SaltEscrow", "FileSaltEscrow", "Neo4jSaltEscrow", "SaltEscrowError"]

# \Z, not $: "$" would also accept a trailing newline.
_EVENT_ID_RE = re.compile(r"^evt_[0-9A-HJKMNP-TV-Z]{26}\Z")
_SALT_BYTES = 32
_SALT_HEX_RE = re.compile(r"^[0-9a-f]{64}\Z")


class SaltEscrowError(GraqleError):
    """A salt entry is invalid, already present, or unreadable. Fail closed."""


class SaltEscrow(Protocol):
    def put(self, event_id: str, salts: dict[str, bytes]) -> None:
        """Store the salts of one event; raise :class:`SaltEscrowError` if present."""
        ...

    def get(self, event_id: str) -> dict[str, bytes]:
        """The event's salts, or ``{}`` when they were erased (redacted)."""
        ...

    def delete(self, event_id: str) -> None:
        """Erase the event's salts (redaction). Idempotent."""
        ...


def _validate(event_id: str, salts: dict[str, bytes] | None = None) -> None:
    if not _EVENT_ID_RE.match(event_id):
        raise SaltEscrowError("invalid event_id")
    if salts is None:
        return
    for path, salt in salts.items():
        if path not in REDACTABLE_FIELDS:
            raise SaltEscrowError(f"{path!r} is not a redactable field")
        if not isinstance(salt, bytes) or len(salt) != _SALT_BYTES:
            raise SaltEscrowError(f"salt for {path} must be exactly {_SALT_BYTES} bytes")


class FileSaltEscrow:
    """One 0600 JSON file per event under ``root`` (default ``.graqle/dag/salts``)."""

    def __init__(self, root: str | os.PathLike[str] = ".graqle/dag/salts") -> None:
        self._root = Path(root)

    def _path(self, event_id: str) -> Path:
        return self._root / f"{event_id}.json"

    def put(self, event_id: str, salts: dict[str, bytes]) -> None:
        _validate(event_id, salts)
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps({p: s.hex() for p, s in sorted(salts.items())})
        fd, tmp = tempfile.mkstemp(dir=str(self._root), prefix=".salt-", suffix=".tmp")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, self._path(event_id))  # atomic; fails if the entry exists
            except FileExistsError as exc:
                raise SaltEscrowError(f"salts for {event_id} already escrowed") from exc
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)

    def get(self, event_id: str) -> dict[str, bytes]:
        _validate(event_id)
        path = self._path(event_id)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        if os.name != "nt" and mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SaltEscrowError(f"escrow entry for {event_id} is group/world accessible")
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise TypeError("escrow entry is not an object")
            salts = {}
            for p, h in data.items():
                if p not in REDACTABLE_FIELDS or not _SALT_HEX_RE.match(h):
                    raise ValueError("bad escrow field")
                salts[p] = bytes.fromhex(h)
        except (ValueError, TypeError) as exc:
            raise SaltEscrowError(f"escrow entry for {event_id} is malformed") from exc
        return salts

    def delete(self, event_id: str) -> None:
        _validate(event_id)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._path(event_id))


class Neo4jSaltEscrow:
    """``(:ProvenanceSalt {event_id, field_path, salt_hex})`` via ``execute_write``.

    A separate label keeps salts separately deletable (redaction = delete).
    """

    def __init__(self, driver: Any, database: str | None = None) -> None:
        self._driver = driver
        self._db = database

    def put(self, event_id: str, salts: dict[str, bytes]) -> None:
        _validate(event_id, salts)
        rows = [{"p": p, "s": s.hex()} for p, s in sorted(salts.items())]

        def _write(tx: Any) -> None:
            existing = tx.run(
                "MATCH (s:ProvenanceSalt {event_id:$id}) RETURN count(s) AS n", id=event_id
            ).single()
            if existing is not None and existing["n"]:
                raise SaltEscrowError(f"salts for {event_id} already escrowed")
            tx.run(
                "UNWIND $rows AS r "
                "CREATE (:ProvenanceSalt {event_id:$id, field_path:r.p, salt_hex:r.s})",
                id=event_id,
                rows=rows,
            )

        try:
            with self._driver.session(database=self._db) as session:
                session.execute_write(_write)
        except SaltEscrowError:
            raise
        except Exception as exc:  # fail closed: no escrow means no persist
            raise SaltEscrowError(f"salts not escrowed ({type(exc).__name__})") from exc

    def get(self, event_id: str) -> dict[str, bytes]:
        _validate(event_id)

        def _read(tx: Any) -> list[Any]:
            return list(
                tx.run(
                    "MATCH (s:ProvenanceSalt {event_id:$id}) "
                    "RETURN s.field_path AS p, s.salt_hex AS h",
                    id=event_id,
                )
            )

        try:
            with self._driver.session(database=self._db) as session:
                rows = session.execute_read(_read)
            salts: dict[str, bytes] = {}
            for row in rows:
                if row["p"] not in REDACTABLE_FIELDS or not _SALT_HEX_RE.match(str(row["h"])):
                    raise ValueError("bad escrow row")
                salts[row["p"]] = bytes.fromhex(row["h"])
        except (ValueError, TypeError) as exc:
            raise SaltEscrowError(f"escrow entry for {event_id} is malformed") from exc
        except Exception as exc:
            raise SaltEscrowError(f"salts not readable ({type(exc).__name__})") from exc
        return salts

    def delete(self, event_id: str) -> None:
        _validate(event_id)

        def _write(tx: Any) -> None:
            tx.run("MATCH (s:ProvenanceSalt {event_id:$id}) DELETE s", id=event_id)

        try:
            with self._driver.session(database=self._db) as session:
                session.execute_write(_write)
        except Exception as exc:
            raise SaltEscrowError(f"salts not deleted ({type(exc).__name__})") from exc
