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
from typing import Protocol

from graqle.assurance.provenance_event import REDACTABLE_FIELDS
from graqle.core.exceptions import GraqleError

__all__ = ["SaltEscrow", "FileSaltEscrow", "SaltEscrowError"]

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
