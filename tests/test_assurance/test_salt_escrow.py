"""CR-018 PR-018a: file salt escrow (AC-12 escrow half, fail-closed behaviour)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from graqle.assurance.provenance_event import REDACTABLE_FIELDS
from graqle.assurance.salt_escrow import FileSaltEscrow, SaltEscrowError

EID = "evt_01J7Q0F3ZK9B4N2X8P5R6T7V9W"
POSIX = os.name != "nt"


def _salts() -> dict[str, bytes]:
    return {p: bytes([i]) * 32 for i, p in enumerate(REDACTABLE_FIELDS, start=1)}


def test_round_trip(tmp_path: Path) -> None:
    esc = FileSaltEscrow(tmp_path / "salts")
    esc.put(EID, _salts())
    assert esc.get(EID) == _salts()


def test_get_of_unknown_or_erased_entry_is_empty(tmp_path: Path) -> None:
    esc = FileSaltEscrow(tmp_path)
    assert esc.get(EID) == {}
    esc.put(EID, _salts())
    esc.delete(EID)
    assert esc.get(EID) == {}
    esc.delete(EID)  # idempotent


def test_put_never_overwrites(tmp_path: Path) -> None:
    esc = FileSaltEscrow(tmp_path)
    esc.put(EID, _salts())
    other = {p: b"\xff" * 32 for p in REDACTABLE_FIELDS}
    with pytest.raises(SaltEscrowError, match="already escrowed"):
        esc.put(EID, other)
    assert esc.get(EID) == _salts()
    assert [p.name for p in tmp_path.iterdir()] == [f"{EID}.json"]  # no temp litter


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
def test_files_are_0600_and_directory_0700(tmp_path: Path) -> None:
    root = tmp_path / "salts"
    esc = FileSaltEscrow(root)
    esc.put(EID, _salts())
    assert stat.S_IMODE((root / f"{EID}.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o666])
def test_loose_permissions_fail_closed(tmp_path: Path, mode: int) -> None:
    esc = FileSaltEscrow(tmp_path)
    esc.put(EID, _salts())
    os.chmod(tmp_path / f"{EID}.json", mode)
    with pytest.raises(SaltEscrowError, match="accessible"):
        esc.get(EID)


@pytest.mark.parametrize(
    "bad_id",
    ["", "../x", "evt_short", EID + "x", EID.lower(), "x/" + EID, "evt_" + "I" * 26, EID + "\n"],
)
def test_event_id_cannot_escape_the_root(tmp_path: Path, bad_id: str) -> None:
    esc = FileSaltEscrow(tmp_path / "salts")
    with pytest.raises(SaltEscrowError):
        esc.put(bad_id, _salts())
    with pytest.raises(SaltEscrowError):
        esc.get(bad_id)
    with pytest.raises(SaltEscrowError):
        esc.delete(bad_id)
    assert not (tmp_path / "salts").exists()


@pytest.mark.parametrize(
    "salts",
    [
        {"actor.agent_id": b"x" * 31},
        {"actor.agent_id": b"x" * 33},
        {"actor.agent_id": "x" * 32},
        {"activity.decision_id": b"x" * 32},  # not a redactable field
        {"../../escape": b"x" * 32},
    ],
)
def test_invalid_salts_are_refused_and_nothing_is_written(
    tmp_path: Path, salts: dict[str, bytes]
) -> None:
    esc = FileSaltEscrow(tmp_path / "salts")
    with pytest.raises(SaltEscrowError):
        esc.put(EID, salts)
    assert not (tmp_path / "salts").exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"actor.agent_id": "zz"}',
        '{"actor.agent_id": 5}',
        '{"activity.decision_id": "' + "ab" * 32 + '"}',
        '{"actor.agent_id": "' + "AB" * 32 + '"}',
    ],
)
def test_malformed_entry_fails_closed(tmp_path: Path, content: str) -> None:
    path = tmp_path / f"{EID}.json"
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(SaltEscrowError, match="malformed"):
        FileSaltEscrow(tmp_path).get(EID)


def test_only_present_fields_need_a_salt(tmp_path: Path) -> None:
    esc = FileSaltEscrow(tmp_path)
    esc.put(EID, {"actor.agent_id": b"a" * 32})
    assert esc.get(EID) == {"actor.agent_id": b"a" * 32}
