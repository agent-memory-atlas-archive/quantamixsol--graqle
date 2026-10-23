"""CR-016 PR-016b guard pattern (Research standing rule 2): hash pins + runtime probes.

The three files that carry the write-path and detection guarantees are pinned
by the SHA-256 of their COMMITTED content, so any change to them is a visible,
reviewed change to this test, never a silent one. The runtime probe proves that
only ``kg_persist`` reaches the private write module.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

PROTECTED: dict[str, str] = {
    # OD-01b (PR-374 round-1 research review): B1-B4 land in both files below.
    "graqle/governance/tamper_evidence/_assurance_write.py": (
        "16121ceebf0b4c89d72b5ddf89382d82340a056eb7e1ed5ad0c7b2200e6c6405"
    ),
    "scripts/ci/assurance_write_path_gate.py": (
        "590fe197e77deb1436096c133f426ff17616bc7e42a585cc05cb33459af14ecc"
    ),
    # Re-pinned after ecf10f80 (CR-016/OD-01b): the B4 participant-set check now
    # coerces edge endpoint ids to str before the membership test; one line in
    # assurance_integrity.py, no behaviour change outside that coercion.
    "graqle/ontology/assurance_integrity.py": (
        "9ec90d539e161b1937b48ddfa35396bfac2c46c1cd6e78cc61f14a384495a780"
    ),
}


def _committed_bytes(path: str) -> bytes:
    """The file as COMMITTED at HEAD; outside a git checkout, the file on disk."""
    try:
        return subprocess.run(
            ["git", "show", f"HEAD:{path}"], cwd=ROOT, capture_output=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return (ROOT / path).read_bytes()


@pytest.mark.parametrize("path", sorted(PROTECTED))
def test_protected_file_is_pinned(path: str) -> None:
    data = _committed_bytes(path).replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == PROTECTED[path], f"{path} changed (CR-016 PR-016b)"


_PROBE = """
import sys
import {module}
print(",".join(sorted(m for m in sys.modules if m.endswith("_assurance_write"))))
"""


@pytest.mark.parametrize(
    "module",
    [
        "graqle.connectors.neo4j",
        "graqle.ontology.assurance_integrity",
        "graqle.ontology.assurance_migration",
        "graqle.governance.tamper_evidence.kg_persist",
    ],
)
def test_nothing_loads_the_private_write_module_at_import(module: str) -> None:
    # kg_persist imports it lazily, inside persist_assurance_ops only.
    out = subprocess.run(
        [sys.executable, "-c", _PROBE.format(module=module)],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout.strip()
    assert out == "", f"{module} loaded {out}"
