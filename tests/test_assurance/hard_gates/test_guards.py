"""CR-013 AC-19 (flag-off, side-effect-free import) and AC-21 (protected files untouched)."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]

#: Line-ending-normalised SHA-256 of files CR-013 must never modify. A mismatch
#: means a CR-013 PR touched a file its spec declares untouched (AC-21). Update
#: only in a PR whose own CR is allowed to change that file.
PROTECTED: dict[str, str] = {
    "graqle/core/rbac.py": "62b8ca5f5cacc1fd8974b338424c252768b18c720c5e98921c66d6042d0686a8",
    "graqle/intelligence/governance/drace.py": "77b91ba7acc9abc620a6ee134ba1116b5fe0b99e93e355f8867df598dbdb0406",  # noqa: E501
    # Re-pinned by CR-015 PR-015b, the CR that owns the check() dispatcher edit.
    "graqle/core/governance.py": "f4960b4e459d8dc4326d65767dd5050815f48d86dfce32950b1dcbb993aa5df5",
}


@pytest.mark.parametrize("path", sorted(PROTECTED))
def test_protected_file_is_unmodified(path: str) -> None:
    data = (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == PROTECTED[path], f"{path} changed (CR-013 AC-21)"


_PROBE = """
import os, sys
os.environ.pop("GRAQLE_DAG_ENABLED", None)
before = set(sys.modules)
import graqle.assurance.hard_gates as hg
reg = hg.default_registry()
loaded = set(sys.modules) - before
bad = sorted(m for m in loaded if m in ("graqle.core.rbac", "graqle.core.governance")
             or m.startswith("graqle.governance.tamper_evidence"))
print(",".join(bad))
"""


def test_import_and_registry_construction_have_no_side_effects() -> None:
    """Importing the module and building the registry loads no RBAC, no legacy
    governance middleware and no canonicaliser — those load only when a gate runs."""
    out = subprocess.run(
        [sys.executable, "-c", _PROBE], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.strip()
    assert out == ""


def test_governance_still_does_not_load_assurance() -> None:
    probe = (
        "import sys, graqle.governance, graqle.governance.trace_schema;"
        "print(any(m.startswith('graqle.assurance') for m in sys.modules))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.strip()
    assert out == "False"
