"""CR-016 AC-1 and the Research guard pattern: flag off is byte-identical, proven at runtime.

Each probe runs in a fresh interpreter so no other test's registration can leak in.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: SHA-256 of the sorted JSON dump of each registry on private master before
#: CR-016 (flag off). Any change without the flag is an AC-1 regression.
GOLDEN = {
    "UPPER": "876f8778d9f2496b495e44cf8195d7e1f99a43432e8a295224af1e6dee29d2e7",
    "NODE": "65d3cda2231dafc39a2b6c5eea9c2f3b9c27689cd964e3a35d23e94e6708db50",
    "EDGE": "6f25c67ac96213fb1466be9e29b99b45b502a0ef56c8f710a8dd8fe17a177026",
}

_DUMP = """
import dataclasses, hashlib, json, os, sys
os.environ.pop("GRAQLE_DAG_ENABLED", None)
from graqle.ontology.upper import UPPER_HIERARCHY
from graqle.ontology import schema
{extra}
def h(o): return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()
print(h(UPPER_HIERARCHY))
print(h({{k: dataclasses.asdict(v) for k, v in schema.NODE_SHAPES.items()}}))
print(h({{k: dataclasses.asdict(v) for k, v in schema.EDGE_SHAPES.items()}}))
"""

_REGISTER = """
from graqle.ontology.upper import UpperOntology
from graqle.ontology.assurance import register_assurance_ontology
assert register_assurance_ontology(UpperOntology()).skipped
"""


def _hashes(extra: str = "") -> list[str]:
    out = subprocess.run(
        [sys.executable, "-c", _DUMP.format(extra=extra)],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout.split()
    return out


def test_registries_match_golden_without_the_module() -> None:
    assert _hashes() == [GOLDEN["UPPER"], GOLDEN["NODE"], GOLDEN["EDGE"]]


def test_importing_and_registering_with_the_flag_off_changes_nothing() -> None:
    assert _hashes(_REGISTER) == [GOLDEN["UPPER"], GOLDEN["NODE"], GOLDEN["EDGE"]]


def test_existing_ontology_imports_do_not_load_the_assurance_layer() -> None:
    probe = (
        "import sys, graqle.ontology, graqle.ontology.schema, graqle.ontology.upper;"
        "print(sorted(m for m in sys.modules if m.startswith('graqle.assurance')"
        " or m in ('graqle.ontology.assurance', 'graqle.ontology.scope_resolution')))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.strip()
    assert out == "[]"


def test_importing_the_module_with_the_flag_off_loads_no_dag_settings() -> None:
    probe = (
        "import os, sys; os.environ.pop('GRAQLE_DAG_ENABLED', None);"
        "import graqle.ontology.assurance, graqle.ontology.scope_resolution;"
        "print('graqle.assurance.settings' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.strip()
    assert out == "False"
