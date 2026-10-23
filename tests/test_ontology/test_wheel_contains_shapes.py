"""CR-016 PR-016d AC-11: assurance.ttl ships in the wheel and resolves via importlib.resources."""

from __future__ import annotations

import fnmatch
import importlib.resources
import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = pytest.importorskip("tomli")

ROOT = Path(__file__).resolve().parents[2]
WHEEL_PATH = "graqle/ontology/shapes/assurance.ttl"


def test_resource_resolves():
    res = importlib.resources.files("graqle.ontology.shapes") / "assurance.ttl"
    assert res.is_file()
    assert "ga:ShapeSetMetadata" in res.read_text(encoding="utf-8")


def test_wheel_config_does_not_exclude_assurance_shapes():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    wheel = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert "graqle" in wheel["packages"]
    assert not [p for p in wheel.get("exclude", []) if fnmatch.fnmatch(WHEEL_PATH, p)]


@pytest.mark.skipif(importlib.util.find_spec("hatchling") is None, reason="hatchling not installed")
def test_built_wheel_contains_shapes(tmp_path):
    out = tmp_path / "dist"
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
         "-w", str(out), str(ROOT)],
        check=True,
        capture_output=True,
    )
    wheels = list(out.glob("*.whl"))
    assert wheels
    with zipfile.ZipFile(wheels[0]) as z:
        assert WHEEL_PATH in z.namelist()
