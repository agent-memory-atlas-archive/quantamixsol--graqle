"""DAG-PORT-01 acceptance 2: ``decision_layer`` must not ship in the wheel.

The wheel is built from ``packages = ["graqle"]`` plus the ``artifacts``
and ``force-include`` entries in ``pyproject.toml``. Anything that can reach
the wheel therefore lives under ``graqle/`` or is named in those entries, so
the checks below cover both sources without needing a build.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GRAQLE_PKG = REPO_ROOT / "graqle"
PYPROJECT = REPO_ROOT / "pyproject.toml"

NEEDLE = "decision_layer"
_BYTECODE_DIRS = {"__pycache__"}


def _packaged_paths() -> list[str]:
    """Every file path under the package tree, bytecode caches excluded."""
    return [
        str(p.relative_to(REPO_ROOT))
        for p in GRAQLE_PKG.rglob("*")
        if p.is_file() and not _BYTECODE_DIRS.intersection(p.parts)
    ]


def test_package_tree_has_no_decision_layer_path() -> None:
    paths = _packaged_paths()
    assert paths, "package tree scan found no files; the scan is broken"
    offenders = [p for p in paths if NEEDLE in p.lower()]
    assert offenders == []


def test_package_tree_has_no_decision_layer_in_source() -> None:
    offenders = [
        p
        for p in _packaged_paths()
        if p.endswith((".py", ".md", ".json", ".yaml", ".yml", ".toml"))
        and NEEDLE in (REPO_ROOT / p).read_text(encoding="utf-8", errors="ignore").lower()
    ]
    assert offenders == []


def test_build_config_does_not_reference_decision_layer() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'packages = ["graqle"]' in text, "wheel package config changed; revisit this test"
    assert NEEDLE not in text.lower()
