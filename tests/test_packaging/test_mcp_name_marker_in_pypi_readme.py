"""The MCP Registry ownership marker must live in the PyPI long_description.

The defect this pins (0.84.0, 2026-09-15): publishing to the MCP Registry
failed with HTTP 400 —

    registry validation failed for package 0 (graqle): PyPI package 'graqle'
    ownership validation failed. The server name 'io.github.quantamixsol/graqle'
    must appear as 'mcp-name: io.github.quantamixsol/graqle' in the package
    README

Root cause: ``<!-- mcp-name: ... -->`` lived in ``README.md``. CR-README-01
repointed ``pyproject.readme`` to ``README_PYPI.md`` for conversion reasons and
did not carry the marker across, so the published ``long_description`` no
longer contained it. The registry reads the **PyPI** README, not the GitHub
one, so ownership validation failed at the first tag push after the change.

0.83.0 published to the registry successfully; 0.84.0 was the first failure —
a clean break introduced by the pointer move.

Why the test is written against ``pyproject.readme`` rather than against a
hard-coded filename: the whole defect was a *pointer change* silently
invalidating an assumption about which file ships. Asserting on the pointer
means any future repoint is caught here rather than at a release.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"

#: The server name registered with the MCP Registry. Must match ``server.json``.
SERVER_NAME = "io.github.quantamixsol/graqle"

#: The exact marker string the registry greps for.
MARKER = f"mcp-name: {SERVER_NAME}"


def _readme_pointer() -> str:
    """Return the filename ``pyproject.toml`` declares as the package readme."""
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^readme\s*=\s*"([^"]+)"', text, re.M)
    assert m, "pyproject.toml has no top-level `readme = \"...\"` declaration"
    return m.group(1)


def test_pypi_readme_contains_mcp_name_marker() -> None:
    """Whatever file ships as long_description must carry the marker.

    Without it, ``mcp-publisher publish`` fails ownership validation and the
    MCP Registry entry silently stops tracking releases.
    """
    readme = ROOT / _readme_pointer()
    assert readme.is_file(), f"pyproject readme points at missing file: {readme}"

    body = readme.read_text(encoding="utf-8")
    assert MARKER in body, (
        f"{readme.name} does not contain {MARKER!r}. The MCP Registry reads the "
        f"PyPI long_description (not README.md) and will reject the publish "
        f"with HTTP 400 ownership-validation failure. Add "
        f"`<!-- {MARKER} -->` to {readme.name}."
    )


def test_marker_server_name_matches_server_json() -> None:
    """The marker must name the same server as ``server.json``.

    A mismatch fails validation just as surely as an absent marker.
    """
    import json

    server_json = ROOT / "server.json"
    if not server_json.exists():
        pytest.skip("server.json not present in this checkout")

    name = json.loads(server_json.read_text(encoding="utf-8-sig")).get("name")
    assert name == SERVER_NAME, (
        f"server.json declares {name!r} but this test (and the README marker) "
        f"expect {SERVER_NAME!r}. Update both together."
    )


def test_github_readme_keeps_its_marker_too() -> None:
    """README.md keeps the marker for anyone reading the repo directly.

    Not required by the registry once the pointer moved, but removing it would
    be a silent regression for GitHub-sourced tooling.
    """
    body = (ROOT / "README.md").read_text(encoding="utf-8")
    assert MARKER in body, "README.md lost its mcp-name marker"
