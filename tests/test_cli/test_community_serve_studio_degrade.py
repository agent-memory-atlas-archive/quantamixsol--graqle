"""0.85.1: Community users get a clean message, not a traceback, from graq serve / studio.

The Community wheel ships without the proprietary backends (graqle.server / graqle.studio).
These tests simulate that by making those imports fail, then drive the real CLI.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from graqle.cli.main import app

pytest.importorskip("uvicorn")
pytest.importorskip("fastapi")

runner = CliRunner()


@pytest.fixture
def community_wheel(monkeypatch, tmp_path):
    """Simulate the Community wheel: the proprietary packages cannot be imported."""
    for name in ("graqle.server", "graqle.server.app", "graqle.studio", "graqle.studio.app"):
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.chdir(tmp_path)


def _assert_clean_degrade(result, command_label: str) -> None:
    assert result.exit_code == 2, result.output
    assert not isinstance(result.exception, ModuleNotFoundError)
    assert "Traceback" not in result.output
    assert f"'{command_label}'" in result.output
    assert "pip install" not in result.output
    assert "graqle.com/pricing" in result.output


def test_serve_degrades_cleanly_on_community(community_wheel):
    result = runner.invoke(app, ["serve", "--port", "8099"])
    _assert_clean_degrade(result, "graq serve")
    # Must fail before announcing a server start that can never happen.
    assert "Server starting" not in result.output


def test_serve_with_reload_also_degrades_cleanly(community_wheel):
    # uvicorn would import the app in a subprocess under --reload; the up-front
    # resolution must catch the absent backend first.
    result = runner.invoke(app, ["serve", "--reload", "--port", "8099"])
    _assert_clean_degrade(result, "graq serve")


def test_studio_names_its_own_command(community_wheel):
    result = runner.invoke(app, ["studio", "--no-browser", "--port", "8098"])
    _assert_clean_degrade(result, "graq studio")
    assert "'graq serve'" not in result.output
