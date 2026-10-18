"""REL-HUB-01: `graq mcp serve --projects` is a Team/Enterprise feature."""

from __future__ import annotations

from typer.testing import CliRunner

from graqle.cli.main import app
from graqle.licensing.manager import TIER_FEATURES, LicenseTier


def _invoke(tmp_path):
    projects = tmp_path / "projects.yaml"
    projects.write_text("projects: {}\n", encoding="utf-8")
    return CliRunner().invoke(
        app, ["mcp", "serve", "--transport", "http", "--projects", str(projects)]
    )


def test_feature_belongs_to_team_not_free():
    assert "multi_project_hub" in TIER_FEATURES[LicenseTier.TEAM]
    assert "multi_project_hub" not in TIER_FEATURES[LicenseTier.FREE]
    assert "multi_project_hub" not in TIER_FEATURES[LicenseTier.PRO]


def test_community_refuses_projects_and_names_edition(tmp_path, monkeypatch):
    monkeypatch.setattr("graqle.licensing.manager.has_feature", lambda feature: False)
    result = _invoke(tmp_path)
    assert result.exit_code == 2
    assert "Team or Enterprise edition" in result.output
    # The refusal comes before the projects file is read.
    assert "non-empty 'projects' mapping" not in result.output


def test_team_edition_passes_gate_and_reaches_projects_validation(tmp_path, monkeypatch):
    monkeypatch.setattr("graqle.licensing.manager.has_feature", lambda feature: True)
    result = _invoke(tmp_path)
    assert result.exit_code == 2
    assert "Team or Enterprise edition" not in result.output
    assert "non-empty 'projects' mapping" in result.output


def test_licence_check_error_fails_closed(tmp_path, monkeypatch):
    def boom(feature):
        raise RuntimeError("licence backend down")

    monkeypatch.setattr("graqle.licensing.manager.has_feature", boom)
    result = _invoke(tmp_path)
    assert result.exit_code != 0
    assert "non-empty 'projects' mapping" not in result.output


def test_single_graph_http_not_gated(tmp_path, monkeypatch):
    monkeypatch.setattr("graqle.licensing.manager.has_feature", lambda feature: False)
    result = CliRunner().invoke(app, ["mcp", "serve", "--transport", "http"])
    # Refused for the missing --allowed-roots, not for edition.
    assert "Team or Enterprise edition" not in result.output
    assert "--allowed-roots" in result.output
