"""CR-INFRA-02 PR-d: CLI flags (--projects, --project) and relay project header."""

from __future__ import annotations

import io
import json

from typer.testing import CliRunner

from graqle.cli.main import app
from graqle.plugins import mcp_relay


class _Resp:
    status = 200
    headers = {mcp_relay.SESSION_HEADER: "sid"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b'{"jsonrpc":"2.0","id":1,"result":{}}'


def test_relay_sends_project_header_on_every_request(monkeypatch):
    seen = []

    def fake_urlopen(req, timeout):
        seen.append({k.lower(): v for k, v in req.header_items()})
        return _Resp()

    monkeypatch.setattr(mcp_relay.urllib.request, "urlopen", fake_urlopen)
    out = io.StringIO()
    lines = [{"jsonrpc": "2.0", "id": i, "method": "initialize" if i == 1 else "tools/list"} for i in (1, 2)]
    mcp_relay.run_relay(
        "http://127.0.0.1:1", stdin=io.StringIO("\n".join(json.dumps(m) for m in lines)), stdout=out,
        project="alpha",
    )
    assert [h["x-graqle-project"] for h in seen] == ["alpha", "alpha"]


def test_relay_without_project_sends_no_project_header(monkeypatch):
    seen = []
    monkeypatch.setattr(
        mcp_relay.urllib.request, "urlopen",
        lambda req, timeout: seen.append(dict(req.header_items())) or _Resp(),
    )
    mcp_relay.run_relay(
        "http://127.0.0.1:1",
        stdin=io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})),
        stdout=io.StringIO(),
    )
    assert all("X-graqle-project" not in h for h in seen)


def test_serve_projects_requires_http_transport():
    result = CliRunner().invoke(app, ["mcp", "serve", "--projects", "projects.yaml"])
    assert result.exit_code == 2
    assert "requires --transport http" in result.output


def test_serve_with_invalid_projects_file_refuses_to_start(tmp_path):
    bad = tmp_path / "projects.yaml"
    bad.write_text("projects: {}\n", encoding="utf-8")
    result = CliRunner().invoke(
        app, ["mcp", "serve", "--transport", "http", "--projects", str(bad)]
    )
    assert result.exit_code == 2
    assert "non-empty 'projects' mapping" in result.output
