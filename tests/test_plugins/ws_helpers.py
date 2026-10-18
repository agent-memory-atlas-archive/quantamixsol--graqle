"""Test helper (CR-INFRA-02e): a TestClient for a single shared server that sends a workspace root."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from graqle.plugins import mcp_http_transport as t
from graqle.plugins.mcp_workspace import WORKSPACE_HEADER


def ws_client(server: Any, root: Path | None = None, allowed: list[Path] | None = None, **kw: Any) -> TestClient:
    root = root or Path.cwd()
    app = t.create_app(server, allowed_roots=allowed or [Path(root.anchor or "/")], **kw)
    return TestClient(app, headers={WORKSPACE_HEADER: str(root)})
