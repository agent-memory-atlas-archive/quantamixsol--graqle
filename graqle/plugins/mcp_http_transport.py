"""HTTP transport for the GraQle MCP dev server (CR-INFRA-02 PR-a).

One process, one graph, many concurrent clients. MCP "streamable HTTP" subset:
``POST /mcp`` carries one JSON-RPC message and is answered with one JSON body
(or 202 for notifications); ``DELETE /mcp`` ends a session. Sessions are
identified by the ``Mcp-Session-Id`` header issued on ``initialize``.

Security defaults (fail closed):
  * bind defaults to 127.0.0.1;
  * a non-loopback bind refuses to start unless the auth-token env var is set;
  * when a token is configured every request must carry it as a Bearer token;
  * a request with a non-loopback ``Origin`` to a loopback bind is rejected.

Per-session gate state (CG-01/CG-02, todos, session cache, cost) lives in a
``SessionState`` per ``Mcp-Session-Id`` (CR-INFRA-02 PR-b, see
``mcp_session_state``); each request is dispatched with that state bound.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from graqle.plugins.mcp_relay_gate import content_scan, evaluate_gate, graph_snapshot
from graqle.plugins.mcp_relay_routing import canonical_name
from graqle.plugins.mcp_session_state import SessionState, bind_session, set_http_serving
from graqle.plugins.mcp_workspace import (
    WORKSPACE_HEADER,
    WorkspaceError,
    bind_root,
    confine_arguments,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_TOKEN_ENV = "GRAQLE_MCP_HTTP_TOKEN"
SESSION_HEADER = "mcp-session-id"
MCP_PATH = "/mcp"
RELAY_GATE_PATH = "/relay/gate"  # CR-INFRA-02f: per-mutation gate check for the hybrid relay
RELAY_SNAPSHOT_PATH = "/relay/snapshot"  # CR-INFRA-02f: versioned graph snapshot
PROJECT_HEADER = "x-graqle-project"  # hub mode: binds a session to one project


class HttpTransportConfigError(RuntimeError):
    """Raised when the HTTP transport is configured unsafely."""


def is_loopback_host(host: str) -> bool:
    """True only for ``localhost`` or a loopback IP literal."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_auth_token(host: str, token_env: str = DEFAULT_TOKEN_ENV) -> str | None:
    """Return the auth token from env var ``token_env`` (never a literal).

    Raises HttpTransportConfigError for a non-loopback bind without a token.
    """
    token = os.environ.get(token_env, "").strip() or None
    if token is None and not is_loopback_host(host):
        raise HttpTransportConfigError(
            f"refusing to bind non-loopback host {host!r} without an auth token: "
            f"set the {token_env} environment variable"
        )
    return token


def _rpc_error(code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}


def _names_other_project(message: dict[str, Any], bound: str) -> bool:
    """True if a tools/call explicitly names a project other than the bound one."""
    params = message.get("params")
    arguments = params.get("arguments") if isinstance(params, dict) else None
    if not isinstance(arguments, dict):
        return False
    return any(
        key in arguments and arguments[key] != bound for key in ("project", "project_name")
    )


def create_app(
    server: Any = None,
    host: str = DEFAULT_HOST,
    token: str | None = None,
    hub: Any = None,
    allowed_roots: list[Path] | None = None,
) -> Any:
    """Build the Starlette app serving *server* (a ``KogniDevServer``).

    With *hub* (a ``ProjectHub``, CR-INFRA-02 PR-d) the app serves several
    projects instead: each session is bound to one project at ``initialize``.

    Single-server mode (CR-INFRA-02e) requires *allowed_roots*: each session
    binds its workspace root once at ``initialize`` and every tool call is
    confined to it.
    """
    if (server is None) == (hub is None):
        raise HttpTransportConfigError("pass exactly one of server or hub")
    if server is not None and not allowed_roots:
        raise HttpTransportConfigError("a shared server needs allowed_roots (--allowed-roots)")
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route

    sessions: dict[str, SessionState] = {}
    session_projects: dict[str, str] = {}  # hub mode: session id -> bound project
    loopback_bind = is_loopback_host(host)

    def _check(request: Request) -> Response | None:
        if token is not None:
            auth = request.headers.get("authorization", "")
            scheme, _, supplied = auth.partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(
                supplied.strip().encode(), token.encode()
            ):
                return JSONResponse(_rpc_error(-32001, "unauthorized"), status_code=401)
        origin = request.headers.get("origin")
        if origin and loopback_bind:
            origin_host = urlparse(origin).hostname or ""
            if not is_loopback_host(origin_host):
                return JSONResponse(_rpc_error(-32002, "origin not allowed"), status_code=403)
        return None

    async def post(request: Request) -> Response:
        denied = _check(request)
        if denied is not None:
            return denied
        try:
            message = json.loads(await request.body())
        except (ValueError, UnicodeDecodeError) as exc:
            return JSONResponse(_rpc_error(-32700, f"Parse error: {exc}"), status_code=400)
        if not isinstance(message, dict):
            return JSONResponse(
                _rpc_error(-32600, "Invalid Request: expected a single JSON object"),
                status_code=400,
            )

        headers: dict[str, str] = {}
        requested_project = request.headers.get(PROJECT_HEADER, "")
        if hub is not None and message.get("method") == "initialize":
            if not requested_project:
                return JSONResponse(
                    _rpc_error(-32600, f"missing project: send the {PROJECT_HEADER} header"),
                    status_code=400,
                )
            if not hub.has(requested_project):
                return JSONResponse(_rpc_error(-32600, "unknown project"), status_code=404)
        workspace_value = request.headers.get(WORKSPACE_HEADER, "")
        new_root: Path | None = None
        if server is not None and message.get("method") == "initialize":
            try:
                new_root = bind_root(workspace_value, allowed_roots or [])
            except WorkspaceError as exc:
                return JSONResponse(_rpc_error(-32002, str(exc)), status_code=403)
            existing = sessions.get(request.headers.get(SESSION_HEADER, ""))
            if existing is not None and existing.workspace_root != new_root:
                return JSONResponse(
                    _rpc_error(-32002, "workspace root is already bound and cannot change"),
                    status_code=403,
                )
        if message.get("method") == "initialize":
            session_id = secrets.token_hex(16)
            sessions[session_id] = SessionState(
                workspace_root=new_root, http_mode=server is not None
            )
            if hub is not None:
                session_projects[session_id] = requested_project
            headers[SESSION_HEADER] = session_id
        else:
            session_id = request.headers.get(SESSION_HEADER, "")
            if not session_id:
                return JSONResponse(_rpc_error(-32600, "missing Mcp-Session-Id"), status_code=400)
            if session_id not in sessions:
                return JSONResponse(_rpc_error(-32600, "unknown session"), status_code=404)

        bound = session_projects.get(session_id)
        if hub is not None:
            # Isolation: a session may only ever address the project it was bound to.
            if bound is None or (requested_project and requested_project != bound):
                return JSONResponse(_rpc_error(-32002, "project mismatch"), status_code=403)
            if _names_other_project(message, bound):
                return JSONResponse(_rpc_error(-32002, "request names another project"), status_code=403)

        state = sessions[session_id]
        # Single-server: the root bound at initialize. Hub (INFRA-02g): the bound
        # project's own root. Either way every tool call is confined to it.
        root = state.workspace_root if server is not None else hub.root_of(bound)
        if root is None:  # cannot happen after initialize; fail closed anyway
            return JSONResponse(_rpc_error(-32002, "workspace root not bound"), status_code=403)
        if server is not None and workspace_value:
            try:
                if bind_root(workspace_value, allowed_roots or []) != root:
                    raise WorkspaceError("workspace root is already bound and cannot change")
            except WorkspaceError as exc:
                return JSONResponse(_rpc_error(-32002, str(exc)), status_code=403)
        params = message.get("params")
        if message.get("method") == "tools/call" and isinstance(params, dict):
            try:
                arguments = params.get("arguments") or {}
                if not isinstance(arguments, dict):
                    raise WorkspaceError("tool arguments must be an object")
                message = {
                    **message,
                    "params": {
                        **params,
                        "arguments": confine_arguments(root, str(params.get("name", "")), arguments),
                    },
                }
            except WorkspaceError as exc:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {"content": [{"type": "text", "text": str(exc)}], "isError": True},
                    },
                    headers=headers,
                )

        try:
            with bind_session(state):
                if hub is not None:
                    response = await hub.dispatch(bound, message)
                else:
                    response = await server._handle_jsonrpc(message)
        except Exception as exc:  # fail closed: report, never pass through
            return JSONResponse(
                _rpc_error(-32603, f"Internal error: {type(exc).__name__}"),
                status_code=500,
                headers=headers,
            )
        if response is None:
            return Response(status_code=202, headers=headers)
        return JSONResponse(response, headers=headers)

    async def delete(request: Request) -> Response:
        denied = _check(request)
        if denied is not None:
            return denied
        session_id = request.headers.get(SESSION_HEADER, "")
        if session_id not in sessions:
            return JSONResponse(_rpc_error(-32600, "unknown session"), status_code=404)
        sessions.pop(session_id, None)
        session_projects.pop(session_id, None)
        return Response(status_code=200)

    def _relay_session(request: Request) -> tuple[SessionState | None, Response | None]:
        """Authenticate a relay side-channel request and look up its session."""
        denied = _check(request)
        if denied is not None:
            return None, denied
        if server is None:  # hub mode has no per-session gate: fail closed
            return None, JSONResponse({"allow": False, "reason": "unsupported in hub mode"}, status_code=403)
        state = sessions.get(request.headers.get(SESSION_HEADER, ""))
        if state is None or state.workspace_root is None:
            return None, JSONResponse({"allow": False, "reason": "unknown session"}, status_code=404)
        return state, None

    async def relay_gate(request: Request) -> Response:
        """CR-INFRA-02f: may this session perform this local mutation right now?"""
        state, denied = _relay_session(request)
        if denied is not None:
            return denied
        assert state is not None and state.workspace_root is not None
        try:
            body = json.loads(await request.body())
            tool, arguments = body["tool"], body.get("arguments") or {}
            if not isinstance(tool, str) or not isinstance(arguments, dict):
                raise ValueError("bad shape")
        except (ValueError, KeyError, UnicodeDecodeError, TypeError):
            return JSONResponse({"allow": False, "reason": "malformed gate request"}, status_code=400)
        verdict = evaluate_gate(server, state, tool, arguments, state.workspace_root)
        if verdict["allow"] and canonical_name(tool) == "graq_write" and not arguments.get("dry_run", True):
            try:
                verdict = await content_scan(server, state, arguments, state.workspace_root)
            except Exception as exc:  # fail closed
                verdict = {"allow": False, "reason": f"content scan failed ({type(exc).__name__})"}
        return JSONResponse(verdict)

    async def relay_snapshot(request: Request) -> Response:
        state, denied = _relay_session(request)
        if denied is not None:
            return denied
        return JSONResponse(graph_snapshot(server))

    return Starlette(
        routes=[
            Route(MCP_PATH, post, methods=["POST"]),
            Route(MCP_PATH, delete, methods=["DELETE"]),
            Route(RELAY_GATE_PATH, relay_gate, methods=["POST"]),
            Route(RELAY_SNAPSHOT_PATH, relay_snapshot, methods=["POST"]),
        ]
    )


def run_http(
    server: Any = None,
    host: str = DEFAULT_HOST,
    port: int = 8765,
    token_env: str = DEFAULT_TOKEN_ENV,
    hub: Any = None,
    allowed_roots: list[Path] | None = None,
) -> None:
    """Validate the bind/auth configuration, then serve until interrupted."""
    import uvicorn

    token = resolve_auth_token(host, token_env)  # raises before anything binds
    app = create_app(server, host=host, token=token, hub=hub, allowed_roots=allowed_roots)
    set_http_serving(server is not None)
    uvicorn.run(app, host=host, port=port, log_level="info")
