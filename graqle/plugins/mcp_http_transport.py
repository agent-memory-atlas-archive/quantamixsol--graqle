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

NOTE (PR-a scope): per-session gate state (CG-01/CG-02, todos, cost) is still
held by the single ``KogniDevServer`` and is therefore shared by all HTTP
sessions. Isolating it per session is CR-INFRA-02 PR-b.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
from typing import Any
from urllib.parse import urlparse

DEFAULT_HOST = "127.0.0.1"
DEFAULT_TOKEN_ENV = "GRAQLE_MCP_HTTP_TOKEN"
SESSION_HEADER = "mcp-session-id"
MCP_PATH = "/mcp"


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


def create_app(server: Any, host: str = DEFAULT_HOST, token: str | None = None) -> Any:
    """Build the Starlette app serving *server* (a ``KogniDevServer``)."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route

    sessions: set[str] = set()
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
        if message.get("method") == "initialize":
            session_id = secrets.token_hex(16)
            sessions.add(session_id)
            headers[SESSION_HEADER] = session_id
        else:
            session_id = request.headers.get(SESSION_HEADER, "")
            if not session_id:
                return JSONResponse(_rpc_error(-32600, "missing Mcp-Session-Id"), status_code=400)
            if session_id not in sessions:
                return JSONResponse(_rpc_error(-32600, "unknown session"), status_code=404)

        try:
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
        sessions.discard(session_id)
        return Response(status_code=200)

    return Starlette(
        routes=[Route(MCP_PATH, post, methods=["POST"]), Route(MCP_PATH, delete, methods=["DELETE"])]
    )


def run_http(
    server: Any, host: str = DEFAULT_HOST, port: int = 8765, token_env: str = DEFAULT_TOKEN_ENV
) -> None:
    """Validate the bind/auth configuration, then serve until interrupted."""
    import uvicorn

    token = resolve_auth_token(host, token_env)  # raises before anything binds
    app = create_app(server, host=host, token=token)
    uvicorn.run(app, host=host, port=port, log_level="info")
