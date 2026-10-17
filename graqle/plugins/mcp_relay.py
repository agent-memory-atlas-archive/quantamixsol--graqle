"""Thin stdio relay to a shared GraQle MCP HTTP server (CR-INFRA-02 PR-c).

``graq mcp relay --url http://127.0.0.1:N`` is a stdio MCP process that holds
no graph and imports no ML code: each JSON-RPC line read from stdin is POSTed
to the shared server (``mcp_http_transport``) and the reply is written to
stdout, so an existing ``.mcp.json`` only changes its command.

Fail closed: if the server is unreachable, rejects the request or answers
with something that is not JSON-RPC, the client gets an explicit error. The
relay never falls back to loading a graph locally (it cannot: it does not
import the server).

Standard library only, on purpose (RSS).
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, TextIO
from urllib.parse import urlparse

DEFAULT_TOKEN_ENV = "GRAQLE_MCP_HTTP_TOKEN"
SESSION_HEADER = "Mcp-Session-Id"
ERR_UNREACHABLE = -32003
ERR_BAD_REPLY = -32004
TIMEOUT_S = 120


class RelayConfigError(RuntimeError):
    """Raised when the relay is configured unsafely or incorrectly."""


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalise_url(url: str) -> str:
    """Return the MCP endpoint URL for *url* (appends ``/mcp`` if no path)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RelayConfigError(f"--url must be an http(s) URL, got {url!r}")
    path = parsed.path.rstrip("/")
    return parsed._replace(path=path or "/mcp").geturl()


def _error_reply(message: dict[str, Any], code: int, text: str) -> dict[str, Any]:
    """A reply the client can show: tool error for tools/call, else JSON-RPC error."""
    if message.get("method") == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        }
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": code, "message": text}}


class Relay:
    """Forwards JSON-RPC messages to one shared server, tracking its session id."""

    def __init__(self, url: str, token: str | None = None) -> None:
        self.url = normalise_url(url)
        parsed = urlparse(self.url)
        if token is not None and parsed.scheme != "https" and not _is_loopback(parsed.hostname or ""):
            raise RelayConfigError("refusing to send the auth token over plain http to a non-loopback host")
        self._token = token
        self._session_id: str | None = None

    def forward(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """POST *message*; return the reply, or None for a notification (202)."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        if self._session_id is not None:
            headers[SESSION_HEADER] = self._session_id
        req = urllib.request.Request(
            self.url, data=json.dumps(message).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310 (scheme validated)
                sid = resp.headers.get(SESSION_HEADER)
                if message.get("method") == "initialize" and sid:
                    self._session_id = sid
                body = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read()).get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001 - detail is best effort; the error is reported anyway
                pass
            return _error_reply(
                message, ERR_UNREACHABLE,
                f"GraQle shared server at {self.url} rejected the request (HTTP {exc.code}{': ' + detail if detail else ''})",
            )
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return _error_reply(
                message, ERR_UNREACHABLE,
                f"GraQle shared server at {self.url} is unreachable ({type(exc).__name__}); "
                "start it with `graq mcp serve --transport http`. No local graph was loaded.",
            )
        if status == 202 or not body:
            return None
        try:
            reply = json.loads(body)
        except ValueError:
            return _error_reply(message, ERR_BAD_REPLY, "GraQle shared server returned a non-JSON reply")
        if not isinstance(reply, dict):
            return _error_reply(message, ERR_BAD_REPLY, "GraQle shared server returned an invalid reply")
        return reply


def run_relay(
    url: str,
    token_env: str = DEFAULT_TOKEN_ENV,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Relay newline-delimited JSON-RPC from stdin to the server until EOF."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    relay = Relay(url, os.environ.get(token_env, "").strip() or None)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            reply: dict[str, Any] | None = {
                "jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"},
            }
        else:
            if not isinstance(message, dict):
                reply = {
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: expected a single JSON object"},
                }
            else:
                reply = relay.forward(message)
                if reply is not None and "id" not in message:
                    print(f"graq mcp relay: dropped error for notification: {reply}", file=sys.stderr)
                    reply = None
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
