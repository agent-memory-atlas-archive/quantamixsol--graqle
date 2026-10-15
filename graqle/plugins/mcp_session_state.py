"""Per-MCP-session state for the shared HTTP server (CR-INFRA-02 PR-b).

The CG-01 / CG-02 gate flags, todos, session cache and cost counters used to be
plain attributes of ``KogniDevServer`` (one instance == one stdio session). With
the HTTP transport one instance serves many sessions, so these attributes are
routed through a ``contextvars.ContextVar`` holding the *current* session's
``SessionState``. The HTTP transport binds the ContextVar around each request;
when it is unset (stdio, tests, ``__init__``) the instance's own default state is
used, so the stdio path behaves exactly as before.

ContextVars are task-local, so interleaved ``await`` points in concurrent
requests can never observe each other's state.
"""

from __future__ import annotations

import contextvars
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class SessionState:
    """Everything that must not leak between two MCP sessions."""

    session_started: bool = False  # CG-01
    plan_active: bool = False  # CG-02
    session_cost_usd: float = 0.0
    cost_advisory_emitted: bool = False
    mcp_client_name: str | None = None
    cg01_bypass: bool = False
    cg02_bypass: bool = False
    cg03_bypass: bool = False
    todos: list[dict[str, Any]] = field(default_factory=list)
    session_cache: OrderedDict = field(default_factory=OrderedDict)


_current: contextvars.ContextVar[SessionState | None] = contextvars.ContextVar(
    "graqle_mcp_session_state", default=None
)


@contextmanager
def bind_session(state: SessionState) -> Iterator[SessionState]:
    """Make *state* the current session for the enclosed code (task-local)."""
    token = _current.set(state)
    try:
        yield state
    finally:
        _current.reset(token)


def _prop(name: str) -> property:
    def getter(self: Any) -> Any:
        state = _current.get() or self.__dict__.setdefault("_default_session", SessionState())
        return getattr(state, name)

    def setter(self: Any, value: Any) -> None:
        state = _current.get() or self.__dict__.setdefault("_default_session", SessionState())
        setattr(state, name, value)

    return property(getter, setter)


class PerSessionStateMixin:
    """Routes the per-session attributes to the current ``SessionState``."""

    _session_started = _prop("session_started")
    _plan_active = _prop("plan_active")
    _session_cost_usd = _prop("session_cost_usd")
    _cost_advisory_emitted = _prop("cost_advisory_emitted")
    _mcp_client_name = _prop("mcp_client_name")
    _cg01_bypass = _prop("cg01_bypass")
    _cg02_bypass = _prop("cg02_bypass")
    _cg03_bypass = _prop("cg03_bypass")
    _todos = _prop("todos")
    _session_cache = _prop("session_cache")
