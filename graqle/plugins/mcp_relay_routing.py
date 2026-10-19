"""Routing table for the hybrid relay (CR-INFRA-02f).

Every ``graq_*`` tool is assigned to exactly one class:

* ``LOCAL``: file / git / bash / test tools; the relay runs them on the user's
  own workspace root, with the user's own permissions, without a graph.
* ``HUB``: graph tools; always forwarded to the shared server (``graq_learn``
  and every other graph write stay central).
* ``MIXED``: need graph context AND local files; run through the fixed
  lock -> snapshot -> compute -> recheck -> write pipeline.

The table is versioned and checked against the server's tool list by a test
(``tests/test_plugins/test_mcp_relay_routing.py``): a tool missing from the
table, or listed twice, fails the build. An unknown tool is refused at run
time, never guessed.

Standard library only, on purpose (relay RSS).
"""

from __future__ import annotations

ROUTING_VERSION = 1

LOCAL = "LOCAL"
HUB = "HUB"
MIXED = "MIXED"

_LOCAL_TOOLS = (
    "bash", "deps_install", "git_branch", "git_commit", "git_diff", "git_log",
    "git_status", "glob", "grep", "read", "test", "vendor", "write",
)

_MIXED_TOOLS = (
    "apply", "auto", "chat_turn", "edit", "generate", "lifecycle", "preflight",
    "review", "scaffold", "workflow",
)

_HUB_TOOLS = (
    "audit", "calibrate_governance", "chat_cancel", "chat_poll", "chat_resume",
    "config_audit", "context", "correct", "debug", "drace", "gate",
    "gate_install", "gate_status", "gcc_status", "github_diff", "github_pr",
    "gov_gate", "graph_health", "impact", "ingest", "inspect", "kg_diag",
    "learn", "lessons", "memory", "phantom_audit", "phantom_browse",
    "phantom_click", "phantom_discover", "phantom_flow", "phantom_screenshot",
    "phantom_session", "phantom_type", "plan", "predict", "profile", "reason",
    "reason_batch", "release_gate", "reload", "route", "runtime",
    "safety_check", "scorch_a11y", "scorch_audit", "scorch_auth_flow",
    "scorch_behavioral", "scorch_brand", "scorch_conversion", "scorch_diff",
    "scorch_i18n", "scorch_mobile", "scorch_perf", "scorch_report",
    "scorch_security", "scorch_seo", "session_compact", "session_list",
    "session_resume", "todo", "vsce_check", "web_search",
)

# Local tools that change the user's disk or run code: every call is checked
# with the hub first (default closed). Read-only local tools are not.
LOCAL_MUTATING = frozenset({
    "bash", "git_branch", "git_commit", "test", "write",
})

# Local tools with a real executor in ``mcp_relay_local``; the others in the
# LOCAL class are refused explicitly rather than forwarded to the hub's disk.
LOCAL_IMPLEMENTED = frozenset({
    "bash", "git_branch", "git_commit", "git_diff", "git_log", "git_status",
    "glob", "grep", "read", "test", "write",
})

ROUTES: dict[str, str] = {
    **{f"graq_{n}": LOCAL for n in _LOCAL_TOOLS},
    **{f"graq_{n}": MIXED for n in _MIXED_TOOLS},
    **{f"graq_{n}": HUB for n in _HUB_TOOLS},
}


class UnknownToolError(ValueError):
    """The tool is not in the routing table; it is refused, never guessed."""


def canonical_name(tool: str) -> str:
    """``kogni_x`` is an alias of ``graq_x``."""
    if tool.startswith("kogni_"):
        return "graq_" + tool[len("kogni_"):]
    return tool


def route_for(tool: str) -> str:
    """Return LOCAL, HUB or MIXED for *tool*; raise ``UnknownToolError``."""
    if not isinstance(tool, str):
        raise UnknownToolError("tool name must be a string")
    try:
        return ROUTES[canonical_name(tool)]
    except KeyError:
        raise UnknownToolError(f"tool {tool!r} is not in the relay routing table (v{ROUTING_VERSION})") from None


def short_name(tool: str) -> str:
    """``graq_write`` -> ``write``."""
    return canonical_name(tool)[len("graq_"):]


def duplicates() -> list[str]:
    """Names listed more than once across the three classes (must be empty)."""
    seen: set[str] = set()
    dup: list[str] = []
    for n in (*_LOCAL_TOOLS, *_MIXED_TOOLS, *_HUB_TOOLS):
        if n in seen:
            dup.append(n)
        seen.add(n)
    return dup
