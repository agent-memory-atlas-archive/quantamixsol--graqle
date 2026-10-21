"""Hub side of the hybrid relay (CR-INFRA-02f): per-mutation gate + graph snapshot.

``POST <base>/relay/gate`` answers, for ONE session and ONE intended local
mutation, whether this session's gates allow it right now. It is evaluated on
the hub on every call and never cached (CG-01 session started, CG-02 plan
active, read-only, CG-03 edit enforcement, CG-15 KG files, G4 protected paths,
and the content scan of the hub's own write handler).

``POST <base>/relay/snapshot`` returns a bounded, read-only, versioned
description of the graph. The relay compares versions before and after the
compute step of a MIXED tool and aborts on any change.

Anything unexpected here denies: the relay treats a missing or malformed
answer as a refusal too.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from graqle.plugins.mcp_relay_routing import canonical_name
from graqle.plugins.mcp_session_state import SessionState, bind_session

logger = logging.getLogger(__name__)

_CODE_EXTS = (".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java")
_SCRATCH_PREFIXES = (".tmp_", "scripts/", "tests/")
SNAPSHOT_MAX_BYTES = 65536


def _deny(reason: str) -> dict[str, Any]:
    return {"allow": False, "reason": reason}


def evaluate_gate(
    server: Any,
    state: SessionState,
    tool: str,
    arguments: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    """Return ``{"allow": bool, "reason": str}`` for *tool* on *state*'s session."""
    try:
        return _evaluate(server, state, tool, arguments, root)
    except Exception as exc:  # fail closed: any surprise is a refusal
        logger.warning("relay gate error: %s", type(exc).__name__)
        return _deny(f"gate evaluation failed ({type(exc).__name__}); refused")


def _evaluate(server: Any, state: SessionState, tool: str, arguments: dict[str, Any], root: Path) -> dict[str, Any]:
    from graqle.plugins.mcp_dev_server import _WRITE_TOOLS

    name = canonical_name(tool)
    if name not in _WRITE_TOOLS:
        return _deny(f"{name} is not a known mutating tool; refused")
    if getattr(server, "read_only", False):
        return _deny("the server is read-only")

    governance = getattr(getattr(server, "_config", None), "governance", None)
    with bind_session(state):
        if governance is not None:
            if getattr(governance, "session_gate_enabled", False) and not (
                state.session_started or state.cg01_bypass
            ):
                return _deny("CG-01_SESSION_GATE: call graq_lifecycle(event='session_start') first")
            if getattr(governance, "plan_mandatory", False) and not (state.plan_active or state.cg02_bypass):
                return _deny("CG-02_PLAN_GATE: call graq_plan(goal='...') before modifying files")
        elif not getattr(server, "_config", None):
            return _deny("server governance configuration is unavailable; refused")

        if name == "graq_write":
            return _write_checks(server, state, governance, arguments, root)
    return {"allow": True, "reason": "ok"}


def _write_checks(server: Any, state: SessionState, governance: Any, arguments: dict[str, Any], root: Path) -> dict[str, Any]:
    from graqle.governance.kg_write_gate import check_kg_block, check_protected_path

    target = str(arguments.get("file_path") or arguments.get("path") or "")
    if not target:
        return _deny("file_path is required")
    allowed, envelope = check_kg_block(target)
    if not allowed:
        return _deny(f"CG-15: {json.dumps(envelope)[:300]}")
    allowed, envelope = check_protected_path(
        target, config=getattr(server, "_config", None), approved_by=arguments.get("approved_by")
    )
    if not allowed:
        return _deny(f"G4_PROTECTED_PATH: {json.dumps(envelope)[:300]}")

    if getattr(governance, "edit_enforcement", False) and not state.cg03_bypass:
        norm = target.replace("\\", "/")
        is_new = not Path(target).exists()
        scratch = any(norm.startswith(p) or f"/{p}" in norm for p in _SCRATCH_PREFIXES)
        if norm.endswith(_CODE_EXTS) and not is_new and not scratch and not arguments.get("force_overwrite"):
            return _deny("CG-03_EDIT_GATE: use graq_edit for existing code files")
    return {"allow": True, "reason": "ok"}


async def content_scan(server: Any, state: SessionState, arguments: dict[str, Any], root: Path) -> dict[str, Any]:
    """Run the hub's own write handler as a dry run, so its content scan applies.

    The probe path is inside the session root on the hub; nothing is written.
    """
    probe = root / ".graqle" / "relay-gate-probe.txt"
    with bind_session(state):
        raw = await server._handle_write({
            "file_path": str(probe), "content": arguments.get("content", ""), "dry_run": True,
        })
    try:
        reply = json.loads(raw)
    except (TypeError, ValueError):
        return _deny("content scan returned a non-JSON answer; refused")
    if isinstance(reply, dict) and "error" in reply:
        return _deny(f"{reply.get('error')}: {str(reply.get('message', ''))[:200]}")
    return {"allow": True, "reason": "ok"}


def graph_snapshot(server: Any) -> dict[str, Any]:
    """Bounded read-only description of the graph with a version stamp."""
    graph = getattr(server, "_graph", None)
    nodes = getattr(graph, "nodes", None)
    try:
        node_count = len(nodes) if nodes is not None else 0
    except TypeError:
        node_count = 0
    mtime = float(getattr(server, "_graph_mtime", 0.0) or 0.0)
    version = hashlib.sha256(f"{mtime!r}:{node_count}".encode()).hexdigest()[:16]
    return {"version": version, "node_count": node_count, "graph_loaded": graph is not None}
