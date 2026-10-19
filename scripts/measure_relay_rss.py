"""CR-INFRA-02f AC10: peak RSS of the hybrid relay with local tools active.

Usage:  python scripts/measure_relay_rss.py

Runs a relay session in-process (initialize, a local read, a local glob, a local
grep against this repository) with ``local_tools=True`` and a hub URL that
nobody listens on, then prints the peak resident set size and which heavy
modules were imported. Linux/macOS only (``resource``).
"""

from __future__ import annotations

import io
import json
import resource
import sys
from pathlib import Path

HEAVY = ("torch", "sentence_transformers", "neo4j")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))  # measure THIS checkout, not an installed copy
    from graqle.plugins.mcp_relay import run_relay

    calls = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "graq_read", "arguments": {"file_path": "README.md"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "graq_glob", "arguments": {"pattern": "graqle/plugins/mcp_relay*.py"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "graq_grep", "arguments": {"pattern": "ROUTING_VERSION", "path": "graqle/plugins"}}},
    ]
    out = io.StringIO()
    run_relay(
        "http://127.0.0.1:9", stdin=io.StringIO("".join(json.dumps(m) + "\n" for m in calls)),
        stdout=out, workspace_root=str(root), local_tools=True,
    )
    answered = [json.loads(line) for line in out.getvalue().splitlines()]
    ok = all(not r["result"].get("isError") for r in answered)
    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        peak_kb //= 1024
    print(json.dumps({
        "local_calls_ok": ok,
        "peak_rss_kb": peak_kb,
        "heavy_modules_imported": [m for m in HEAVY if m in sys.modules],
    }))
    return 0 if ok and not any(m in sys.modules for m in HEAVY) else 1


if __name__ == "__main__":
    raise SystemExit(main())
