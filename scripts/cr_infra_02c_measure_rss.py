"""CR-INFRA-02 PR-c AC5 - RSS of the relay, and one shared server + 3 relays vs 3 stdio servers.

Linux only (reads VmRSS from /proc). Run as its own interpreter, from the repo root:

    python scripts/cr_infra_02c_measure_rss.py [NODES]

Builds a fixture graph (NODES nodes, default 20000) in a temp dir, then:
  A. 3 x ``graq mcp serve`` (stdio), each made to load the graph via ``graq_inspect``;
  B. 1 x ``graq mcp serve --transport http`` + 3 x ``graq mcp relay``, each relay
     driving ``initialize`` + ``graq_inspect`` through to the shared server.
Prints one ``key=value`` line per measurement (paste the output verbatim as evidence).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLI = "from graqle.cli.main import app; app()"
INSPECT = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
           "params": {"name": "graq_inspect", "arguments": {"stats": True}}}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def rss_mb(pid: int) -> float:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    raise RuntimeError(f"no VmRSS for {pid}")


def build_fixture(root: Path, nodes: int) -> None:
    import networkx as nx

    from graqle.core.graph import Graqle

    g = nx.Graph()
    for i in range(nodes):
        g.add_node(f"n{i}", label=f"node {i}", type="Entity", description=f"fixture node {i} " * 8)
    for i in range(1, nodes):
        g.add_edge(f"n{i}", f"n{i // 2}", relationship="RELATED_TO")
    Graqle.from_networkx(g).to_json(str(root / "graqle.json"))


def spawn(args: list[str], root: Path) -> subprocess.Popen:
    env = {**os.environ, "GRAQLE_SERVE_CWD": str(root), "PYTHONPATH": os.getcwd()}
    return subprocess.Popen([sys.executable, "-c", CLI, *args], cwd=root, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def rpc(proc: subprocess.Popen, msg: dict) -> dict:
    assert proc.stdin and proc.stdout
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def drive(proc: subprocess.Popen) -> None:
    rpc(proc, INIT)
    reply = rpc(proc, INSPECT)
    assert "result" in reply and not reply["result"].get("isError"), reply


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stop(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.terminate()
    for p in procs:
        p.wait(timeout=15)


def main() -> None:
    nodes = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        build_fixture(root, nodes)
        print(f"fixture_nodes={nodes}")

        stdio = [spawn(["mcp", "serve"], root) for _ in range(3)]
        for p in stdio:
            drive(p)
        sizes = [rss_mb(p.pid) for p in stdio]
        print("stdio_server_rss_mb=" + ",".join(f"{s:.1f}" for s in sizes))
        print(f"stdio_3_servers_total_rss_mb={sum(sizes):.1f}")
        stop(stdio)

        port = free_port()
        server = spawn(["mcp", "serve", "--transport", "http", "--port", str(port)], root)
        url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        relays = [spawn(["mcp", "relay", "--url", url], root) for _ in range(3)]
        for p in relays:
            drive(p)
        relay_sizes = [rss_mb(p.pid) for p in relays]
        server_rss = rss_mb(server.pid)
        print("relay_rss_mb=" + ",".join(f"{s:.1f}" for s in relay_sizes))
        print(f"shared_server_rss_mb={server_rss:.1f}")
        print(f"shared_server_plus_3_relays_total_rss_mb={server_rss + sum(relay_sizes):.1f}")
        stop(relays + [server])


if __name__ == "__main__":
    main()
