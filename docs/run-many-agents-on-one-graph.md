# Run many agents on one graph

By default every MCP client starts its own `graq mcp serve` process, and each process loads its own copy of the graph.
With several agents on one machine, that copy is paid for several times. From 0.86.0 you can run **one shared server**
and point every client at it through a very small relay process.

## Which pieces do what

| Piece | Command | What it does |
|---|---|---|
| Shared server | `graq mcp serve --transport http` | Loads the graph once and serves it over HTTP. |
| Relay | `graq mcp relay --url ...` | A stdio MCP process that holds no graph; it forwards each request to the shared server. |
| Per-session gates | built in | Each client session has its own governance gate state; one agent's open gate does not open another's. |
| Workspace roots | `--allowed-roots`, `--workspace-root` | Each session is confined to a directory the server allows. |
| Multi-project hub | `graq mcp serve --projects projects.yaml` | Several separate project graphs in one server (Team / Enterprise). |

## Same machine

Start the server once. `--allowed-roots` is required: it lists the directories a session may use as its workspace.

```bash
graq mcp serve --transport http --port 8765 --allowed-roots /path/to/your/repos
```

It binds to `127.0.0.1` by default. In each project, change the command in `.mcp.json` from `serve` to `relay`:

```json
{ "mcpServers": { "graq": { "command": "graq", "args": ["mcp", "relay", "--url", "http://127.0.0.1:8765"] } } }
```

The relay sends the current directory as the session's workspace root (override with `--workspace-root`). If the shared
server is unreachable the relay returns an explicit error; it never falls back to loading a graph itself.

## Teammates over an SSH tunnel

Keep the server bound to localhost and let each teammate forward the port:

```bash
ssh -N -L 8765:127.0.0.1:8765 you@shared-host
```

Teammates then use the same relay URL (`http://127.0.0.1:8765`) on their own machine. Nothing is exposed beyond
localhost on the server.

## Token and HTTPS (only beyond localhost)

If you bind to anything other than a loopback address, the server refuses to start unless an auth token is set in
`GRAQLE_MCP_HTTP_TOKEN`; the relay reads the same variable and sends it with each request. Put the server behind HTTPS
(for example a reverse proxy) before exposing it beyond localhost, and give the relay an `https://` URL. On loopback,
and through an SSH tunnel, no token or HTTPS is needed.

## What the server can touch

File tools (read, edit, write, git) act on the **server's disk**, inside the allowed roots. A remote teammate should use
the graph tools (context, inspect, reason, impact, lessons, preflight); their own file edits stay on their machine.

## Several projects in one server (Team / Enterprise)

`--projects` serves several separate project graphs from one process. Graphs are never merged: each project has its own
config, graph, caches and cost counters, and a session is bound to one project when it connects.

```yaml
# projects.yaml
idle_seconds: 900          # optional: unload a graph unused for this long
memory_budget_mb: 4096     # optional: drop least-recently-used idle graphs above this (needs psutil)
projects:
  alpha:
    root: /path/to/alpha
  beta:
    root: /path/to/beta
    config: graqle.yaml    # optional, default graqle.yaml
```

```bash
graq mcp serve --transport http --projects projects.yaml
graq mcp relay --url http://127.0.0.1:8765 --project alpha
```

Graphs load lazily on the first tool call for a project. Requests across projects are serialised, because the server
changes its working directory around each call.

Without a Team or Enterprise licence, `--projects` refuses to start and the message names the edition. Run
`graq doctor` to see which edition you have.

## Editions

| | Community (free) | Team / Enterprise |
|---|---|---|
| Shared HTTP server with one graph | yes | yes |
| `graq mcp relay` | yes | yes |
| Per-session gates, workspace roots, token auth | yes | yes |
| `--projects` multi-project hub | no | yes |

## Measured memory

Measured on a 20,000-node fixture (`scripts/cr_infra_02c_measure_rss.py`, output committed in
`scripts/cr_infra_02c_measure_rss.output.txt`):

| Setup | Total resident memory |
|---|---|
| 3 separate stdio servers | 687.0 MB (229.0 MB each) |
| 1 shared server + 3 relays | 492.8 MB (server 259.2 MB; relays about 77.9 MB each) |

These figures are for that fixture only; your numbers depend on your graph.
