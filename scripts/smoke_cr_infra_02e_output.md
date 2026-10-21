# CR-INFRA-02e AC8: live smoke

Command: `bash scripts/smoke_cr_infra_02e.sh` (one shared `graq mcp serve --transport http --allowed-roots <base>`,
two `graq mcp relay` processes started from two git worktrees of one repo; each creates and commits a file).

Output (builder server, 2026-10-17):

```
--- relay 1 (cwd=wt1)
7d8340e smoke
smoke-1

--- relay 2 (cwd=wt2)
513d60a smoke
smoke-2

--- wt1 tree:
file_one.txt
seed.txt
--- wt2 tree:
file_two.txt
seed.txt
--- main tree (must hold only seed.txt):
seed.txt
--- smoke files in the server's own cwd (must be 0):
0
```

Protocol: the relay sends its workspace root (default: its cwd; `--workspace-root` overrides) in the
`X-Graqle-Workspace-Root` header (percent-encoded) on every request. The server binds it once at `initialize`.
