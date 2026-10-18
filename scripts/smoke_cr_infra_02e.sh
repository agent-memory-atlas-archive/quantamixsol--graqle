#!/usr/bin/env bash
# CR-INFRA-02e AC8: one shared server, two relays from two git worktrees.
# Run from the SDK checkout: bash scripts/smoke_cr_infra_02e.sh
set -u
SDK="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
BASE="$OUT/work"; mkdir -p "$BASE/main"
cd "$BASE/main" && git init -q && git config user.email s@example.invalid && git config user.name smoke
echo seed > seed.txt && git add seed.txt && git commit -q -m seed
git worktree add -q "$BASE/wt1" -b smoke-1
git worktree add -q "$BASE/wt2" -b smoke-2
cd "$SDK"
PORT=${PORT:-18765}
PYTHONPATH="$SDK" python -m graqle.cli.main mcp serve --transport http --port "$PORT" --allowed-roots "$BASE" >"$OUT/server.log" 2>&1 &
SERVER=$!
for _ in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:$PORT/mcp" && break; sleep 1; done

drive() { # $1 = worktree, $2 = file name
  local root=$1 f=$2
  cd "$root" || exit 1
  {
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"graq_lifecycle","arguments":{"event":"session_start"}}}'
    echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"graq_plan","arguments":{"goal":"smoke","dry_run":true}}}'
    echo "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"graq_write\",\"arguments\":{\"file_path\":\"$f\",\"content\":\"from $f\",\"dry_run\":false}}}"
    echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"graq_bash","arguments":{"command":"git add -A && git commit -q -m smoke && git log --oneline -1 && git rev-parse --abbrev-ref HEAD"}}}'
  } | PYTHONPATH="$SDK" python -m graqle.cli.main mcp relay --url "http://127.0.0.1:$PORT" | tail -1 \
    | python -c "import sys,json; r=json.load(sys.stdin); print(json.loads(r['result']['content'][0]['text']).get('stdout'))"
}
echo "--- relay 1 (cwd=wt1)"; drive "$BASE/wt1" file_one.txt
echo "--- relay 2 (cwd=wt2)"; drive "$BASE/wt2" file_two.txt
echo "--- wt1 tree:"; ls "$BASE/wt1"
echo "--- wt2 tree:"; ls "$BASE/wt2"
echo "--- main tree (must hold only seed.txt):"; ls "$BASE/main"
echo "--- smoke files in the server's own cwd (must be 0):"; ls "$SDK" | grep -c "file_one\|file_two"
kill "$SERVER"
