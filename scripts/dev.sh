# Local test gateway on :7790 with throwaway data (never touches the real install).
# usage: source scripts/dev.sh ; gwstart ; tc call_tool '{"tool":"gemini.voices","arguments":{}}' ; api GET /api/servers
TOOLGATE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
T="${TOOLGATE_DEV_DATA:-${TMPDIR:-/tmp}/toolgate-dev}"
gwstart(){ pkill -f "toolgate serve -data $T" ; sleep 0.5; (cd "$TOOLGATE_SRC" && PATH=$HOME/sdk/go/bin:$PATH go build -o bin/toolgate . ) || return 1; mkdir -p "$T"; ("$TOOLGATE_SRC/bin/toolgate" serve -data "$T" -addr 127.0.0.1:7790 -key-store file >> "$T/log.txt" 2>&1 &); sleep 1.5; TOK=$(grep -o 'agw_[a-f0-9]*' "$T/first-run.txt" | head -1); ADM=$(cat "$T/admin.token"); echo "dev gateway: http://localhost:7790/ui/#token=$ADM"; }
gwstop(){ pkill -f "toolgate serve -data $T"; }
call(){ curl -sS -m 150 http://127.0.0.1:7790/mcp -H "Authorization: Bearer ${2:-$TOK}" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' -d "$1"; echo; }
tc(){ call "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" $3 | python3 -c 'import sys,json; d=json.load(sys.stdin); r=d.get("result",d); print("ERR" if r.get("isError") else "OK"); [print(c.get("text","")[:2500]) for c in r.get("content",[])] if "content" in r else print(d)'; }
api(){ m=$1; p=$2; shift 2; curl -sS -m 90 -X $m "http://127.0.0.1:7790$p" -H "X-Admin-Token: $ADM" -H 'Content-Type: application/json' "$@"; echo; }
