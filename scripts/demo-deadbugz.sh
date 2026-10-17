#!/bin/bash
# Reproduces the "Deadbugz" MCP supply-chain pattern in an isolated HOME and shows kova catching it:
# the server is benign at install (tools/list clean, static scan passes) and changes its tool
# definitions after two tool calls. Run: make demo
set -e
cd "$(dirname "$0")/.."
[ -x bin/kova ] || go build -o bin/kova ./cmd/kova
[ -x bin/kova-drift-demo ] || go build -o bin/kova-drift-demo ./cmd/kova-drift-demo
KOVA=$(pwd)/bin/kova; DEMO=$(pwd)/bin/kova-drift-demo
export HOME=$(mktemp -d) KOVA_HOME=$HOME/.kova KOVA_BIN=$KOVA
mkdir -p "$HOME/.claude"
cat > "$HOME/.claude.json" <<JSON
{"mcpServers":{"markdown-helper":{"command":"$DEMO","args":["--drift-after","2"]}}}
JSON
echo "── 1. Install-time review: static scan of the server's tools (passes)"
$KOVA scan --mcp -- "$DEMO" --drift-after 2 && echo
echo "── 2. kova init pins the tool definitions and wraps the server with the proxy"
$KOVA init --no-hooks --quiet && $KOVA wrap --all --quiet && echo "   pinned + wrapped" && echo
echo "── 3. A session: initialize, list tools, call the tool twice, list tools again"
CMD=$(python3 -c "import json,shlex;d=json.load(open('$HOME/.claude.json'));s=d['mcpServers']['markdown-helper'];print(shlex.join([s['command']]+s['args']))")
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"format_markdown","arguments":{"text":"hello"}}}' \
 '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"format_markdown","arguments":{"text":"world"}}}' \
 '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' | eval "$CMD" >/dev/null
echo
echo "── 4. What kova recorded"
$KOVA events --limit 3
echo
echo "Re-run with enforcement to see the drifted tools/list replaced by an error:  kova wrap --all --enforce"
rm -rf "$HOME"
