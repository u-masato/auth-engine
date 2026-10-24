#!/usr/bin/env bash
# MCP Inspector（公式の MCP クライアント）を使って、CIMD の client_id + PKCE + resource の完全フローを
# auth-engine のデモ構成に対して回す。手順と結果は docs/mcp-interop.md。
#
#   .claude/skills/run-demo/scripts/demo.sh start -auto-approve   # AS + mcp-server + cimd-host
#   conformance/mcp-inspector.sh tools/list                        # 認可 → 接続 → tools/list
#   conformance/mcp-inspector.sh tools/call --tool-name whoami     # 保存済みトークンで tools/call
#
# Inspector CLI は TTY がないと対話的 OAuth を始めないので script(1) で疑似 TTY を与え、ブラウザは開かず
# （MCP_AUTO_OPEN_ENABLED=false）認可 URL を標準エラーに出させる。-auto-approve のデモなら、その URL を
# curl で辿るだけで loginapp が demo-user として承認し、Code が Inspector の loopback コールバックに届く。
# 通常起動のデモなら表示された URL をブラウザで開いて承認する。
#
# 環境変数: DEMO_PORT_BASE（demo.sh と同じ。既定 8080）、INSPECTOR_VERSION（既定 2.12.0）、
#           INSPECTOR_STATE_DIR（OAuth 状態と秘密の保存先。既定 examples/standalone/.demo/inspector。
#           開発者の ~/.mcp-inspector には触らない）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT_BASE="${DEMO_PORT_BASE:-8080}"
ISSUER="http://localhost:$PORT_BASE"
MCP_URL="http://localhost:$((PORT_BASE + 10))/mcp"
CLIENT_ID_URL="https://localhost:$((PORT_BASE + 11))/demo-cli.json"
VERSION="${INSPECTOR_VERSION:-2.12.0}"
STATE_DIR="${INSPECTOR_STATE_DIR:-$ROOT/examples/standalone/.demo/inspector}"
mkdir -p "$STATE_DIR"
OUT="$STATE_DIR/last.log"

# 隔離した保存先（docs/cli-smoke-testing.md §6 のとおり 2 つとも指定する）。秘密は OS キーチェーンではなく
# このディレクトリのファイルに置く（デモ用トークンだけなので暗号化しない）。
export MCP_STORAGE_DIR="$STATE_DIR"
export MCP_INSPECTOR_OAUTH_STATE_PATH="$STATE_DIR/oauth.json"
export MCP_INSPECTOR_SECRET_STORE=file
export MCP_AUTO_OPEN_ENABLED=false

METHOD="${1:-tools/list}"; shift || true
script -q /dev/null npx -y "@modelcontextprotocol/inspector@$VERSION" --cli \
  --transport http --server-url "$MCP_URL" \
  --client-metadata-url "$CLIENT_ID_URL" \
  --connect-timeout 20000 --format json --method "$METHOD" "$@" >| "$OUT" 2>&1 &
PID=$!

# 認可 URL が出たら、-auto-approve のデモなら curl で承認まで進める（OSC 8 ハイパーリンクの装飾を剥がす）
extract_url() {
  python3 -c 'import re,sys
s=open(sys.argv[1],"rb").read().decode("utf-8","replace")
m=re.search(r"%s/authorize\?[^\s\x1b\x07]*" % re.escape(sys.argv[2]), s)
u=m.group(0) if m else ""
i=u.find("http://",10)
print(u[:i] if i>0 else u)' "$OUT" "$ISSUER"
}
url=""
for _ in $(seq 1 240); do
  url=$(extract_url 2>/dev/null || true)
  [ -n "$url" ] && break
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.5
done
if [ -n "$url" ]; then
  echo "authorization_url: $url"
  if grep -q 'msg=ready.*auto_approve=true' "$ROOT/examples/standalone/.demo/server.log" 2>/dev/null; then
    jar=$(mktemp)
    curl -sL -m 30 -c "$jar" -b "$jar" -o /dev/null -w 'browser: %{http_code} %{url_effective}\n' "$url"
    rm -f "$jar"
  else
    echo "ブラウザでこの URL を開いて承認してください（Inspector は 15 分待つ）"
  fi
fi
set +e
wait "$PID"; status=$?
set -e
echo "--- inspector output (exit $status)"
tr -d '\r' < "$OUT" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | grep -v '^$' | grep -v 'Please navigate to' | grep -v '^\^D' | tail -20
exit $status
