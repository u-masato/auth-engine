#!/usr/bin/env bash
# examples/standalone のデモサーバー（エンジン + Interaction API + デモ Interaction App + 開発者コンソール）を
# バックグラウンドで起動・停止・確認し、cli-client で Authorization Code + PKCE を回す。
#
#   demo.sh start [-auto-approve] [server の追加フラグ...]
#   demo.sh stop | status | logs [N] | reset
#   demo.sh flow [-scope "openid profile"]   # 認可フローを実行（-auto-approve 起動なら全自動）
#   demo.sh flow-wait                        # ブラウザ承認後の結果を表示
#   demo.sh mcp-flow                         # MCP クライアント（CIMD の client_id）として MCP サーバーまで呼ぶ
#
# start は認可サーバーに加えて、デモ MCP サーバー（cmd/mcp-server、base+10）と CIMD 文書の配信
# （cmd/cimd-host、base+11、自己署名 TLS）も起動する。認可サーバーには -resources（MCP サーバーの登録）、
# -cimd-allow-loopback、-cimd-ca（cimd-host の証明書）を渡す。
#
# 環境変数: DEMO_PORT_BASE（既定 8080。公開=base, Interaction=base+1, login=base+2, console=base+3,
#                           MCP サーバー=base+10, CIMD 文書=base+11）
#           DEMO_DIR（既定 examples/standalone/.demo。DB・鍵・ログ・PID をここに置く）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
APP="$ROOT/examples/standalone"
PORT_BASE="${DEMO_PORT_BASE:-8080}"
PUBLIC_PORT=$PORT_BASE
INTERACTION_PORT=$((PORT_BASE + 1))
LOGIN_PORT=$((PORT_BASE + 2))
CONSOLE_PORT=$((PORT_BASE + 3))
MCP_PORT=$((PORT_BASE + 10))
CIMD_PORT=$((PORT_BASE + 11))
DEMO_DIR="${DEMO_DIR:-$APP/.demo}"
PID_FILE="$DEMO_DIR/server.pid"
LOG="$DEMO_DIR/server.log"
BIN="$DEMO_DIR/server"
CLI="$DEMO_DIR/cli-client"
MCP_BIN="$DEMO_DIR/mcp-server"
MCP_PID_FILE="$DEMO_DIR/mcp-server.pid"
MCP_LOG="$DEMO_DIR/mcp-server.log"
CIMD_BIN="$DEMO_DIR/cimd-host"
CIMD_PID_FILE="$DEMO_DIR/cimd-host.pid"
CIMD_LOG="$DEMO_DIR/cimd-host.log"
CIMD_CERT="$DEMO_DIR/cimd-cert.pem"
CIMD_KEY="$DEMO_DIR/cimd-key.pem"
RESOURCES_JSON="$DEMO_DIR/resources.json"
MCP_URL="http://localhost:$MCP_PORT/mcp"
CIMD_URL="https://localhost:$CIMD_PORT"
CLIENT_ID_URL="$CIMD_URL/demo-cli.json"
FLOW_OUT="$DEMO_DIR/flow.out"
FLOW_PID="$DEMO_DIR/flow.pid"
ISSUER="http://localhost:$PUBLIC_PORT"
LOGIN_URL="http://localhost:$LOGIN_PORT/login"
# コンソールは認証なしで Store に書き込むので loopback にだけ bind する。localhost ではなく 127.0.0.1 に
# するのは、Cookie がポートを区別せず :8080 / :8082 と混ざるのを避けるためと、Native の loopback
# redirect（RFC 8252 §7.3）にそのまま使えるようにするため。
CONSOLE_URL="http://127.0.0.1:$CONSOLE_PORT"

# GOROOT が別バージョンの SDK を指していると go build が "version does not match" で失敗する
# （この Mac では .zshrc の GOROOT=go1.26.10 と PATH 先頭の go1.26.3 が食い違うことがある）。
# go コマンドは自分の GOROOT を知っているので、食い違うときは環境変数の方を捨てる。
ensure_go() {
  if [ -n "${GOROOT:-}" ] && [ "$(head -n1 "$GOROOT/VERSION" 2>/dev/null)" != "$(go env GOVERSION)" ]; then
    echo "note: GOROOT=$GOROOT と go コマンド ($(go env GOVERSION)) のバージョンが違うため GOROOT を無視する" >&2
    unset GOROOT
  fi
}

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

server_pid() { [ -f "$PID_FILE" ] && cat "$PID_FILE" || true; }
is_running() { local p; p=$(server_pid); [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
pid_of() { [ -f "$1" ] && cat "$1" || true; }
pid_running() { local p; p=$(pid_of "$1"); [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }

# ポートを LISTEN しているプロセスを「PID コマンド」の形で返す（なければ空）。
port_users() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $2, $1}' | sort -u || true; }

auto_approve_on() { grep -q 'msg=ready.*auto_approve=true' "$LOG" 2>/dev/null; }

print_summary() {
  echo "issuer:            $ISSUER"
  echo "discovery:         $ISSUER/.well-known/openid-configuration"
  echo "console:           $CONSOLE_URL  (Client 登録とフローの手動確認はここから)"
  echo "login (demo app):  $LOGIN_URL"
  echo "interaction api:   http://127.0.0.1:$INTERACTION_PORT (loginapp 専用。外部に出さない)"
  echo "auto_approve:      $(auto_approve_on && echo true || echo false)"
  echo "pid:               $(server_pid)"
  echo "log:               $LOG"
  echo "data:              $DEMO_DIR (auth.db, keys.json, resources.json, cimd-cert.pem)"
  echo "mcp server:        $MCP_URL (pid $(pid_of "$MCP_PID_FILE"), log $MCP_LOG; metadata: http://localhost:$MCP_PORT/.well-known/oauth-protected-resource/mcp)"
  echo "cimd client_id:    $CLIENT_ID_URL (pid $(pid_of "$CIMD_PID_FILE"), log $CIMD_LOG)"
}

# wait_ready は PID ファイルのプロセスがログに msg=ready を書くまで待つ。
wait_ready() { # name pidfile log
  local i
  for i in $(seq 1 60); do
    grep -q 'msg=ready' "$3" 2>/dev/null && return 0
    if ! pid_running "$2"; then echo "$1 exited during startup. log:" >&2; cat "$3" >&2; rm -f "$2"; return 1; fi
    sleep 0.5
  done
  echo "timed out waiting for $1. log:" >&2; tail -n 30 "$3" >&2; return 1
}

stop_pidfile() { # pidfile
  pid_running "$1" || { rm -f "$1"; return 0; }
  local p; p=$(cat "$1")
  kill "$p"
  local i
  for i in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$p" 2>/dev/null && kill -9 "$p"
  rm -f "$1"
  echo "stopped $(basename "$1" .pid) (pid $p)"
}

cmd_start() {
  if is_running; then
    echo "already running"; print_summary; return 0
  fi
  rm -f "$PID_FILE"
  local busy=0 p
  for p in "$PUBLIC_PORT" "$INTERACTION_PORT" "$LOGIN_PORT" "$CONSOLE_PORT" "$MCP_PORT" "$CIMD_PORT"; do
    local u; u=$(port_users "$p")
    if [ -n "$u" ]; then echo "port $p is in use by: $u"; busy=1; fi
  done
  if [ "$busy" = 1 ]; then
    echo "ポートが使われています。該当プロセスを止めるか、DEMO_PORT_BASE=8090 のように別のポートで起動してください。" >&2
    return 1
  fi
  mkdir -p "$DEMO_DIR"
  ensure_go
  (cd "$APP" && go build -o "$BIN" ./cmd/server && go build -o "$MCP_BIN" ./cmd/mcp-server && go build -o "$CIMD_BIN" ./cmd/cimd-host)

  # 1. CIMD 文書の配信（自己署名証明書を初回に生成する。認可サーバーがその証明書を信頼する必要があるので先に起動）
  nohup "$CIMD_BIN" -addr "127.0.0.1:$CIMD_PORT" -url "$CIMD_URL" -cert "$CIMD_CERT" -key "$CIMD_KEY" >"$CIMD_LOG" 2>&1 &
  echo $! >"$CIMD_PID_FILE"
  wait_ready cimd-host "$CIMD_PID_FILE" "$CIMD_LOG" || return 1

  # 2. 認可サーバー。MCP サーバーを resource として登録し（JWT Access Token）、CIMD は loopback の cimd-host から取る
  printf '[\n  {\n    "uri": "%s",\n    "name": "Demo MCP Server",\n    "access_token_format": "jwt",\n    "scopes": ["mcp:read", "mcp:write"]\n  }\n]\n' "$MCP_URL" >| "$RESOURCES_JSON"
  nohup "$BIN" \
    -db "$DEMO_DIR/auth.db" -keys "$DEMO_DIR/keys.json" \
    -issuer "$ISSUER" -public-addr ":$PUBLIC_PORT" \
    -interaction-addr "127.0.0.1:$INTERACTION_PORT" \
    -login-addr ":$LOGIN_PORT" -login-url "$LOGIN_URL" \
    -console-addr "127.0.0.1:$CONSOLE_PORT" -console-url "$CONSOLE_URL" \
    -resources "$RESOURCES_JSON" -cimd-allow-loopback -cimd-ca "$CIMD_CERT" \
    "$@" >"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
  wait_ready server "$PID_FILE" "$LOG" || { stop_pidfile "$CIMD_PID_FILE"; return 1; }

  # 3. デモ MCP サーバー（JWT をローカル検証。認可サーバーのメタデータと JWKS は最初の要求時に取る）
  nohup "$MCP_BIN" -addr ":$MCP_PORT" -resource "$MCP_URL" -issuer "$ISSUER" >"$MCP_LOG" 2>&1 &
  echo $! >"$MCP_PID_FILE"
  wait_ready mcp-server "$MCP_PID_FILE" "$MCP_LOG" || { stop_pidfile "$PID_FILE"; stop_pidfile "$CIMD_PID_FILE"; return 1; }

  echo "started"; print_summary
}

cmd_stop() {
  if [ -f "$FLOW_PID" ]; then kill "$(cat "$FLOW_PID")" 2>/dev/null || true; rm -f "$FLOW_PID"; fi
  stop_pidfile "$MCP_PID_FILE"
  stop_pidfile "$CIMD_PID_FILE"
  if ! is_running; then echo "not running"; rm -f "$PID_FILE"; return 0; fi
  stop_pidfile "$PID_FILE"
}

cmd_status() {
  if is_running; then
    echo "running"; print_summary
    if curl -fsS -m 3 "$ISSUER/.well-known/openid-configuration" >/dev/null; then
      echo "discovery:         OK"
    else
      echo "discovery:         NOT reachable"
    fi
    pid_running "$MCP_PID_FILE" && echo "mcp server:        running" || echo "mcp server:        NOT running"
    pid_running "$CIMD_PID_FILE" && echo "cimd-host:         running" || echo "cimd-host:         NOT running"
    return 0
  fi
  echo "not running"
  local p
  for p in "$PUBLIC_PORT" "$INTERACTION_PORT" "$LOGIN_PORT" "$CONSOLE_PORT" "$MCP_PORT" "$CIMD_PORT"; do
    local u; u=$(port_users "$p"); [ -n "$u" ] && echo "port $p is in use by: $u (このスクリプトが起動したものではない)"
  done
  return 0
}

cmd_logs() { tail -n "${1:-50}" "$LOG"; }

cmd_reset() {
  cmd_stop
  rm -f "$DEMO_DIR"/auth.db "$DEMO_DIR"/auth.db-wal "$DEMO_DIR"/auth.db-shm "$DEMO_DIR"/keys.json "$CIMD_CERT" "$CIMD_KEY" "$FLOW_OUT"
  echo "removed auth.db, keys.json and the cimd-host certificate under ${DEMO_DIR}（次の start で再生成。demo-cli も再登録される）"
}

# cli-client を起動し、認可 URL を得る。-auto-approve 起動のサーバーなら curl で承認まで進めて結果を出す。
cmd_flow() {
  if ! is_running; then echo "server is not running. run: $0 start" >&2; return 1; fi
  ensure_go
  (cd "$APP" && go build -o "$CLI" ./cmd/cli-client)
  rm -f "$FLOW_OUT"
  nohup "$CLI" -issuer "$ISSUER" "$@" >"$FLOW_OUT" 2>&1 &
  echo $! >"$FLOW_PID"
  local url="" i
  for i in $(seq 1 40); do
    url=$(grep -m1 -o "$ISSUER/authorize?[^[:space:]]*" "$FLOW_OUT" 2>/dev/null || true)
    [ -n "$url" ] && break
    if ! kill -0 "$(cat "$FLOW_PID")" 2>/dev/null; then echo "cli-client exited:" >&2; cat "$FLOW_OUT" >&2; return 1; fi
    sleep 0.25
  done
  [ -z "$url" ] && { echo "no authorization URL from cli-client:" >&2; cat "$FLOW_OUT" >&2; return 1; }
  if auto_approve_on; then
    # -auto-approve では loginapp が画面を出さず demo-user として承認し、callback へリダイレクトする。
    # Cookie（セッション）を引き継いでリダイレクトを辿れば、cli-client の loopback に Code が届く。
    local jar; jar=$(mktemp)
    curl -sL -m 30 -c "$jar" -b "$jar" -o /dev/null "$url" || true
    rm -f "$jar"
    cmd_flow_wait
    return
  fi
  echo "authorization_url: $url"
  echo
  echo "ブラウザでこの URL を開き、ユーザー名を入れて承認してください（パスワードはない）。"
  echo "承認後に結果を見る: $0 flow-wait"
}

# MCP クライアントとしてのフロー: CIMD の client_id（cimd-host の文書）で、MCP サーバーの 401 → RFC 9728 メタデータ →
# 認可サーバーの発見 → resource 付き認可 → Access Token で /mcp を呼ぶ、までを cli-client が行う。
cmd_mcp_flow() {
  pid_running "$MCP_PID_FILE" && pid_running "$CIMD_PID_FILE" || { echo "mcp-server / cimd-host is not running. run: $0 start" >&2; return 1; }
  cmd_flow -client-id-url "$CLIENT_ID_URL" -mcp "$MCP_URL" "$@"
}

cmd_flow_wait() {
  [ -f "$FLOW_PID" ] || { echo "no flow in progress. run: $0 flow" >&2; return 1; }
  local p; p=$(cat "$FLOW_PID")
  local i
  for i in $(seq 1 1200); do kill -0 "$p" 2>/dev/null || break; sleep 0.5; done
  if kill -0 "$p" 2>/dev/null; then echo "cli-client is still waiting for the browser callback" >&2; return 1; fi
  rm -f "$FLOW_PID"
  cat "$FLOW_OUT"
  grep -q '^access_token:' "$FLOW_OUT"
}

case "${1:-}" in
  start) shift; cmd_start "$@" ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  logs) shift; cmd_logs "$@" ;;
  reset) cmd_reset ;;
  flow) shift; cmd_flow "$@" ;;
  flow-wait) cmd_flow_wait ;;
  mcp-flow) shift; cmd_mcp_flow "$@" ;;
  -h|--help|help|"") usage ;;
  *) echo "unknown command: $1" >&2; usage >&2; exit 2 ;;
esac
