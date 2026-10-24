#!/usr/bin/env bash
# examples/standalone のデモサーバー（エンジン + Interaction API + デモ Interaction App）を
# バックグラウンドで起動・停止・確認し、cli-client で Authorization Code + PKCE を回す。
#
#   demo.sh start [-auto-approve] [server の追加フラグ...]
#   demo.sh stop | status | logs [N] | reset
#   demo.sh flow [-scope "openid profile"]   # 認可フローを実行（-auto-approve 起動なら全自動）
#   demo.sh flow-wait                        # ブラウザ承認後の結果を表示
#
# 環境変数: DEMO_PORT_BASE（既定 8080。公開=base, Interaction=base+1, login=base+2）
#           DEMO_DIR（既定 examples/standalone/.demo。DB・鍵・ログ・PID をここに置く）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
APP="$ROOT/examples/standalone"
PORT_BASE="${DEMO_PORT_BASE:-8080}"
PUBLIC_PORT=$PORT_BASE
INTERACTION_PORT=$((PORT_BASE + 1))
LOGIN_PORT=$((PORT_BASE + 2))
DEMO_DIR="${DEMO_DIR:-$APP/.demo}"
PID_FILE="$DEMO_DIR/server.pid"
LOG="$DEMO_DIR/server.log"
BIN="$DEMO_DIR/server"
CLI="$DEMO_DIR/cli-client"
FLOW_OUT="$DEMO_DIR/flow.out"
FLOW_PID="$DEMO_DIR/flow.pid"
ISSUER="http://localhost:$PUBLIC_PORT"
LOGIN_URL="http://localhost:$LOGIN_PORT/login"

# GOROOT が別バージョンの SDK を指していると go build が "version does not match" で失敗する
# （この Mac では .zshrc の GOROOT=go1.26.10 と PATH 先頭の go1.26.3 が食い違うことがある）。
# go コマンドは自分の GOROOT を知っているので、食い違うときは環境変数の方を捨てる。
ensure_go() {
  if [ -n "${GOROOT:-}" ] && [ "$(head -n1 "$GOROOT/VERSION" 2>/dev/null)" != "$(go env GOVERSION)" ]; then
    echo "note: GOROOT=$GOROOT と go コマンド ($(go env GOVERSION)) のバージョンが違うため GOROOT を無視する" >&2
    unset GOROOT
  fi
}

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

server_pid() { [ -f "$PID_FILE" ] && cat "$PID_FILE" || true; }
is_running() { local p; p=$(server_pid); [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }

# ポートを LISTEN しているプロセスを「PID コマンド」の形で返す（なければ空）。
port_users() { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $2, $1}' | sort -u || true; }

auto_approve_on() { grep -q 'msg=ready.*auto_approve=true' "$LOG" 2>/dev/null; }

print_summary() {
  echo "issuer:            $ISSUER"
  echo "discovery:         $ISSUER/.well-known/openid-configuration"
  echo "login (demo app):  $LOGIN_URL"
  echo "interaction api:   http://127.0.0.1:$INTERACTION_PORT (loginapp 専用。外部に出さない)"
  echo "auto_approve:      $(auto_approve_on && echo true || echo false)"
  echo "pid:               $(server_pid)"
  echo "log:               $LOG"
  echo "data:              $DEMO_DIR (auth.db, keys.json)"
}

cmd_start() {
  if is_running; then
    echo "already running"; print_summary; return 0
  fi
  rm -f "$PID_FILE"
  local busy=0 p
  for p in "$PUBLIC_PORT" "$INTERACTION_PORT" "$LOGIN_PORT"; do
    local u; u=$(port_users "$p")
    if [ -n "$u" ]; then echo "port $p is in use by: $u"; busy=1; fi
  done
  if [ "$busy" = 1 ]; then
    echo "ポートが使われています。該当プロセスを止めるか、DEMO_PORT_BASE=8090 のように別のポートで起動してください。" >&2
    return 1
  fi
  mkdir -p "$DEMO_DIR"
  ensure_go
  (cd "$APP" && go build -o "$BIN" ./cmd/server)
  nohup "$BIN" \
    -db "$DEMO_DIR/auth.db" -keys "$DEMO_DIR/keys.json" \
    -issuer "$ISSUER" -public-addr ":$PUBLIC_PORT" \
    -interaction-addr "127.0.0.1:$INTERACTION_PORT" \
    -login-addr ":$LOGIN_PORT" -login-url "$LOGIN_URL" \
    "$@" >"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
  local i
  for i in $(seq 1 60); do
    if grep -q 'msg=ready' "$LOG" 2>/dev/null; then
      echo "started"; print_summary; return 0
    fi
    if ! is_running; then
      echo "server exited during startup. log:" >&2; cat "$LOG" >&2; rm -f "$PID_FILE"; return 1
    fi
    sleep 0.5
  done
  echo "timed out waiting for ready. log:" >&2; tail -n 30 "$LOG" >&2; return 1
}

cmd_stop() {
  if [ -f "$FLOW_PID" ]; then kill "$(cat "$FLOW_PID")" 2>/dev/null || true; rm -f "$FLOW_PID"; fi
  if ! is_running; then echo "not running"; rm -f "$PID_FILE"; return 0; fi
  local p; p=$(server_pid)
  kill "$p"
  local i
  for i in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$p" 2>/dev/null && kill -9 "$p"
  rm -f "$PID_FILE"
  echo "stopped (pid $p)"
}

cmd_status() {
  if is_running; then
    echo "running"; print_summary
    if curl -fsS -m 3 "$ISSUER/.well-known/openid-configuration" >/dev/null; then
      echo "discovery:         OK"
    else
      echo "discovery:         NOT reachable"
    fi
    return 0
  fi
  echo "not running"
  local p
  for p in "$PUBLIC_PORT" "$INTERACTION_PORT" "$LOGIN_PORT"; do
    local u; u=$(port_users "$p"); [ -n "$u" ] && echo "port $p is in use by: $u (このスクリプトが起動したものではない)"
  done
  return 0
}

cmd_logs() { tail -n "${1:-50}" "$LOG"; }

cmd_reset() {
  cmd_stop
  rm -f "$DEMO_DIR"/auth.db "$DEMO_DIR"/auth.db-wal "$DEMO_DIR"/auth.db-shm "$DEMO_DIR"/keys.json "$FLOW_OUT"
  echo "removed auth.db and keys.json under ${DEMO_DIR}（次の start で再生成。demo-cli も再登録される）"
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
    url=$(grep -m1 -o 'http://[^[:space:]]*' "$FLOW_OUT" 2>/dev/null || true)
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
  -h|--help|help|"") usage ;;
  *) echo "unknown command: $1" >&2; usage >&2; exit 2 ;;
esac
