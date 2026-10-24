#!/usr/bin/env sh
# OpenID Foundation Conformance Suite（Basic OP）をローカルで回す手順をスクリプトにしたもの。
# 前提: Docker（compose v2）、Python 3、git。Java / Maven は不要（公開イメージを使う）。
# 詳細と結果は docs/conformance.md。
#
#   ./conformance/run.sh                       # suite を取得・起動し、テストプランを実行
#   OP_PORT=8090 ./conformance/run.sh          # auth-engine を 8090 で起動している場合
#   RERUN=1:2,1:35 ./conformance/run.sh        # 一部のモジュールだけ再実行（番号は --list で確認）
#
# 別の端末で auth-engine を起動しておくこと（OP_PORT を変えるなら -issuer / -public-addr /
# -interaction-addr / -login-addr / -login-url も合わせる）:
#   cd examples/standalone && go run ./cmd/server \
#     -issuer http://host.docker.internal:8080 -allow-insecure-issuer \
#     -login-url http://host.docker.internal:8082/login \
#     -auto-approve -clients ../../conformance/clients.json -db ./conformance.db -keys ./conformance-keys.json
set -eu

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
SUITE_DIR="${SUITE_DIR:-../conformance-suite}"
SUITE_TAG="${SUITE_TAG:-release-v5.3.3}"
OP_PORT="${OP_PORT:-8080}"
PLAN="${PLAN:-oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]}"
WORK="${WORK:-$ROOT/conformance/.work}"
mkdir -p "$WORK/export"

# 1. Suite のリポジトリ（scripts/run-test-plan.py と compose 定義のため）
if [ ! -d "$SUITE_DIR" ]; then
  git clone --depth 1 --branch "$SUITE_TAG" https://gitlab.com/openid/conformance-suite.git "$SUITE_DIR"
fi
SUITE_DIR="$(cd "$SUITE_DIR" && pwd)"

# 2. Python 依存（httpx, pyparsing）は venv に閉じ込める
if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" -q install -r "$SUITE_DIR/scripts/requirements.txt"
fi

# 3. Suite を公開イメージで起動（https://localhost.emobix.co.uk:8443、devmode のためトークン不要）
(cd "$SUITE_DIR" && IMAGE_TAG="$SUITE_TAG" docker compose -f docker-compose-prebuilt.yml up -d)
echo "waiting for the suite at https://localhost.emobix.co.uk:8443 ..."
i=0
until curl -ks -m 5 https://localhost.emobix.co.uk:8443/api/server >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "suite did not start" >&2; exit 1; }
  sleep 2
done

# 4. 設定の Issuer ポートを差し替えて実行。結果の zip は $WORK/export に出る
CONFIG="$WORK/basic-op.json"
sed "s/host.docker.internal:8080/host.docker.internal:${OP_PORT}/g" "$ROOT/conformance/basic-op.json" > "$CONFIG"
set -- --verbose --export-dir "$WORK/export" \
  --expected-failures-file "$ROOT/conformance/expected-failures.json" \
  --expected-skips-file "$ROOT/conformance/expected-skips.json"
[ -n "${RERUN:-}" ] && set -- "$@" --rerun "$RERUN"
cd "$SUITE_DIR"
exec "$WORK/venv/bin/python" scripts/run-test-plan.py "$@" "$PLAN" "$CONFIG"
