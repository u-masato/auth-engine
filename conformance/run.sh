#!/usr/bin/env sh
# OpenID Foundation Conformance Suite（Basic OP）をローカルで回す手順をスクリプトにしたもの。
# 前提: Docker、Java 17+、Maven、Python 3（requests）。詳細は docs/conformance.md。
#
#   ./conformance/run.sh            # suite を clone・ビルドして起動し、テストプランを実行
#   SUITE_DIR=../conformance-suite ./conformance/run.sh
set -eu

cd "$(dirname "$0")/.."
SUITE_DIR="${SUITE_DIR:-../conformance-suite}"
PLAN="${PLAN:-oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]}"
CONFIG="$(pwd)/conformance/basic-op.json"

if [ ! -d "$SUITE_DIR" ]; then
  git clone --depth 1 https://gitlab.com/openid/conformance-suite.git "$SUITE_DIR"
fi
cd "$SUITE_DIR"
if [ ! -f target/fapi-test-suite.jar ]; then
  mvn -q clean package -DskipTests
fi
docker compose up -d
echo "waiting for the suite at https://localhost.emobix.co.uk:8443 ..."
for _ in $(seq 1 60); do
  if curl -ks https://localhost.emobix.co.uk:8443/api/server >/dev/null 2>&1; then break; fi
  sleep 2
done

# 別の端末で auth-engine を起動しておくこと:
#   cd examples/standalone && go run ./cmd/server \
#     -issuer http://host.docker.internal:8080 -allow-insecure-issuer \
#     -login-url http://host.docker.internal:8082/login \
#     -auto-approve -clients ../../conformance/clients.json -db ./conformance.db
python3 scripts/run-test-plan.py --expected-failures-file "$OLDPWD/conformance/expected-failures.json" \
  "$PLAN" "$CONFIG"
