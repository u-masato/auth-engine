#!/usr/bin/env sh
# コアモジュールの外部依存が許可リストに収まっているかを検査する。
# ADR-0002 / ADR-0007: コアが import してよい外部モジュールは go-jose/v4 のみ。
set -eu

cd "$(dirname "$0")/.."

allowed='^github.com/go-jose/go-jose/v4$'

# 標準ライブラリとコア自身を除いた、推移的に依存する全モジュール
deps=$($(command -v go) list -deps -f '{{if and .Module (not .Standard)}}{{.Module.Path}}{{end}}' ./... \
	| sort -u | grep -v '^github.com/u-masato/auth-engine$' || true)

bad=$(printf '%s\n' "$deps" | grep -v -E "$allowed" | grep -v '^$' || true)
if [ -n "$bad" ]; then
	echo "core module depends on modules outside the allow list:" >&2
	printf '  %s\n' $bad >&2
	exit 1
fi
# resourceserver は Resource Server 側で動くので、認可サーバー側のパッケージ（ルートの Engine、httpapi）に依存しない（ADR-0008 §7）
rsdeps=$($(command -v go) list -deps ./resourceserver | grep -E '^github.com/u-masato/auth-engine(/httpapi|/authorization|/token|/oidc|/grant|/client|/cimd|/storage.*)?$' || true)
if [ -n "$rsdeps" ]; then
	echo "resourceserver must not depend on authorization server packages:" >&2
	printf '  %s\n' $rsdeps >&2
	exit 1
fi
echo "core deps OK"
