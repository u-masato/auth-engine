#!/usr/bin/env sh
# コアモジュールの外部依存が許可リストに収まっているかを検査する。
# ADR-0002 / ADR-0007: コアが import してよい外部モジュールは go-jose/v4 のみ。
set -eu

cd "$(dirname "$0")/.."

allowed='^github.com/go-jose/go-jose/v4$'

# 標準ライブラリとコア自身を除いた、推移的に依存する全モジュール
deps=$($(command -v go) list -deps -f '{{if and .Module (not .Standard)}}{{.Module.Path}}{{end}}' ./... \
	| sort -u | grep -v '^github.com/muno/auth-engine$' || true)

bad=$(printf '%s\n' "$deps" | grep -v -E "$allowed" | grep -v '^$' || true)
if [ -n "$bad" ]; then
	echo "core module depends on modules outside the allow list:" >&2
	printf '  %s\n' $bad >&2
	exit 1
fi
echo "core deps OK"
