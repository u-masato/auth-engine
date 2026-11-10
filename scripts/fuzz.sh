#!/usr/bin/env sh
# コアモジュールの Fuzz テストを 1 つずつ FUZZTIME（既定 30s）ずつ回す。
# go test -fuzz は 1 回に 1 パッケージの 1 ターゲットしか受け付けないので、func Fuzz を列挙して順に実行する。
# seed だけなら通常の go test でも実行される。ここで見つかった入力は各パッケージの testdata/fuzz/ に残るので、
# 原因を直したうえで回帰テストとしてコミットする。
set -eu

cd "$(dirname "$0")/.."

fuzztime=${FUZZTIME:-30s}
go=${GO:-go}

git ls-files '*_test.go' | grep -v '^adapters/\|^examples/\|^tests/' | while read -r f; do
	pkg="./$(dirname "$f")"
	for target in $(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\)(.*/\1/p' "$f"); do
		echo "== $pkg $target ($fuzztime)"
		"$go" test -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" "$pkg"
	done
done
