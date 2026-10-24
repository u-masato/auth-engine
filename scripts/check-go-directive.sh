#!/usr/bin/env sh
# go.work と各 go.mod の go 指示子が最低バージョン（Go 1.26）のままかを検査する。
# go mod tidy は手元の Go に合わせて go 指示子を上げることがあり、上がると利用者の最低要件まで変わる。
set -eu

cd "$(dirname "$0")/.."

min='1.26'

bad=0
for f in go.work $(git ls-files '*go.mod'); do
	v=$(awk '$1 == "go" { print $2; exit }' "$f")
	case "$v" in
	"$min" | "$min.0") ;;
	*)
		echo "$f: go directive is '$v', want $min or $min.0" >&2
		bad=1
		;;
	esac
done
[ "$bad" -eq 0 ] || exit 1
echo "go directives OK"
