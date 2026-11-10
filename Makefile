GO ?= go
# go.work に列挙したモジュールのディレクトリ
MODULES := . ./adapters/sqlite ./adapters/postgres ./examples/standalone ./tests

# lint ツールのバージョン。@latest にすると新しいチェックの追加で CI が突然落ちるので固定し、上げるときはここを直す
STATICCHECK_VERSION := v0.8.2
GOVULNCHECK_VERSION := v1.9.0

.PHONY: test lint vet fmt-check staticcheck vulncheck deps-check go-directive-check fuzz

test: vet
	@for m in $(MODULES); do (cd $$m && $(GO) test -race ./...) || exit 1; done

vet:
	@for m in $(MODULES); do (cd $$m && $(GO) vet ./...) || exit 1; done

lint: fmt-check go-directive-check staticcheck vulncheck deps-check

# gofmt -l は整形が必要なファイルを列挙するだけで終了コードは 0 なので、出力の有無で判定する
fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "gofmt が必要なファイル:" >&2; echo "$$out" >&2; exit 1; fi

staticcheck:
	@for m in $(MODULES); do (cd $$m && $(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...) || exit 1; done

vulncheck:
	@for m in $(MODULES); do (cd $$m && $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...) || exit 1; done

# コアモジュールが import してよい外部モジュールは go-jose/v4 のみ（ADR-0002, ADR-0007）
deps-check:
	@./scripts/check-core-deps.sh

# go mod tidy で go 指示子が最低バージョン（Go 1.26）から上がっていないか
go-directive-check:
	@./scripts/check-go-directive.sh

# コアの Fuzz テストを 1 ターゲットずつ回す。時間は FUZZTIME で変える（例: make fuzz FUZZTIME=5m）
fuzz:
	@GO=$(GO) ./scripts/fuzz.sh
