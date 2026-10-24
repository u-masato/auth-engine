GO ?= go
# go.work に列挙したモジュールのディレクトリ
MODULES := . ./adapters/sqlite ./examples/standalone

.PHONY: test lint vet staticcheck vulncheck deps-check

test: vet
	@for m in $(MODULES); do (cd $$m && $(GO) test -race ./...) || exit 1; done

vet:
	@for m in $(MODULES); do (cd $$m && $(GO) vet ./...) || exit 1; done

lint: staticcheck vulncheck deps-check

staticcheck:
	@for m in $(MODULES); do (cd $$m && $(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./...) || exit 1; done

vulncheck:
	@for m in $(MODULES); do (cd $$m && $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...) || exit 1; done

# コアモジュールが import してよい外部モジュールは go-jose/v4 のみ（ADR-0002, ADR-0007）
deps-check:
	@./scripts/check-core-deps.sh
