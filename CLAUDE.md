# auth-engine

Go 製のヘッドレスな OAuth 2.0 / OpenID Connect 認可サーバー「Protocol Engine」。ログイン・同意 UI とユーザー管理は外部の Interaction App の責務で、本体はプロトコル処理とトークン・Grant の状態管理だけを担う。品質目標は「他者の参考実装になるわかりやすさ」。性能や機能網羅より、仕様との対応が読めることを優先する。

## まず読むもの

- [docs/README.md](docs/README.md) — 設計判断の索引。**設計を変えるときは必ず ADR を追記・修正する**
- [docs/adr/0003-interaction-contract.md](docs/adr/0003-interaction-contract.md) — ヘッドレス契約（最重要）
- [docs/adr/0005-storage-port.md](docs/adr/0005-storage-port.md) / [0007-package-layout.md](docs/adr/0007-package-layout.md) — Store の契約と依存の向き
- [docs/roadmap.md](docs/roadmap.md) — マイルストーンとタスク順序。作業はここの番号に沿って進める
- [docs/interaction-api.md](docs/interaction-api.md) — Interaction App 向け公開仕様。HTTP の形を変えたらここも直す
- [docs/embedding.md](docs/embedding.md) — 組み込む人向けの手順。`Config` や公開 API を変えたら、ここと各パッケージの `example_test.go` も直す

## モジュール構成（go.work で束ねる）

| モジュール | 役割 | 外部依存 |
| --- | --- | --- |
| `.`（`github.com/muno/auth-engine`） | コア。`client` `authorization` `grant` `token` `oidc` `keys` `httpapi` `storage` と、配線の入口 `Engine` | go-jose/v4 のみ |
| `adapters/sqlite` | SQLite Store Adapter（modernc.org/sqlite、goose ライブラリ） | — |
| `adapters/postgres` | PostgreSQL Store Adapter（pgx/v5、goose）。契約テストは Testcontainers（Docker がなければ Skip、`AUTH_ENGINE_POSTGRES_DSN` で既存 DB も可） | — |
| `examples/standalone` | デモサーバー、デモ Interaction App（`loginapp`）、サンプルクライアント（`oauthclient`）、開発者コンソール（`console`。Client 登録とフローの手動確認、`127.0.0.1:8083`） | `console` の RP 側 ID Token 検証に go-jose |
| `tests` | SQLite + httptest + loginapp の E2E（RP 側の ID Token 検証に go-jose） | — |

コアのテストから Adapter は import できない（依存が循環する）。Adapter を使うテストは `tests/` に置く。

## コマンド

```bash
make vet test   # 全モジュールで go vet + go test -race
make lint       # gofmt + go 指示子 + staticcheck + govulncheck + コア依存検査（scripts/check-*.sh）
go test -race ./authorization/            # 1 パッケージ
(cd adapters/sqlite && go test -race -count=1 ./...)   # Adapter の契約テスト（ファイル DB）
(cd adapters/postgres && go test -race -count=1 ./...) # PostgreSQL の契約テスト（Docker が必要）
(cd examples/standalone && go run ./cmd/server -db ./auth.db)   # デモ起動（別端末で go run ./cmd/cli-client）
```

- staticcheck / govulncheck はローカルのバイナリではなく、Makefile が `go run` で固定バージョン（`STATICCHECK_VERSION` `GOVULNCHECK_VERSION`）を使う。上げるときは Makefile を直す。
- 並行テスト（Code 同時消費など）は不安定さを疑ったら `-count=3` で回す。
- `go mod tidy` が各 `go.mod` の `go` 指示子を上げることがある。最低バージョンは Go 1.26 なので、`make go-directive-check`（CI でも実行）が検出する。

## 守るべき不変条件（変更には ADR の修正が必要）

- コアが import する外部モジュールは go-jose/v4 だけ。DB ドライバーや Web フレームワークは入れない。JOSE の利用は `keys` に閉じる。
- Store インターフェースは**使う側の文脈パッケージ**で定義し、ルート `authengine.Store` で合成する。`storage` はセンチネルエラーだけの葉パッケージ。
- Store の各メソッドは単体で原子的。Port に `BeginTx` を置かない。競合は `ConsumeAuthorizationCode` `RotateRefreshToken` `IssueTokens` `RevokeGrant` のような意図を表す 1 メソッドで解く。全 Adapter は `storage/storagetest` を通す。
- 全 Port メソッドの第一引数は `context.Context`。`ctx` に値を載せて挙動を変えない。
- Client Profile（Web / Native / Machine）で grant_type・PKCE・認証方式・redirect 照合を固定する。個別フラグの開放や Custom Profile は作らない。PKCE なし、`plain`、Implicit、Password Grant は実装しない。
- 秘密値（Code、トークン、Resume Token、Client Secret）は 256 bit 乱数で、保存は SHA-256 ハッシュのみ。比較は定数時間（`internal/rand`）。
- 状態遷移は fail-closed。Resume は CAS で `consumed` にしてから Code を作る。Code 交換は先に消費し、検証失敗でも戻さない。
- Code 再利用の検知で失効させるのは Token Family（Grant ではない）。

## コーディング規約

- パッケージはレイヤーではなく文脈で切り、entity・値オブジェクト・`Service`（ユースケース）を同居させる。ファイルは種類別ではなく概念別（`transaction.go` `begin.go`）。1 ユースケース 1 ファイル。
- 永続化対象は公開フィールドの構造体。構築はコンストラクタ、変更は遷移メソッド。Adapter 以外でフィールドに直接代入しない。
- エラーは各パッケージのセンチネル（`storage.ErrNotFound` など）を `errors.Is` で判別する。プロトコルエラーは `authorization.Error` / `token.Error`、内部障害は通常の `error` で返し HTTP 層が 500 にする。
- コメントは日本語。判断には対応する RFC / OIDC の節番号を書く（`// RFC 6749 §4.1.2.1`）。各パッケージの `doc.go` に対応仕様を列挙する。
- `storage/memory` を使うテストは外部テストパッケージ（`package xxx_test`）にする。内部テストにすると import が循環する。
- HTTP 層は薄く保つ。パラメータの取り出し、Cookie、ステータスへの写像、JSON だけ。プロトコルの判断は Service に書く。
- 文脈をまたぐ Store 操作は、実行する側の文脈のインターフェースに置く（`ConsumeAuthorizationCode` は `token.Store`）。

## 作業の進め方

- roadmap のタスク 1 件につき 1 コミット。メッセージは `feat(token): M2タスク4 ...` のように `type(scope): マイルストーンとタスク番号 要約`、本文に何を・なぜを箇条書き。
- コミット前に `make vet test` と staticcheck、コア依存検査を通す。
- 設計から外れる判断をしたら、該当 ADR を修正し、roadmap の「実施結果」に差分を記録する。
- 文書はすべて日本語。識別子と RFC 用語は原文のまま。
- M1 の API は安定していない。後方互換を気にせず正しい形に直してよいが、docs/interaction-api.md の契約を変えるときは明記する。
