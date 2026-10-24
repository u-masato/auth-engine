# auth-engine

Go 製のヘッドレスな OAuth 2.0 / OpenID Connect 認可サーバー「Protocol Engine」。

ログイン・同意 UI とユーザー管理は外部アプリケーション（Interaction App）の責務とし、本体はプロトコル処理（`/authorize`, `/token`, `/userinfo`, `/jwks`, Discovery）と Authorization Transaction・Grant・トークンの状態管理に専念する。
ロジックがわかりやすく、他者の参考実装になる品質を目指す。

## 状態

M1 完了（2026-10-24）: Go ライブラリとして、SQLite だけで Authorization Code + PKCE を完走できる。
OIDC（ID Token、Discovery、UserInfo）、Refresh Token、Revocation、Introspection、PostgreSQL は M2 で追加する。API は安定していない。

## 試す

```bash
# エンジン + Interaction API + デモのログイン画面を 1 プロセスで起動
cd examples/standalone && go run ./cmd/server -db ./auth.db

# 別の端末で、Native クライアントとしてフローを実行（URL をブラウザで開く）
cd examples/standalone && go run ./cmd/cli-client
```

詳細は [examples/standalone/README.md](examples/standalone/README.md)。

## モジュール構成

| モジュール | 内容 | 外部依存 |
| --- | --- | --- |
| `github.com/muno/auth-engine` | コア。`client` / `authorization` / `grant` / `token` / `httpapi` / `storage` と、配線の入口 `Engine` | なし（JOSE ライブラリは M2 で追加） |
| `.../adapters/sqlite` | SQLite Store Adapter | modernc.org/sqlite, goose |
| `.../examples/standalone` | デモサーバー、デモ Interaction App、サンプルクライアント | — |
| `.../tests` | E2E テスト | — |

Interaction App（ログイン・同意画面）を実装するには [docs/interaction-api.md](docs/interaction-api.md) を読む。

## 設計

- [設計ドキュメント索引](docs/README.md) — ADR と技術スタック案に対する判断の要約
- [Interaction App との契約](docs/adr/0003-interaction-contract.md) — ヘッドレス構成の核心
- [Interaction API 仕様](docs/interaction-api.md) — Interaction App 実装者向け
- [準拠仕様一覧](rfcs.md) — P0〜P3 の段階分け
- [ロードマップ](docs/roadmap.md) — M1〜M4 とタスク順序、M1 の実施結果

## 意図した制約

- PKCE（S256）を使わない Authorization Code Grant は受け付けない。Implicit / Password Grant は提供しない。
- Client の設定は Client Profile（Web / Native・CLI / M2M）で固定し、RFC の個別設定は開放しない。
- 永続化は Store Port 経由。コアモジュールは DB ドライバーを参照しない。

## 開発

```bash
make test   # 全モジュールで go vet + go test -race
make lint   # staticcheck + govulncheck + コア依存の検査
```

Go 1.26 以上。モジュールは `go.work` で束ねている。

## ライセンス

Apache License 2.0
