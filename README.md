# auth-engine

Go 製のヘッドレスな OAuth 2.0 / OpenID Connect 認可サーバー「Protocol Engine」。

ログイン・同意 UI とユーザー管理は外部アプリケーション（Interaction App）の責務とし、本体はプロトコル処理（`/authorize`, `/token`, `/userinfo`, `/jwks`, Discovery）と Authorization Transaction・Grant・トークンの状態管理に専念する。
ロジックがわかりやすく、他者の参考実装になる品質を目指す。

## 状態

設計フェーズ完了、M1（SQLite だけで Authorization Code + PKCE を完走）の実装中。
まだ利用できる状態ではない。

## 設計

- [設計ドキュメント索引](docs/README.md) — ADR と技術スタック案に対する判断の要約
- [準拠仕様一覧](rfcs.md) — P0〜P3 の段階分け
- [ロードマップ](docs/roadmap.md) — M1〜M4 とタスク順序

## 意図した制約

- PKCE（S256）を使わない Authorization Code Grant は受け付けない。Implicit / Password Grant は提供しない。
- Client の設定は Client Profile（Web / Native・CLI / M2M）で固定し、RFC の個別設定は開放しない。
- 永続化は Store Port 経由。コアモジュールは DB ドライバーを参照しない。

## 開発

```bash
make test   # go vet + go test -race
make lint   # staticcheck + govulncheck + コア依存の検査
```

Go 1.26 以上。

## ライセンス

Apache License 2.0
