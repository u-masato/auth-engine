# examples/standalone

エンジン、Interaction API、デモ Interaction App を 1 プロセスで起動する例と、Native / CLI Profile のサンプルクライアント。

## 起動

```bash
go run ./cmd/server -db ./auth.db
```

| リスナー | 既定アドレス | 内容 |
| --- | --- | --- |
| 公開エンドポイント | `:8080` | `/authorize`, `/token`, `/.well-known/oauth-authorization-server` |
| Interaction API | `127.0.0.1:8081` | Interaction App 専用。外部に公開しない |
| デモ Interaction App | `:8082` | `/login`。ユーザー名を入れて承認するだけの画面（パスワード検証なし） |

初回起動時に署名鍵セット（RS256 と ES256）を生成して `-keys`（既定 `keys.json`、0600）に保存し、Native クライアント `demo-cli`（redirect URI は `http://127.0.0.1/callback`、ポートは任意）を登録する。
`-auto-approve` を付けると画面を出さず `demo-user` として全 scope を承認する（テスト・Conformance Suite 用）。

## クライアントでフローを実行

```bash
go run ./cmd/cli-client -issuer http://localhost:8080
```

表示された URL をブラウザで開き、承認すると Access Token が表示される。

## 構成

- `loginapp/` — Interaction API を呼ぶ Interaction App の最小実装。E2E テストからも使う
- `oauthclient/` — Authorization Code + PKCE、loopback redirect、RFC 8414 Discovery、`iss` 検証を行う最小クライアント
- `cmd/server/` — 上記を配線して起動する
- `cmd/cli-client/` — `oauthclient` を使う CLI

`http://localhost` で動かすため `InsecureCookies: true` にしている。本番構成では https にして既定（Secure Cookie）のまま使うこと。
