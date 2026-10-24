# examples/standalone

エンジン、Interaction API、デモ Interaction App、開発者コンソールを 1 プロセスで起動する例と、Native / CLI Profile のサンプルクライアント。

## 起動

```bash
go run ./cmd/server -db ./auth.db
```

| リスナー | 既定アドレス | 内容 |
| --- | --- | --- |
| 公開エンドポイント | `:8080` | `/authorize`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/jwks`, `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` |
| Interaction API | `127.0.0.1:8081` | Interaction App 専用。外部に公開しない |
| デモ Interaction App | `:8082` | `/login`。ユーザー名を入れて承認するだけの画面（パスワード検証なし） |
| 開発者コンソール | `127.0.0.1:8083` | Client の登録とフローの手動確認（下記）。`-console-addr ""` で無効 |

初回起動時に署名鍵セット（RS256 と ES256）を生成して `-keys`（既定 `keys.json`、0600）に保存し、Native クライアント `demo-cli`（redirect URI は `http://127.0.0.1/callback`、ポートは任意）を登録する。
`-auto-approve` を付けると画面を出さず `demo-user` として全 scope を承認する（テスト・Conformance Suite 用）。
`-clients clients.json` で Web / Native / Machine の Client を起動時に静的登録できる（形式は [conformance/clients.json](../../conformance/clients.json)）。
`-allow-insecure-issuer` は Docker 内から到達させるために localhost 以外の http Issuer を許す開発用の緩和。

デモの Interaction App は Cookie セッション（署名なし）でログイン状態を持ち、`prompt=none`（セッションがなければ `login_required`）、`prompt=login`（再認証）、`max_age`（超過時は再認証）を解釈する。

## 開発者コンソールで手動確認する

`http://127.0.0.1:8083` を開くと、ブラウザだけで次を確認できる。

1. **Client の登録** — Profile（web / native / machine）、redirect URI、scope を入れて Store に登録する。Web / Machine の Client Secret は登録直後の画面に出る。既定の redirect URI はコンソール自身の `http://127.0.0.1:8083/callback`
2. **認可要求** — 送るパラメータ（PKCE の `code_challenge`、`nonce`、任意の `prompt` / `login_hint` / `max_age`）を表で見てから認可エンドポイントへ進む
3. **コールバック以降** — `state` と `iss`（RFC 9207）の検証、Code の交換、ID Token の署名（公開 JWKS）と `iss` / `aud` / `exp` / `nonce` の検証を段階ごとに表示する
4. **トークン操作** — UserInfo、Refresh（Rotation の確認）、Revoke、Introspect をボタンで実行する。Machine Client は client_credentials でトークンを取る

各段階に対応する RFC / OIDC の節番号を出す。ログイン画面は Cookie セッションを持つので、2 回目以降に画面を見たいときは `prompt=login` で開始する。

コンソールは認証なしで Store に書き込む開発用の道具なので、loopback にだけ bind する。フローの状態とコンソールで登録した Client の Secret はメモリにだけ持ち、再起動で消える（Client 自体は DB に残る）。Store に更新・一覧の操作はないため、登録内容を変えるときは別の client_id で登録するか DB を作り直す。

## クライアントでフローを実行

```bash
go run ./cmd/cli-client -issuer http://localhost:8080
```

表示された URL をブラウザで開き、承認すると Access Token・Refresh Token・ID Token と UserInfo の内容が表示される。

## 構成

- `loginapp/` — Interaction API を呼ぶ Interaction App の最小実装。E2E テストからも使う
- `oauthclient/` — Authorization Code + PKCE、Client Credentials、loopback redirect、RFC 8414 Discovery、`iss` 検証、Refresh、Revocation、Introspection、UserInfo を行う最小クライアント
- `console/` — 開発者コンソール。Client の登録（Store に直接書く運用者の操作）と、`oauthclient` を使う RP としてのフロー実行・ID Token 検証
- `cmd/server/` — 上記を配線して起動する
- `cmd/cli-client/` — `oauthclient` を使う CLI

`http://localhost` で動かすため `InsecureCookies: true` にしている。本番構成では https にして既定（Secure Cookie）のまま使うこと。
