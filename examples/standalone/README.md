# examples/standalone

エンジン、Interaction API、デモ Interaction App、開発者コンソールを 1 プロセスで起動する例と、Native / MCP Profile のサンプルクライアント、デモ MCP サーバー（Resource Server）、CIMD 文書の配信サーバー。

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
`-resources resources.json` で Resource Server（RFC 8707 の resource indicator）を静的登録する（形式は [resources.json](resources.json)。`uri` `name` `access_token_format`（`opaque` | `jwt`）`access_token_alg` `scopes`）。
CIMD（URL 形式の `client_id` を Client ID Metadata Document で解決する。MCP クライアントの事前登録なし接続）は既定で有効（`-cimd=false` で無効）。文書をローカルの `cmd/cimd-host` から取るときは `-cimd-allow-loopback` と `-cimd-ca cimd-cert.pem` を付ける。

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

## MCP クライアントとして MCP サーバーにアクセスする（M3）

MCP クライアント（事前登録なし、CIMD の `client_id`）が MCP サーバー（Resource Server）向けの Access Token を得て `/mcp` を呼ぶまでを、4 つのプロセスで動かす。CIMD の `client_id` は https でなければならない（CIMD §3）ので、文書はローカルでも TLS で配る。

```bash
# 1. CIMD 文書の配信（初回に自己署名証明書 cimd-cert.pem / cimd-key.pem を生成。client_id は https://localhost:8444/demo-cli.json）
go run ./cmd/cimd-host

# 2. 認可サーバー。MCP サーバーを resource として登録し、loopback の文書サーバーとその証明書を信頼する
go run ./cmd/server -db ./auth.db -resources ./resources.json -cimd-allow-loopback -cimd-ca ./cimd-cert.pem

# 3. デモ MCP サーバー（http://localhost:8090/mcp。JWT Access Token をローカル検証）
go run ./cmd/mcp-server -issuer http://localhost:8080

# 4. MCP クライアント。MCP サーバーの 401 → RFC 9728 メタデータ → 認可サーバーの発見 → resource 付き認可 → /mcp 呼び出し
go run ./cmd/cli-client -client-id-url https://localhost:8444/demo-cli.json -mcp http://localhost:8090/mcp
```

`cli-client` は `-mcp` の URL にトークンなしで要求し、`WWW-Authenticate` の `resource_metadata` から Protected Resource Metadata（RFC 9728）を取って `authorization_servers` と `resource`、必要な `scope` を決める（MCP 仕様「Authorization Server Location」「Scope Selection Strategy」）。`-issuer` `-resource` `-scope` を明示すればそれが優先される。承認後、Access Token を Bearer にして `/mcp` を呼び、ステータスと本文を表示する。

同意画面（loginapp）は MCP Client では `client_id` のホスト名と redirect URI のホスト名を名前と並べて出し、redirect URI が localhost / loopback なら「このコンピュータ上のアプリケーションに戻る」注意書きを添える（MCP 仕様 CIMD Security の MUST / SHOULD。[Interaction API 仕様](../../docs/interaction-api.md)「`profile` が `mcp` のとき」）。

`cmd/mcp-server` は `resourceserver` パッケージの使用例。`GET /.well-known/oauth-protected-resource/mcp` でメタデータを返し、`/mcp` は `mcp:read`、`/mcp/admin` は `mcp:write` を要求する（scope 不足は 403 `insufficient_scope`）。`/mcp` は MCP クライアント（MCP Inspector、公式 SDK）が接続してツールを呼べるだけの最小の MCP（Streamable HTTP の `initialize` / `ping` / `tools/list` / `tools/call`。`whoami` ツールが検証済みの主体を返す）を話す。SSE やセッションは実装しない。公式クライアントとの確認手順は [docs/mcp-interop.md](../../docs/mcp-interop.md)。`-introspect -client-id ... -client-secret ...` で Introspection（RFC 7662）による検証に切り替えられる（そのときは Machine Profile の Client を `-clients` で登録し、resource は `opaque` でよい）。

`.claude/skills/run-demo/scripts/demo.sh start` はこの 3 サーバーをまとめて起動し、`demo.sh mcp-flow` が 4 を実行する。

## 構成

- `loginapp/` — Interaction API を呼ぶ Interaction App の最小実装。E2E テストからも使う。MCP Client ではホスト名表示と localhost の注意書きを出す
- `oauthclient/` — Authorization Code + PKCE、Client Credentials、loopback redirect、RFC 8414 Discovery、`iss` 検証、Refresh、Revocation、Introspection、UserInfo、`resource`（RFC 8707）、Resource Server の発見（RFC 9728 の `WWW-Authenticate` と Protected Resource Metadata）を行う最小クライアント
- `console/` — 開発者コンソール。Client の登録（Store に直接書く運用者の操作）と、`oauthclient` を使う RP としてのフロー実行・ID Token 検証
- `cmd/server/` — 上記を配線して起動する。`-resources` と CIMD の設定もここ
- `cmd/cli-client/` — `oauthclient` を使う CLI。`-client-id-url` と `-mcp` で MCP クライアントになる
- `cmd/mcp-server/` — `resourceserver` を組み込んだデモ MCP サーバー（Resource Server）。`mcp.go` が最小の MCP プロトコル
- `cmd/cimd-host/` — CIMD 文書を自己署名 TLS で配るローカル開発用サーバー
- `resources.json` — `-resources` の例（デモ MCP サーバーを JWT Access Token で登録）

`http://localhost` で動かすため `InsecureCookies: true` にしている。本番構成では https にして既定（Secure Cookie）のまま使うこと。
