# MCP 相互運用（MCP Inspector）

- 対象: [MCP Inspector](https://github.com/modelcontextprotocol/inspector) v2.12.0（公式の MCP クライアント兼デバッガ。`@modelcontextprotocol/inspector`、CLI モード）
- 状態: **実行済み（2026-10-25）**。CIMD の `client_id` + PKCE + `resource` の完全フロー（Resource Server の発見 → 認可サーバーの発見 → 認可 → トークン → MCP 接続 → `tools/list` → `tools/call`）が通った。結果は本文末尾。
- 基準: [MCP Authorization Specification（2026-07-28）](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)、[CIMD draft-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)、RFC 8707、RFC 9728

Conformance Suite（[docs/conformance.md](conformance.md)）と同じく手動実行で、CI には含めない。CI で回す結合テストは [`tests/mcp_test.go`](../tests/mcp_test.go)（`oauthclient` を MCP クライアントに見立てた E2E）。

## 構成

```
MCP Inspector CLI（npx、MCP クライアント）                 auth-engine のデモ（examples/standalone）
┌────────────────────────────────────────┐              ┌──────────────────────────────────────────┐
│ client_id = https://localhost:8091/demo-cli.json │ ──▶ POST /mcp（トークンなし → 401）          │ cmd/mcp-server   http://localhost:8090/mcp
│ redirect  = http://127.0.0.1:6276/oauth/callback │ ──▶ GET /.well-known/oauth-protected-resource/mcp │  （resourceserver、JWT をローカル検証）
│                                        │ ──▶ GET /.well-known/oauth-authorization-server   │ cmd/server       http://localhost:8080
│                                        │ ──▶ GET /authorize（PKCE、resource）→ loginapp    │  （Engine + httpapi + loginapp）
│                                        │ ◀── 302 …/oauth/callback?code=…&iss=…           │
│                                        │ ──▶ POST /token（code、code_verifier、resource）   │
│                                        │ ──▶ POST /mcp（Bearer JWT）initialize / tools/*  │
└────────────────────────────────────────┘              │ cmd/cimd-host    https://localhost:8091（自己署名） │
                                                        │  ◀── 認可サーバーが CIMD 文書を取得             │
                                                        └──────────────────────────────────────────┘
```

- CIMD の `client_id` は https でなければならない（CIMD §3）ので、ローカルでは `cmd/cimd-host` が自己署名証明書で文書を配り、認可サーバーは `-cimd-allow-loopback -cimd-ca` でそれを信頼する（本番では使わない開発用の緩和。[examples/standalone/README.md](../examples/standalone/README.md)）。
- Inspector の CLI / TUI は OAuth のコールバックを `http://127.0.0.1:6276/oauth/callback`、Web は `http://localhost:6274/oauth/callback` で受ける。デモの CIMD 文書（`demo.sh` の既定）は両方を `redirect_uris` に含む。loopback IP はポートを無視して照合し、`http://localhost` はポートまで完全一致（ADR-0008 §4）。
- Inspector の CIMD はインストール単位の設定（`client.json` の `cimd.clientMetadataUrl`、または CLI の `--client-metadata-url`）で、サーバーごとの OAuth 設定には書けない。認可サーバーが `client_id_metadata_document_supported: true` を広告していると、Inspector は `client_id` にその URL を使う（Dynamic Client Registration は試みない。本エンジンは `registration_endpoint` を出さない）。
- `cmd/mcp-server` は Inspector が接続できるだけの最小の MCP（Streamable HTTP、`initialize` / `ping` / `tools/list` / `tools/call`、`whoami` ツール）を実装する。認可の確認が目的で、MCP の網羅は目指さない。

## 手順

```bash
# 1. デモを自動承認で起動（AS :8080、mcp-server :8090、cimd-host :8091。demo-user として全承認）
.claude/skills/run-demo/scripts/demo.sh start -auto-approve

# 2. Inspector CLI で認可 → 接続 → tools/list。認可 URL は curl で辿られ、Code が Inspector のコールバックに届く
conformance/mcp-inspector.sh tools/list

# 3. 保存済みトークン（.demo/inspector/）を再利用して tools/call
conformance/mcp-inspector.sh tools/call --tool-name whoami

# 片付け
.claude/skills/run-demo/scripts/demo.sh stop
```

`conformance/mcp-inspector.sh` は次を行う（手で再現するときの要点）。

- `npx -y @modelcontextprotocol/inspector@2.12.0 --cli --transport http --server-url http://localhost:8090/mcp --client-metadata-url https://localhost:8091/demo-cli.json --method tools/list --format json`
- Inspector CLI は TTY がないと対話的 OAuth を始めないので `script -q /dev/null` で疑似 TTY を与え、`MCP_AUTO_OPEN_ENABLED=false` でブラウザを開かせず、標準エラーに出る認可 URL を使う。通常起動（自動承認なし）のデモなら、その URL をブラウザで開いて承認する。同意画面には `client_id` のホスト名（`localhost:8091`）と redirect 先（`127.0.0.1:6276`、「このコンピュータ上のアプリケーション」の注意書き）が出る。
- OAuth の状態と秘密は `MCP_STORAGE_DIR` / `MCP_INSPECTOR_OAUTH_STATE_PATH` / `MCP_INSPECTOR_SECRET_STORE=file` で `examples/standalone/.demo/inspector/` に隔離し、開発者の `~/.mcp-inspector` と OS キーチェーンに触れない。

Web UI（`npx @modelcontextprotocol/inspector`、`http://localhost:6274`）でも同じ流れになるはずだが、今回は実行していない。使うときは Client settings の CIMD に `https://localhost:8091/demo-cli.json` を入れ、サーバー URL に `http://localhost:8090/mcp` を指定する。Connection Info の Client registration が `Client ID Metadata (CIMD)`、Client ID がメタデータ URL と一致していれば CIMD で通っている。

## 結果（2026-10-25、Inspector 2.12.0、`@modelcontextprotocol/core` 2.3.1）

Inspector が送った認可要求（認可サーバーのログと Inspector の出力から）:

```
GET /authorize?response_type=code
  &client_id=https%3A%2F%2Flocalhost%3A8091%2Fdemo-cli.json
  &code_challenge=…&code_challenge_method=S256
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A6276%2Foauth%2Fcallback
  &state=…
  &scope=mcp%3Aread+mcp%3Awrite            ← Protected Resource Metadata の scopes_supported
  &resource=http%3A%2F%2Flocalhost%3A8090%2Fmcp
```

| 段階 | 結果 |
| --- | --- |
| Resource Server の発見 | トークンなしの `POST /mcp` に 401 と `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`。Inspector は `resource_metadata` の URL からメタデータを取り、`authorization_servers` の `http://localhost:8080` へ進んだ |
| 認可サーバーの発見 | `/.well-known/oauth-authorization-server` を取得。`client_id_metadata_document_supported: true` を見て CIMD の `client_id` を使った（`registration_endpoint` はないので DCR は起きない） |
| CIMD 文書の取得 | 認可サーバーが `https://localhost:8091/demo-cli.json` を取得・検証（ログ `event=cimd.resolved cache_ttl=1m0s`）。`redirect_uri` は文書の `http://127.0.0.1/oauth/callback` とポートを無視して一致 |
| 認可と同意 | `-auto-approve` の loginapp が `demo-user` として `mcp:read mcp:write` を承認。Code を `http://127.0.0.1:6276/oauth/callback?code=…&iss=http%3A%2F%2Flocalhost%3A8080&state=…` へ返した（RFC 9207 の `iss` 付き） |
| トークン | `grant_type=authorization_code`、PKCE 検証、`resource` を引き継いだ JWT Access Token（`aud: ["http://localhost:8090/mcp"]`、`scope: "mcp:read mcp:write"`）と Refresh Token を発行（ログ `event=token.issued`）。Inspector は「Authorization complete.」と表示 |
| MCP 接続 | Bearer の JWT を `resourceserver.JWTVerifier` が JWKS でローカル検証。`initialize` → `tools/list` が成功し、`whoami` ツールが返った |
| `tools/call` | 2 回目の実行は保存済みトークンを再利用し（認可なし）、`whoami` が `subject=demo-user`、`client_id=https://localhost:8091/demo-cli.json`、`scope=[mcp:read mcp:write]`、`aud=[http://localhost:8090/mcp]` を返した |

Inspector の出力（抜粋）:

```
Authorization complete.
{"result":{"tools":[{"name":"whoami","title":"Who am I","description":"Returns the subject, client_id, scope and audience of the access token that authorized this call.", …}]}}
{"result":{"content":[{"type":"text","text":"{\"aud\":[\"http://localhost:8090/mcp\"],\"client_id\":\"https://localhost:8091/demo-cli.json\",…,\"scope\":[\"mcp:read\",\"mcp:write\"],\"subject\":\"demo-user\"}"}], …}}
```

## 確認できたこと・できていないこと

- 確認できた: MCP 仕様「Authorization Server Location」（401 → `resource_metadata` → `authorization_servers`）、「Scope Selection Strategy」（`scopes_supported` を要求）、CIMD（URL の `client_id`、`token_endpoint_auth_method=none`、loopback redirect のポート無視）、RFC 8707（認可要求とトークン要求の `resource`、Access Token の `aud`）、RFC 9728 のメタデータ、PKCE S256、RFC 9207 の `iss`、JWT Access Token（RFC 9068）のローカル検証、保存済みトークンの再利用。
- 未実施: Inspector の Web UI（CLI と同じ `@modelcontextprotocol/core` のクライアントを使うので同じ結果になるはずだが、同意画面をブラウザで通していない）。`insufficient_scope`（403）からの step-up 再認可を Inspector で起こす操作（`/mcp/admin` は MCP のエンドポイントではないので Inspector からは叩けない。E2E `TestMCPStepUpAuthorization` で確認）。Opaque + Introspection の MCP サーバーに対する Inspector の接続（E2E `TestMCPClientJWTAndOpaque` で確認。Inspector からはトークン形式の違いは見えない）。Refresh Token による更新（Inspector は期限切れ前に再実行したため）。
- 本エンジン側で対応していないもの: Dynamic Client Registration（ADR-0008 §8。Inspector は CIMD を広告している AS には DCR を試みないので問題にならない）、CIMD Client の `private_key_jwt`（M4）。
- 注意点: Inspector の CIMD 設定はインストール単位で、`--client-metadata-url` で上書きできる。デモの `cimd-host` が配る文書の `redirect_uris` に Inspector のコールバックが含まれていないと `redirect_uri` の照合で 400 になる（`DEMO_CIMD_REDIRECT_URIS` で変えられる）。認可サーバーの CIMD キャッシュは下限 1 分なので、文書を変えた直後は古い内容で照合される。
