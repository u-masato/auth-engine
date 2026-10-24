# ロードマップと M1 の実装順序

- 状態: 採用（2026-10-24 合意）。**M1 は 2026-10-24 に完了**
- 日付: 2026-10-24

準拠仕様の段階（P0〜P3）は [rfcs.md](../rfcs.md) に従う。ここでは P0 を 2 つのマイルストーンに分け、M1 のタスク順序を決める。

## マイルストーン

| MS | 到達点 | 含むもの |
| --- | --- | --- |
| **M1** | Go ライブラリとして、SQLite だけで Authorization Code + PKCE を完走 | Web / Native Profile、Txn と Interaction API（ADR-0003）、Code 発行・交換、Opaque Access Token、SQLite Adapter、E2E テスト、最小の Discovery（RFC 8414） |
| **M2** | OIDC 対応と運用に必要なトークンライフサイクル | ID Token、`/jwks`、`/userinfo`、OIDC Discovery、Refresh Token Rotation、Revocation、Introspection、M2M Profile（client_credentials）、PostgreSQL Adapter、Conformance Suite（Basic OP） |
| M3（P1） | MCP 連携 | Resource Indicators、MCP Client Profile（CIMD）、JWT Access Token（任意）、Protected Resource Metadata 用ミドルウェア |
| M4（P2） | 高度な拡張 | Token Exchange、DPoP、PAR、private_key_jwt、RAR |

技術スタック案の Phase 1〜4 との差分:

- Refresh Token は案どおり M2 だが、Storage の契約テストと Token Family の型は M1 で用意する（後から原子性を足すと Adapter の作り直しになる）。
- Introspection・Revocation を「推奨」から M2 必須に上げる（Opaque AT の帰結、ADR-0006）。
- Token Operations の `Mint` / `Reissue` は計画から外す（ADR-0006）。

## M1 のタスク順序

依存関係の順に並べる。各タスクは単独で PR にできる粒度。

| # | タスク | 内容 | 完了条件 |
| --- | --- | --- | --- |
| 1 | 足場 | `go.mod`（go 1.26）、`go.work`、`LICENSE`（Apache-2.0）、`README.md`、`.github/workflows/ci.yml`（vet / staticcheck / govulncheck / `test -race`）、`internal/rand`, `internal/clock` | CI が空のテストで通る |
| 2 | `client` | `Client` 型、3 Profile の条件表（ADR-0004）、`NewWeb/NewNative/NewMachine`、redirect URI 照合（完全一致、loopback ポート無視）、secret のハッシュと検証 | 条件表と実装の一致テスト、照合規則のテーブルテスト |
| 3 | Store Port | `storage` のセンチネルエラー、各文脈パッケージの `Store` インターフェースと保存対象の構造体（Txn / Code / Grant / Token Family / Token）、ルートの合成 `authengine.Store`、`storage/memory`、`storage/storagetest`（並行テスト含む） | memory 実装が契約テストを通る |
| 4 | `authorization` | `AuthorizationRequest` の解析・検証（RFC 6749 §4.1.1、RFC 7636、OIDC §3.1.2.2 の `nonce` 受理）、「リダイレクトしてよいエラー / してはいけないエラー」の判定、Txn 状態機械、`Begin/Complete/Reject/Resume`、PKCE S256 検証、Code 発行 | 状態遷移の全パス、`max_age` 検証、`granted_scopes ⊆ requested_scopes`、Fuzz（要求パース） |
| 5 | `grant` + `token`（Code 交換） | Grant の upsert、Token Family 作成、Opaque Access Token 発行、`/token` の `authorization_code` 処理（client 認証 `client_secret_basic/post` と `none`、`redirect_uri` 一致、PKCE、Code 単回消費、再利用検知→Token Family 失効）、RFC 6749 §5.2 のエラー | Code 二重交換テスト、PKCE 不一致、Client 不一致 |
| 6 | `httpapi` | 公開 Handler（`/authorize`, `/authorize/resume`, `/token`, `/.well-known/oauth-authorization-server`）、Interaction Handler（`GET /transactions/{id}`, `POST .../complete`, `POST .../reject`）、Bearer 認証、ブラウザ結合 Cookie、`ErrorRenderer`、`Cache-Control: no-store` | `httptest` で各エンドポイントの正常・異常系 |
| 7 | `adapters/sqlite` | スキーマ（`migrations/*.sql` を `embed`）、goose ライブラリで適用、Port 実装、WAL / busy_timeout の固定 | `storagetest` を **ファイル DB** で通過（並行テスト含む） |
| 8 | `examples/standalone` | エンジン + テスト用 Interaction App（固定ユーザーで自動承認、`/login` フォーム付き）+ サンプル CLI Client（loopback redirect） | `go run` で 1 プロセス起動し、CLI がトークンを得る |
| 9 | `tests/` E2E | `httptest` で Engine と Interaction App を起動し、Web / Native 両 Profile でフロー完走。異常系（期限切れ Txn、Cookie 不一致、Code 再利用） | CI で実行 |
| 10 | 文書 | `docs/interaction-api.md`（Interaction App 実装者向け）、各パッケージ `doc.go` に対応 RFC 節 | — |

タスク 2〜3 は並行可能。4 以降は直列。

## M1 の実施結果（2026-10-24）

10 タスクすべてを完了した。計画との差分:

- `tests/` は別モジュールにした（コアから Adapter を import できないため。ADR-0007 §3）。
- Code 再利用の検知で失効させるのは Grant ではなく Token Family にした（ADR-0003 / ADR-0005 を修正）。
- Refresh Token の型と `RotateRefreshToken` の契約テストは M1 で用意し、SQLite Adapter も実装済み。発行と `refresh_token` グラントの処理は M2。
- `Outcome.remember_consent` は M1 では実装せず、Grant は常に記録する。
- Interaction API の「既存 Grant の参照」は M1 では提供せず、M2 で `GET /grants` として追加する。
- `Engine`（ルートの配線）はタスク 6 で実装した。

## M1 で明示的に先送りするもの

- `/jwks`, `/userinfo`, ID Token（M2）。ただし `openid` scope と `nonce` は M1 で受理して Txn に保存する。
- Refresh Token の発行（M2）。Token Family の型と契約テストは M1。
- `resource` パラメータ（M3）。未知のパラメータとして無視せず、M1 では `invalid_target` を返さずに受理だけして保存する（M3 で検証を足す）。
- PostgreSQL（M2）。
