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

## M2 のタスク順序

到達点: OIDC Basic OP として動き、Refresh Token・Revocation・Introspection・M2M を備え、PostgreSQL でも同じ契約テストを通す。
依存関係の順に並べる。1〜3 が OIDC、4〜6 がトークンライフサイクル、7〜9 が永続化と品質保証。

| # | タスク | 内容 | 完了条件 |
| --- | --- | --- | --- |
| 1 | `keys` | 署名鍵セット。RS256（RSA 2048）/ ES256（P-256）の生成、`kid`（RFC 7638 サムプリント）、署名鍵 1 本と検証鍵複数（ローテーション中の旧鍵）、公開 JWKS の出力、秘密鍵セットの JSON 入出力（examples が永続化に使う）。go-jose/v4 の利用はこのパッケージに閉じる（ADR-0002） | 署名→検証の往復、未知 `kid`・`alg` 不一致の拒否、JWKS に秘密鍵が含まれないこと |
| 2 | `oidc` ID Token + Discovery | ID Token の組立（`iss` `sub` `aud` `exp` `iat` `auth_time` `nonce` `at_hash` `amr` `acr`、OIDC Core §2・§3.1.3.6）と署名。`openid` 付与時に Code 交換の応答へ `id_token` を追加。`GET /jwks`、`GET /.well-known/openid-configuration`（`jwks_uri` `userinfo_endpoint` `id_token_signing_alg_values_supported` `subject_types_supported` `claims_supported` 等）。RFC 8414 側のメタデータにも追加分を反映 | ID Token を JWKS で検証できる、`at_hash` が RFC 7636 と同様の base64url 左半分で一致、`nonce` の往復 |
| 3 | `oidc` UserInfo | `GET|POST /userinfo`（Bearer、RFC 6750 §3 の `WWW-Authenticate` エラー）。Access Token → Grant の Claims を scope で絞って返す（OIDC Core §5.4 の `profile` `email` `address` `phone` 対応表）。`sub` は必須 | 失効・期限切れ・`openid` なしのトークンを拒否、Claims が scope で絞られる |
| 4 | Refresh Token | Code 交換時に Profile が許せば Refresh Token を発行（絶対期限 30 日・スライド期限 14 日、Family の `ExpiresAt`）。`grant_type=refresh_token`: `RotateRefreshToken`、再利用検知で Family 失効、`scope` パラメータによる縮小（RFC 6749 §6）、`openid` なら新しい ID Token（OIDC Core §12.2）。Discovery の `grant_types_supported` 更新 | Rotation の往復、再利用で Family 失効、scope 拡大の拒否、期限切れ |
| 5 | M2M（`client_credentials`） | Machine Profile の `grant_type=client_credentials`（RFC 6749 §4.4）。Grant は `subject = client_id` で記録し、Refresh Token も ID Token も出さない。`scope` は Client の許可範囲内 | M2M の発行・Introspection、Web / Native では `unauthorized_client` |
| 6 | Revocation・Introspection・管理 API | `POST /revoke`（RFC 7009、`token_type_hint`、他 Client のトークンは黙って 200）、`POST /introspect`（RFC 7662、confidential Client の認証、`active` `scope` `client_id` `sub` `exp` `iat` `token_type`）。Go API: `Inspect` `RevokeToken` `RevokeGrant` `ListGrants(subject)`（ADR-0006 §5）。Store に `ListGrantsBySubject` を追加。Interaction API に `GET /grants?client_id=&subject=`（同意スキップ用、ADR-0003 §3 (4)） | 失効後の Introspection が `active:false`、Refresh Token 失効で Family 全体が無効、`GET /grants` で既存の付与 scope が取れる |
| 7 | `adapters/postgres` | pgx/v5、goose、同じ契約テストを Testcontainers で実行。`FOR UPDATE` による Grant 行ロック、`UPDATE ... RETURNING`。Docker がなければ `t.Skip` | `storagetest` 全件通過（Docker あり環境） |
| 8 | Conformance Suite | OpenID Foundation Conformance Suite（Basic OP プロファイル）を Docker Compose で起動し、`-auto-approve` の loginapp で自動実行する手順と設定ファイル。見つかった不適合を修正 | Basic OP の必須テストが通る。結果と未対応項目を `docs/conformance.md` に記録 |
| 9 | E2E・文書 | E2E に ID Token の JWKS 検証、Refresh、Revocation、Introspection、UserInfo を追加。`docs/interaction-api.md` に `GET /grants`、README と ADR の状態更新 | — |

タスク 1〜3 と 4〜6 は互いに独立しており並行可能。7 はいつでも着手できる。8 は 1〜6 の後。

## M2 で明示的に先送りするもの

- JWT 形式の Access Token（RFC 9068）、`resource` の検証（M3）
- `private_key_jwt`、PAR、DPoP、Token Exchange（M4）
- Client の更新・削除 API（必要になった時点で `UpdateClient` を Store に追加する）
