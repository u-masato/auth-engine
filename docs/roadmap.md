# ロードマップと M1 の実装順序

- 状態: 採用（2026-10-24 合意）。**M1・M2 は 2026-10-24 に完了**（Conformance Suite は実行したが、PKCE 必須のため Basic OP の大半は評価不能。[conformance.md](conformance.md)）
- 日付: 2026-10-24

準拠仕様の段階（P0〜P3）は [準拠仕様一覧](specifications.md) に従う。ここでは P0 を 2 つのマイルストーンに分け、M1 のタスク順序を決める。

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

## M2 の実施結果（2026-10-24）

タスク 1〜9 を実施した。計画との差分と補足:

- Refresh Token は絶対期限（30 日）とスライド期限（14 日）の両方を実装した（ADR-0006 §4 の「P0 は絶対期限のみでもよい」より踏み込んだ）。`Engine.Config.RefreshTokenTTL` / `RefreshTokenIdleTTL` で変更できる。
- Refresh 応答の ID Token に元の `auth_time` / `amr` / `acr` を載せるため、Token Family にそれらの写しを持たせた（SQLite は migration `00002`）。`token.Store` に `GetTokenFamily` を追加。
- scope 縮小は今回の Access Token にだけ効き、Family（後継 Refresh Token）の scope は変えない。
- Introspection は confidential Client（Web / Machine）の認証を要求し、認証に通れば他 Client のトークンも参照できる（Resource Server は Machine Profile の Client として登録する想定）。public Client は `invalid_client`。
- Revocation は他 Client・不明・失効済みのトークンに対して黙って 200 を返す。Refresh Token の失効は Family 全体を失効させる。
- Grant の管理 API は `grant.Service`（`Find` / `List` / `Revoke`）として `Engine.Grants` に配線した。`grant.Store` に `ListGrantsBySubject` を追加。Interaction API の `GET /grants` は参照のみで、連携解除の HTTP API は置いていない。
- OIDC 要求（`openid` scope）では `redirect_uri` を必須にした（OIDC Core §3.1.2.1）。OAuth 2.0 だけの要求は従来どおり登録 URI が 1 つなら省略できる。
- PostgreSQL Adapter はプロセス内 Mutex を使わず、`SELECT ... FOR UPDATE` と CAS で原子性を担保する。契約テストは Testcontainers（`postgres:16`）で全件通過。
- Conformance Suite（release-v5.3.3、公開イメージ）で Basic OP プランを実行した。35 モジュール中 30 は `code_challenge` なしの要求から始まり、PKCE 必須のエンジンでは `invalid_request` になるため評価できない。評価できた 5 件は PASSED 2（PKCE 付きの完全フロー、`response_type` 欠落）、REVIEW 2（redirect_uri 不一致のエラーページ）、SKIPPED 1（`request_not_supported`）。PKCE 必須は維持し Basic OP 認定は目標にしないと判断した（[conformance.md](conformance.md)「結果」）。実行のために `Config.AllowInsecureIssuer`、`client.WebParams.Secret`、loginapp の Cookie セッション（`prompt=none` / `prompt=login` / `max_age` の解釈）を追加した。
- `go mod tidy` が各 `go.mod` の `go` 指示子を 1.26.10 に上げたことがあったため、1.26 に戻した。最低バージョンは Go 1.26 のまま。

## M2 で明示的に先送りするもの

- JWT 形式の Access Token（RFC 9068）、`resource` の検証（M3）
- `private_key_jwt`、PAR、DPoP、Token Exchange（M4）
- Client の更新・削除 API（必要になった時点で `UpdateClient` を Store に追加する）
- Basic OP 認定（PKCE 必須を維持するため目標にしない。必要になれば新 Profile を追加して対応する。[conformance.md](conformance.md)「PKCE 必須との非互換」の判断）
- Interaction API での連携解除（`DELETE /grants`）。M2 では Go API `Engine.Grants.Revoke` のみ

## M3 のタスク順序

到達点: MCP クライアント（CIMD で識別、事前登録なし）が MCP サーバー（Resource Server）向けに `resource` 付きで認可を受け、対象リソースに結びついた Access Token を得る。MCP サーバー側は本リポジトリのミドルウェアで RFC 9728 のメタデータを公開し、Audience を検証できる。基準は [MCP Authorization Specification（2026-07-28）](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) と [CIMD draft-02（2026-07-06）](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)（MCP 仕様は draft-00 を参照するが、AS 側の要件は draft-02 と矛盾しない）。

### 着手前に合意した設計判断（[ADR-0008](adr/0008-mcp-integration.md)）

M3 はコアの状態遷移を変えずに済む（ADR-0001 §2 (5)）が、次の判断は既存 ADR の記述を超えるため、2026-10-24 に合意して ADR-0008 に記録した。詳細と既存 ADR への影響は ADR-0008 を参照。

1. **Resource Server の登録は静的設定。** `Engine.Config.Resources`（URI、表示名、Access Token 形式、許可 scope）で与え、Store には置かない。Resource Server はデプロイ単位で決まり、Client のように実行時に増えないため。要求された `resource` が設定にないものは `invalid_target`（RFC 8707 §2）。
2. **登録済み Client の `resource` 制限。** ADR-0004 §2 の予約どおり `Client.Resources` を開放項目に加える。空なら設定済みの全 resource を要求でき、指定があればその範囲に限る。CIMD で識別する Client は事前登録がないので、常に設定済みの全 resource を要求できる。
3. **Access Token の形式は resource ごとに決める。** JWT（RFC 9068）を使うかは Resource Server の都合なので、Client ではなく `Config.Resources` の項目で選ぶ。`resource` なしの要求は従来どおり Opaque。複数 `resource` を要求する場合は形式が揃っていること（揃わなければ `invalid_target`）。JWT でも Store に Access Token の行を持ち（Hash はトークン文字列の SHA-256）、Introspection と Revocation は形式に依らず同じ経路で動く。ただし JWT の失効は Resource Server がローカル検証する限り伝播しないことを明記する（ADR-0006 §1 の帰結）。
4. **MCP Client Profile。** ADR-0004 §6 のとおり 4 つ目の Profile を追加する。public、`authorization_code` + `refresh_token`、PKCE S256、`token_endpoint_auth_method=none`（`private_key_jwt` は M4）、`resource` 必須（欠落は `invalid_request`）、Refresh Token は Native と同じく発行・Rotation（MCP 仕様 Security Considerations「Token Theft」）、`openid` scope 要求時は ID Token を発行する。redirect URI は CIMD 文書の `redirect_uris` と完全一致。ただし loopback はポート番号を無視し（RFC 8252 §7.3）、`http://localhost` も許可する（MCP 仕様「Communication Security」が localhost を明示的に許すため。Native Profile の既定とは異なる）。
5. **CIMD の Resolver はコアの `cimd` パッケージ。** `client.Resolver` の実装を 2 つ重ねる（Store → CIMD）。`https://` で始まり path を持つ `client_id` だけを CIMD として扱う。取得は net/http（標準ライブラリなので ADR-0002 の依存制約には触れない）、リダイレクト追従なし、5 KB 上限、タイムアウト、RFC 6890 の特殊用途アドレスへの接続拒否（loopback は開発用フラグでのみ許可）。文書の `client_id` は URL と単純文字列比較で一致すること。`token_endpoint_auth_method` が `none` 以外、または `client_secret` を含む文書は拒否。キャッシュはプロセス内メモリで、HTTP の `Cache-Control` を尊重し上下限を設け、エラーと不正な文書はキャッシュしない。信頼ポリシー（ドメイン許可リスト等）は `cimd.TrustPolicy` インターフェースとして差し替え可能にし、既定は全許可。
6. **Interaction API の追加。** `client.profile` に `mcp` を追加し、`client.client_uri` と `request.redirect_uri` を全 Profile で返す。MCP 仕様（CIMD Security）は同意画面で redirect URI のホスト名を表示することを MUST とするため、Interaction App が描けるようにする。`docs/interaction-api.md` の契約変更として明記する。
7. **Resource Server 用ミドルウェアはコアモジュール内の `resourceserver` パッケージ。** 外部依存を増やさない（JWT 検証は `keys` 経由、Introspection は net/http）ので別モジュールにする理由がない。`Engine` には依存せず、別プロセスの MCP サーバーから単独で使える。
8. **Dynamic Client Registration（RFC 7591）は実装しない。** MCP 2026-07-28 版で非推奨であり、CIMD が「事前関係なし」の場面を満たす。無認証の登録エンドポイントはごみ登録の経路になる。旧クライアントとの相互運用で必要になった時点で再検討する。

### タスク

依存関係の順に並べる。1〜3 が Resource Indicators とトークン、4〜5 が MCP Client（CIMD）、6 が Resource Server 側、7〜9 が結合と品質保証。

| # | タスク | 内容 | 完了条件 |
| --- | --- | --- | --- |
| 1 | `resource` の検証（認可要求側） | `Config.Resources` と `resource.Resource`（URI は絶対 URI、fragment なし、scheme / host は小文字に正規化して比較。RFC 8707 §2、MCP「Canonical Server URI」）。`Client.Resources` の追加（ADR-0004 §2）。認可要求の `resource` を設定と Client の許可範囲で検証し、範囲外は `invalid_target`（リダイレクトしてよいエラー）。Txn と `AuthorizationCode` に `Resource` を保存。Store: Client と Code の列追加（memory / SQLite migration `00003` / PostgreSQL migration `00002`）と `storagetest` の更新 | 許可外・不正形式・未設定の `resource` が `invalid_target`、Code に `resource` が引き継がれる、3 Adapter の契約テスト通過 |
| 2 | Audience 付き Access Token（トークン要求側） | `/token` の `resource` パラメータ（RFC 8707 §2.2）: `authorization_code` では Code の `resource` の部分集合、`refresh_token` では Family の部分集合への縮小、`client_credentials` では Client の許可範囲。`Family.Audience` と `AccessToken.Audience` の追加と保存。Introspection 応答に `aud`（RFC 7662 §2.2）。UserInfo は `openid` scope があれば `aud` に関わらず受理する（UserInfo は AS 自身のリソース）。Refresh の ID Token は従来どおり | Code の `resource` を超える要求が `invalid_target`、Introspection の `aud` 一致、`resource` なしの既存フローが変わらないこと |
| 3 | `token.Issuer` と JWT Access Token | ADR-0007 §4 で予約した `token.Issuer` を実体化し、Opaque と JWT（RFC 9068）の 2 実装を置く。形式は `Config.Resources` の項目で選ぶ（合意事項 3）。JWT は `typ: at+jwt`、`iss` `sub` `aud` `exp` `iat` `jti` `client_id` `scope`、`auth_time` `acr` `amr`（RFC 9068 §2.2）、署名は `keys` の RS256 / ES256。JWT の Access Token も Store に行を持ち、Introspection / Revocation は Opaque と同じ経路。Discovery に追加する項目はない（RFC 8707 / 9068 はメタデータを定義しない） | JWT を `/jwks` で検証できる、`aud` が `resource` に一致、Revocation 後の Introspection が `active:false`、Opaque 側の既存テストが変わらないこと |
| 4 | `client` MCP Profile と CIMD 文書の検証 | `ProfileMCP` を条件表に追加（合意事項 4）。`client.NewMCP(doc)`: CIMD 文書（`client_id` `client_name` `redirect_uris` 必須、`client_uri` `logo_uri` `scope` `grant_types` `token_endpoint_auth_method` を解釈）から `Client` を組み立てる純粋な検証。`client_id` の形式（https、path あり、userinfo / fragment なし、`.` `..` セグメントなし。CIMD §3）、`client_id` と文書 URL の一致（§4）、`token_endpoint_auth_method=none` 以外の拒否（§4.1）。redirect URI の照合規則（loopback ポート無視、`http://localhost` 許可、それ以外は完全一致）。ネットワークは触らない | 条件表と実装の一致テスト、CIMD 文書の正常・異常系のテーブルテスト、照合規則のテーブルテスト |
| 5 | `cimd` Resolver と配線 | `cimd.Resolver`（`client.Resolver` 実装）: 取得（net/http、リダイレクト追従なし、5 KB 上限、タイムアウト、200 以外はエラー。CIMD §5、§8.6）、SSRF 対策（RFC 6890 特殊用途アドレスの拒否、開発用 `AllowLoopback`。§8.7）、メモリキャッシュ（`Cache-Control` 尊重、上下限、エラーはキャッシュしない。§5.2）、`TrustPolicy`。`client.ChainResolver`（Store → CIMD）を `Engine` が配線し、`Config.CIMD`（有効 / 無効、HTTP クライアント、上下限）で制御。Discovery に `client_id_metadata_document_supported: true`（§6）。Interaction API に `client.profile=mcp`、`client.client_uri`、`request.redirect_uri` を追加（合意事項 6）。`cimd/doc.go` に対応節を列挙 | `httptest` で CIMD 文書を配信し、URL `client_id` で認可要求が通る。`client_id` 不一致・リダイレクト・サイズ超過・特殊用途アドレス・`client_secret` 入り文書の拒否、キャッシュの有効期限、Store にある `client_id` が優先されること |
| 6 | `resourceserver` ミドルウェア | MCP サーバー（Resource Server）に組み込む net/http ミドルウェア（合意事項 7）。(a) RFC 9728 のメタデータ `GET /.well-known/oauth-protected-resource[/{path}]`（`resource` `authorization_servers` `scopes_supported` `bearer_methods_supported=["header"]` `resource_name`）。(b) Bearer 検証: 未提示・無効は 401 と `WWW-Authenticate: Bearer resource_metadata="..." scope="..."`（RFC 9728 §5.1、MCP「Scope Selection Strategy」）、scope 不足は 403 と `error="insufficient_scope"` + 必要 scope + `resource_metadata`（MCP「Runtime Insufficient Scope Errors」）。(c) 検証方式を `TokenVerifier` で差し替え: Introspection（RFC 7662、Machine Profile の資格情報）と JWT ローカル検証（AS メタデータから `jwks_uri` を得て `keys` で検証、`typ=at+jwt`、`iss` `aud` `exp`、`alg` 許可リスト）。どちらも **Audience が自分自身であること** を必須で確認する（MCP「Token Handling」）。(d) 検証済みの主体（`sub` `client_id` `scope` `aud`）を `context.Context` に載せる補助。scope 階層の解釈はミドルウェアの責務にせず、ルートごとの必要 scope を利用者が与える | 他 resource 向けトークンの拒否（Opaque / JWT とも）、401 / 403 のヘッダー形式、メタデータの JSON、JWKS キャッシュと `kid` 不明時の再取得 |
| 7 | `examples/standalone` と `oauthclient` | `cmd/server` に `-resources`（`Config.Resources` の静的設定）と `-cimd-allow-loopback` を追加。デモ MCP サーバー `cmd/mcp-server`（`resourceserver` を使い、`/mcp` に 401 / 403 / 200 を返す最小の Resource Server。MCP プロトコル自体は実装しない）。`oauthclient` に `resource` と CIMD `client_id`（文書を `httptest` または `cmd/cimd-host` で配信）を追加し、`cli-client` に `-resource` `-client-id-url` を追加。loginapp の同意画面に `client_uri` と redirect URI のホスト名を表示 | `go run` で AS・MCP サーバー・CLI を起動し、CIMD の `client_id` で `/mcp` にアクセスできる |
| 8 | `tests/` E2E と MCP 相互運用 | E2E: CIMD Client → `resource` 付き認可 → Opaque / JWT 各形式で `resourceserver` が受理、別 resource 向けトークンの拒否、`insufficient_scope` からの step-up 再認可（scope の和集合で Grant が広がる）、`invalid_target`、CIMD 文書の差し替え（キャッシュ切れ後に redirect URI が変わる）。相互運用: 公式の MCP クライアント（MCP Inspector、または Go / TypeScript SDK のクライアント）を使い、CIMD + `resource` + PKCE の完全フローを確認する手順と結果を `docs/mcp-interop.md` に記録する。Conformance Suite と同様に手動実行でよい | CI で E2E が通る。相互運用の結果と未対応項目が文書化されている |
| 9 | 文書 | ADR-0008 の状態更新と、ADR-0004（Profile 表に MCP、開放項目に `Resources`）、ADR-0006（JWT AT と Audience）、ADR-0007（`cimd` `resource` `resourceserver` の追加、`token.Issuer` の実体化）の修正。`docs/interaction-api.md` の契約変更、`docs/specifications.md` の P1 の状態、README、各パッケージ `doc.go` | — |

タスク 1〜3 は直列。4 は 1 と並行可能。5 は 1 と 4 の後。6 は 2〜3 の後（JWT 検証と Introspection の `aud` を使う）。7〜8 は 5〜6 の後。

### M3 で明示的に先送りするもの

- Dynamic Client Registration（RFC 7591）。合意事項 8 のとおり実装しない
- CIMD Client の `private_key_jwt`（RFC 7523、CIMD §4.1）。M4 の `private_key_jwt` と併せて実装し、そのとき `token_endpoint_auth_method=private_key_jwt` と `jwks` / `jwks_uri` を受理する
- CIMD 文書の変更検知（`redirect_uris` や鍵の変更時の再同意・失効。CIMD §8）。M3 ではキャッシュ切れ後に新しい文書で上書きするだけで、Grant には触れない
- `logo_uri` の事前取得とキャッシュ（CIMD §8.3）。Interaction App の責務とし、エンジンは URL を透過する
- CIMD Client の永続化。M3 ではプロセス内キャッシュのみ。複数インスタンス構成でのキャッシュ共有は、必要になった時点で `cimd.Cache` の Store 実装を足す
- Token Exchange（RFC 8693）による別 Audience への交換、DPoP（RFC 9449）によるトークン拘束（M4）
- MCP Authorization Extensions（ext-auth リポジトリ）。コア仕様の範囲に留める
