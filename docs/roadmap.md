# ロードマップと M1 の実装順序

- 状態: 採用（2026-10-24 合意）。**M1・M2 は 2026-10-24 に完了**（Conformance Suite は実行したが、PKCE 必須のため Basic OP の大半は評価不能。[conformance.md](conformance.md)）。**M3 は 2026-10-25 に完了**（MCP Inspector との相互運用は手動実行。[mcp-interop.md](mcp-interop.md)）。**M4 は M4a / M4b に分け、M4a の分解は草案**（2026-10-25。末尾の「M4a のタスク順序（案）」）
- 日付: 2026-10-24

準拠仕様の段階（P0〜P3）は [準拠仕様一覧](specifications.md) に従う。ここでは P0 を 2 つのマイルストーンに分け、M1 のタスク順序を決める。

## マイルストーン

| MS | 到達点 | 含むもの |
| --- | --- | --- |
| **M1** | Go ライブラリとして、SQLite だけで Authorization Code + PKCE を完走 | Web / Native Profile、Txn と Interaction API（ADR-0003）、Code 発行・交換、Opaque Access Token、SQLite Adapter、E2E テスト、最小の Discovery（RFC 8414） |
| **M2** | OIDC 対応と運用に必要なトークンライフサイクル | ID Token、`/jwks`、`/userinfo`、OIDC Discovery、Refresh Token Rotation、Revocation、Introspection、M2M Profile（client_credentials）、PostgreSQL Adapter、Conformance Suite（Basic OP） |
| **M3**（P1） | MCP 連携 | Resource Indicators、MCP Client Profile（CIMD）、JWT Access Token（任意）、Protected Resource Metadata 用ミドルウェア |
| M4a（P2、案） | クライアント認証と送信者拘束。FAPI 2.0 Security Profile を Conformance Suite で回せる | Web Legacy Profile（ADR-0009）、`private_key_jwt`（`jwks` / `jwks_uri`）、PAR、DPoP、FAPI Profile（[ADR-0010](adr/0010-client-auth-and-sender-constraint.md)） |
| M4b（P2、案） | エージェント間の委譲と細かい権限の表現 | Token Exchange、RAR（ADR-0011 で決める） |

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

### M3 の実施結果（2026-10-25 完了）

タスク 1〜9 を実施した。各タスクの差分と補足:

- **タスク 1（2026-10-24 完了）**: `resource` パッケージ（`Resource` / `Format` / `Set`、`Normalize`）、`Config.Resources`、`Client.Resources`（全 Profile の `Params` に追加、正規形で保持）、認可要求の `resource` 検証（構文違反・未設定・Client の許可範囲外・形式不一致は `invalid_target`、リダイレクトして返す）、`Request.Resource` と `AuthorizationCode.Resource` の引き継ぎ、SQLite migration `00003` / PostgreSQL migration `00002`、`storagetest` の更新。計画との差分と補足:
  - `resource.Normalize` は RFC 8707 §2 の「絶対 URI」をそのまま採り、`https` に限定しない（`urn:` も受理する）。MCP は `https` を使うが、RFC 8707 自体は scheme を限定しないため。host を持たない `scheme:` だけの値は拒否する。
  - 複数 `resource` の Access Token 形式の一致検査（ADR-0008 §3）は、形式を決める `Resource.AccessTokenFormat` がタスク 1 で入るので、認可要求側の検証に含めた。
  - `Resource.Scopes`（resource ごとの scope 上限）は型と検証だけを入れ、要求 scope の絞り込みはトークン発行側のタスク 2 で行う。認可要求の `scope` は AS 自身向け（`openid` 等）と resource 向けが混在するため、認可要求の段階で `resource.Scopes ⊆` を強制すると OIDC と併用できない。
  - `resource=`（値なし）は RFC 6749 §3.1 のとおり省略として扱う。正規形で重複する値は 1 つにまとめる。
- **タスク 2（2026-10-24 完了）**: `Family.Audience` / `AccessToken.Audience`、`/token` の `resource` パラメータ（`authorization_code` は Code の `Resource` の部分集合、`refresh_token` は Family の `Audience` の部分集合、`client_credentials` は設定済みかつ Client の許可範囲内）、Introspection 応答の `aud`（常に配列。`resource` なしのトークンでは省略）、SQLite migration `00004` / PostgreSQL migration `00003`、`storagetest` の更新。計画との差分と補足:
  - `resource.Set.Resolve`（正規化・設定照合・重複排除・形式一致）を認可要求とトークン要求で共有する。認可要求の `invalid_target` の説明文は `invalid resource indicator: ...` / `unknown resource: ...` の形になった。
  - `Resource.Scopes` の制限を実装した。**OIDC の標準 scope（`openid` `profile` `email` `address` `phone` `offline_access`）は制限を受けない**。これらは認可サーバー自身（UserInfo、ID Token、Refresh Token）に向けた scope で、MCP クライアントが `openid` と resource 向け scope を同時に要求できなくなるのを避けるため。ADR-0008 §1 の「範囲外は `invalid_scope`」はこの例外付きで読む（ADR への追記はタスク 9）。複数 `resource` ではいずれかの resource が許せばよい（各 Resource Server は関係ない scope を無視する）。認可要求（`invalid_scope`、リダイレクト可）とトークン要求の両方で検査する。
  - fail-closed の追加: 設定から外された resource を Code / Family が持っていると、`resource` 未指定でも `invalid_target` にする（設定変更後に古い Family で発行し続けない）。
  - migration の番号は ADR-0008 の記述（SQLite `00003` / PostgreSQL `00002`）からずれ、タスク 1 で使った番号の次（SQLite `00004` / PostgreSQL `00003`）にした。タスク 1 の migration を適用済みの DB を壊さないため。
  - UserInfo は変更なし（`openid` があれば `aud` に関わらず受理する）。テストで明示した。
- **タスク 3（2026-10-24 完了）**: `token.Issuer`（`IssueInput` → 平文と `AccessToken` の記録）を実体化し、`OpaqueIssuer`・`JWTIssuer`（RFC 9068）・形式で振り分ける `ByFormat` を置いた。`Engine` は `ByFormat{Opaque, JWT}` を `token.Service.Issuer` に配線し、`Service` は Audience 先頭の resource 設定（`EffectiveFormat` / `EffectiveAlg`）で形式を決める。JWT は `typ: at+jwt`、`iss` `sub` `aud`（常に配列）`exp` `iat` `jti` `client_id` `scope`、認可コード由来なら `auth_time` `acr` `amr`。`keys` に `SignTyped` と `Header.Type` を追加。計画との差分と補足:
  - JWT の署名アルゴリズムは `Resource.AccessTokenAlg`（RS256 / ES256、既定 RS256）で resource ごとに選ぶ。ADR-0008 §1 の設定例にはなかった項目。`FormatOpaque` では指定できない。`Engine.New` は JWT の resource に対応する署名鍵が `Keys` にあることを起動時に確認する。
  - `JWTIssuer` は `oidc` ではなく `token` パッケージ（`token/jwt.go`）に置いた。Access Token は OAuth の概念であり、`token` → `keys` の依存は `oidc` → `keys` と同じ向きで循環しない。
  - Discovery への追加項目はない（RFC 8707 / 9068 はメタデータを定義しない）。
  - 失効はローカル検証に伝播しないことをテストで明示した（Revocation 後も署名は検証できるが Introspection は `active:false`）。
- **タスク 4（2026-10-25 完了）**: `client.ProfileMCP`（public、`authorization_code` + `refresh_token`、PKCE S256、`none`、`resource` 必須、ID Token 発行）、`client.MetadataDocument` と `client.NewMCP(doc, documentURL, now)`（CIMD §3 の `client_id` 形式、§4 の文書 URL との単純文字列一致、§4.1 の共有シークレット拒否、`grant_types` / `response_types` の矛盾検査）、`client.ParseClientIDURL`、MCP の redirect URI 規則（https 完全一致、`http://localhost` 許可、http loopback はポート無視）。認可要求で MCP Client の `resource` 欠落は `invalid_request`（リダイレクト可）。計画との差分と補足:
  - 文書に `scope` がない MCP Client は scope の上限を持たない（`Client.Scopes` 空 = 制限なし。他 Profile では空は不正のまま）。事前登録のないクライアントの scope は resource ごとの上限（`Resource.Scopes`）で絞る。
  - `Client.ClientURI`（CIMD の `client_uri`）を追加し、Store にも保存する（SQLite migration `00005` / PostgreSQL migration `00004`）。URL 形式の `client_id` を `Store` に事前登録する経路（CIMD §7）で値が落ちないようにするため。計画では Store の変更はなかった。
  - `client.ChainResolver`（Store → CIMD）と `client.ErrUnresolvable`（形式は正しいが解決できない `client_id`）はタスク 4 で入れた。`authorization` は理由付きの `invalid_request`（リダイレクトしない）、`token` は `invalid_client` に写す。
  - `http://localhost` のポートは完全一致で、ポートを無視するのは loopback IP リテラル（RFC 8252 §7.3 の対象）だけにした。
- **タスク 5（2026-10-25 完了）**: `cimd` パッケージ（`cimd.Resolver`、`cimd.Config`、`cimd.TrustPolicy` / `AllowAll` / `HostAllowlist`、`cimd.NewTransport`）、`Config.CIMD` による `Engine` の配線（`Engine.Clients` = `ChainResolver{Store, CIMD}`、`Engine.CIMD`）、Discovery の `client_id_metadata_document_supported: true`（有効時のみ）、Interaction API の `client.profile=mcp`・`client.client_uri`・`request.redirect_uri`（全 Profile）。`docs/interaction-api.md` に契約変更と、MCP ではホスト名を表示する要請を記載。計画との差分と補足:
  - SSRF 対策は名前解決後の接続先アドレスを `net.Dialer.Control` で検査する形にした（ADR-0008 §5 の「接続前に名前解決し」を、解決と接続の間に隙間がない形で満たす）。拒否対象は netip の判定（loopback、private、link-local、multicast、unspecified）に RFC 6890 の残りの範囲（Shared Address Space、TEST-NET、Benchmarking、6to4、Documentation、IPv4-mapped 等）を足した。プロキシは使わない（プロキシ経由だと接続先を検査できない）。
  - `Config.HTTPClient` を差し替えてもリダイレクト非追従（`CheckRedirect`）は Resolver が上書きするが、接続先の検査は Transport の責務なので `cimd.NewTransport` を基にすることを文書で求めた。
  - `Cache-Control` は `max-age`（`s-maxage` 優先）を [下限 1 分, 上限 24 時間] に収める。`no-store` / `no-cache` も下限でキャッシュする（取得ごとに文書サーバーへ問い合わせない判断。ADR-0008 §5 の「ヘッダーがなければ下限」と同じ扱い）。キャッシュ件数の上限（既定 1000。期限切れ → 期限の近いものの順に捨てる）を足した。未知の `client_id` を大量に送られてもメモリが際限なく増えないようにするため。
  - `Interaction API` の `GET /transactions/{id}` は `Store` ではなく `Engine.Clients` で Client を引く（CIMD Client は Store にない）。
  - `examples/standalone` と loginapp の対応（`-cimd-allow-loopback`、同意画面でのホスト名表示）はタスク 7。
- **タスク 6（2026-10-25 完了）**: `resourceserver` パッケージ（`Protector`、`Config`、`Metadata`、`TokenVerifier` / `VerifierFunc`、`Principal` / `FromContext`、`IntrospectionVerifier`、`JWTVerifier`）。RFC 9728 のメタデータ（`MetadataHandler` を `MetadataPath()` に mount。path を持つ resource は `/.well-known/oauth-protected-resource/{path}`）、Bearer 検証（未提示は 401 + `resource_metadata` + `scope`、無効は 401 `invalid_token`、scope 不足は 403 `insufficient_scope`、検証方式の障害は 503）、`aud` の必須確認（正規形で比較、無効化する設定なし）。`keys.ImportJWKS`（公開 JWKS から検証専用の Set）を追加。計画との差分と補足:
  - `IntrospectionVerifier` は応答の `token_type` が `Bearer` でない（省略を含む）トークンを拒否する。本エンジンの Introspection は Refresh Token に `token_type` を付けないので、Refresh Token を Bearer として持ち込まれても Resource Server で止まる。
  - `JWTVerifier` は署名検証の前にヘッダの `alg` を許可リスト（既定 RS256 / ES256）で落とす。JWKS は `Cache-Control: max-age` を [1 分, 24 時間] で尊重し（既定 1 時間）、未知の `kid` では `MinRefresh`（既定 1 分）を過ぎていれば再取得する。再取得に失敗しても手元の JWKS があればそれで続ける。
  - 認可サーバーメタデータ（RFC 8414）は `Issuer` から 1 回取得して `issuer` の一致を確認する（§3.3）。`Endpoint` / `JWKSURI` を直接与えればメタデータは取得しない。
  - `scripts/check-core-deps.sh` に、`resourceserver` が認可サーバー側のパッケージ（ルート、`httpapi`、`authorization`、`token` 等）に依存しないことの検査を足した（ADR-0008 §7 の「同様の検査で守る」）。
  - クエリやフォームの `access_token`（RFC 6750 §2.2、§2.3）は受け付けない（`bearer_methods_supported` は `header` のみ）。
- **タスク 7（2026-10-25 完了）**: `cmd/server` に `-resources`（JSON。`uri` `name` `access_token_format` `access_token_alg` `scopes`）、`-cimd`（既定 true）、`-cimd-allow-loopback`、`-cimd-ca`（文書サーバーの証明書を信頼する）、`-clients` の `mcp` Profile（`client.NewMCP` で事前登録。CIMD §7）と `resources` 項目。`cmd/mcp-server`（`resourceserver` を使う最小の Resource Server。`/mcp` は `mcp:read`、`/mcp/admin` は `mcp:write`、既定は JWT のローカル検証、`-introspect` で Introspection）。`cmd/cimd-host`（CIMD 文書を自己署名 TLS で配る。組み込みの `/demo-cli.json` を `client.NewMCP` で自己検証してから配る）。`oauthclient` に `CodeFlow.Resources`（認可要求とトークン要求の `resource`）、`DiscoverResource`（401 の `WWW-Authenticate` → RFC 9728 メタデータ → `authorization_servers`）、`ParseChallenge`、`CallResource`。`cli-client` に `-client-id-url` `-resource`（複数可）`-mcp`。loginapp の同意画面に `client_id` と redirect URI のホスト名、localhost の注意書き、`client_uri`（文字列）、`resource`。`demo.sh start` が 3 サーバーをまとめて起動し、`demo.sh mcp-flow` で CIMD の `client_id` から `/mcp` の 200 まで通ることを確認した。計画との差分と補足:
  - CIMD の `client_id` は https 必須（CIMD §3）なので、ローカルの文書配信は自己署名証明書を使う `cmd/cimd-host` にし、認可サーバー側に `-cimd-ca` を足した（`cimd.NewTransport` に `RootCAs` を加えた HTTPClient を `cimd.Config.HTTPClient` に渡す。計画では `-cimd-allow-loopback` だけだった）。TLS 検証を外す選択肢は作らない。
  - `cli-client` は `-resource` を直接与えるだけでなく、`-mcp` で MCP 仕様「Authorization Server Location」の手順（401 → `resource_metadata` → `authorization_servers`）を実際に辿る。`oauthclient.DiscoverResource` はメタデータの `resource` が要求した URL と一致しないと拒否する（RFC 9728 §3.3）。
  - loginapp は redirect URI のホスト名を MCP 以外の Profile でも出す（表示する情報を Profile で分けない方が単純で、Native の loopback にも同じ注意書きが当てはまる）。`client_uri` はエンジンが到達性を確認していないのでリンクにせず文字列で出す。
  - `-cimd` は既定で有効にした。デモサーバーは MCP 連携を試す入口でもあるため。本番の組み込みでは `Config.CIMD` を明示的に与える（`docs/embedding.md`）。
- **タスク 8（2026-10-25 完了）**: `tests/mcp_test.go`（E2E 4 本。CIMD Client → `resource` 付き認可 → JWT / Opaque 各形式を `resourceserver` が受理し別 resource 向けは拒否、Revocation の反映の差、`insufficient_scope` からの step-up で Grant の scope が和集合になる、Refresh での resource 乗り換え拒否、`invalid_target` / resource 欠落 / scope 上限超過 / 形式混在 / redirect 不一致 / 取得できない文書、CIMD 文書の差し替えがキャッシュ切れ後に効く）。相互運用は MCP Inspector v2.12.0（CLI）で CIMD + PKCE + `resource` の完全フローと `tools/list` / `tools/call` を確認し、手順・結果・未実施項目を [`docs/mcp-interop.md`](mcp-interop.md) に記録。再現スクリプトは `conformance/mcp-inspector.sh`。計画との差分と補足:
  - `cmd/mcp-server` に最小の MCP（Streamable HTTP の `initialize` / `ping` / `tools/list` / `tools/call`、`whoami` ツール。`cmd/mcp-server/mcp.go`）を実装した。タスク 7 では「MCP プロトコル自体は実装しない」としたが、公式クライアントは認可後に `initialize` を送るので、接続まで確かめるには最小限が要る。SSE・セッション・通知は実装しない。
  - Inspector の相互運用は Web UI ではなく CLI で行った（疑似 TTY と curl で自動承認のデモに対して無人で再現できる）。Web UI は未実施として文書に明記した。
  - `tests/e2e_test.go` に `newSystemWith`（`Config` の差し替え）と `registerMachine` を足した。
  - `demo.sh` の CIMD 文書は Inspector の CLI / TUI / Web のコールバックを既定で `redirect_uris` に含める（`DEMO_CIMD_REDIRECT_URIS`）。
- **タスク 9（2026-10-25 完了）**: ADR-0008 を「実装済み」にし、計画からの差分を末尾の「実装結果」に節ごとに記録した。既存 ADR への追記: ADR-0001 §3（DCR は実装しない）、ADR-0004 §1 の Profile 表に MCP Client の列、§2 の開放項目に `Resources` と `ClientURI`、§4 に `NewMCP`、§6 を「MCP Client Profile（M3 で追加）」に書き換え。ADR-0005 §3（`GetClient` は `ChainResolver` の 1 実装）。ADR-0006 §1（JWT Access Token は resource ごとに選ぶ、`Issuer` の 3 実装、Audience）。ADR-0007 §1 / §2 / §4（`resource` `cimd` `resourceserver` の位置づけと依存、拡張点の実体化）。`docs/specifications.md` の P1 に状態列、README の状態と制約、`docs/embedding.md` の本番前チェック（`Resources` / CIMD / `aud`）、ルート `doc.go`。計画との差分と補足:
  - `docs/interaction-api.md` の契約変更はタスク 5 で反映済みだったので、対象バージョンの表記だけを M3 に揃えた。
  - 各パッケージの `doc.go` は実装タスクで都度更新しており、タスク 9 で追加したのはルートの `doc.go`（`Resources` / `CIMD` の案内）だけ。

### M3 で明示的に先送りするもの

- Dynamic Client Registration（RFC 7591）。合意事項 8 のとおり実装しない
- CIMD Client の `private_key_jwt`（RFC 7523、CIMD §4.1）。M4 の `private_key_jwt` と併せて実装し、そのとき `token_endpoint_auth_method=private_key_jwt` と `jwks` / `jwks_uri` を受理する
- CIMD 文書の変更検知（`redirect_uris` や鍵の変更時の再同意・失効。CIMD §8）。M3 ではキャッシュ切れ後に新しい文書で上書きするだけで、Grant には触れない
- `logo_uri` の事前取得とキャッシュ（CIMD §8.3）。Interaction App の責務とし、エンジンは URL を透過する
- CIMD Client の永続化。M3 ではプロセス内キャッシュのみ。複数インスタンス構成でのキャッシュ共有は、必要になった時点で `cimd.Cache` の Store 実装を足す
- Token Exchange（RFC 8693）による別 Audience への交換、DPoP（RFC 9449）によるトークン拘束（M4）
- MCP Authorization Extensions（ext-auth リポジトリ）。コア仕様の範囲に留める

## M3 完了後の修正

マイルストーンのタスクに属さない修正のうち、外から見える挙動が変わるものを記録する。

- **HTTP 応答の形の変更（[#20](https://github.com/u-masato/auth-engine/issues/20)、2026-10-25）**: `/revoke` `/introspect` `/jwks` の内部障害（500）の本文を、`ErrorRenderer` が描く HTML のエラーページから、`/token` `/userinfo` と同じ JSON（`{"error":"server_error","error_description":"internal error"}`、`Content-Type: application/json`）に変えた。ステータスコード（500）と、プロトコルエラー（4xx）の形は変わらない。これらの呼び出し元は Client や Resource Server で、HTML のページは解釈できないため。[Interaction API](interaction-api.md) の契約の対象外だが、500 の本文を見ていた利用者には非互換になる。あわせて、`*token.Error` ならプロトコルエラー、それ以外は 500 とする振り分けを `/token` `/revoke` `/introspect` で `writeTokenFailure` に共通化した。

## M4a のタスク順序（案）

- 状態: **草案**（2026-10-25）。着手前に合意する設計判断は [ADR-0010](adr/0010-client-auth-and-sender-constraint.md) に書き起こした。合意後にこの節と ADR-0010 の状態を「採用」にする。

到達点: confidential クライアントが `private_key_jwt` で認証し、PAR で認可要求を提出し、DPoP で拘束された Access Token / Refresh Token を得る。FAPI 2.0 Security Profile（final）の AS 要件を Profile `fapi` で満たし、OpenID Conformance Suite の FAPI 2.0 Security Profile プラン（`private_key_jwt` + DPoP の variant）を回して結果を [conformance.md](conformance.md) に記録する。M2 で見送った「適合性を示す手段」をここで作る。

### 着手前に合意する設計判断（[ADR-0010](adr/0010-client-auth-and-sender-constraint.md)）

論点 1〜4 を 2026-10-25 に議論し、次の形で書き起こした。詳細と既存 ADR への影響は ADR-0010 を参照。

1. **認証方式は Profile が許す集合の中から、登録時の資格情報で決める**（ADR-0010 §1）。Client に方式のフィールドは置かず、`SecretHash` / `JWKS` / `JWKSURI` のどれか 1 つだけを持つ。Web / Web Legacy / Machine はシークレットか `private_key_jwt`、Native は `none`、MCP は `none` か `private_key_jwt`（CIMD 文書で決まる）、FAPI は `private_key_jwt` のみ。ADR-0004 §3 の「Profile が決める」は「許す集合を Profile が決める」に読み替え、個別フラグは増やさない。
2. **クライアントアサーションの検証**（§2）。`aud` は発行者識別子のみ、`iat` から `exp` までは既定 5 分、未来方向の許容 10 秒、`jti` 必須、`alg` は PS256 / ES256 / RS256（FAPI は RS256 を拒否）、失敗は理由を区別せず `invalid_client`。
3. **認証ロジックは `clientauth` パッケージ**（§3）。トークンエンドポイントと PAR が共用する。
4. **鍵は `jwks` と `jwks_uri` の両方**（§4）。併記は拒否。取得器は `resourceserver` の JWKS キャッシュを `keys` に移して共用し、SSRF 対策の Transport は `internal/safehttp` に移して `cimd` と共用する。キャッシュの単位は URL。CIMD Client の `jwks_uri` には同一 origin を求めず、文書と同じ `TrustPolicy` を適用する。
5. **`jti` のリプレイ記録は Store Port の 1 メソッド `RecordJTI`**（§5）。用途・発行者・`jti` の組の SHA-256 を期限付きで記録し、重複は `ErrAlreadyExists`。`clientauth.Store` と `dpop.Store` が同じシグネチャで宣言し、Adapter の実装は 1 つ（`replay_ids` 表）。掃除は `Purge`。Resource Server 側は差し替え可能なプロセス内キャッシュ。
6. **DPoP は Proof が提示されたら拘束する**（§6）。`Family.JKT`（public Client の Refresh Token）と `AccessToken.JKT`、`dpop_jkt` による認可コードの拘束（PAR の `DPoP` ヘッダも受ける）、`token_type: DPoP`、JWT の `cnf.jkt`、Introspection の `jkt`。nonce は `Config.DPoP.NonceSecret` を設定したときだけ要求する（ステートレスな HMAC）。Proof の `iat` は過去 5 分・未来 10 秒。
7. **FAPI 2.0 の要件は Profile `fapi` として束ねる**（§7）。confidential、`private_key_jwt` のみ（PS256 / ES256）、PAR 必須、DPoP 必須、Refresh Token は **Rotation しない**、認可コード寿命 60 秒以内、redirect URI は `https` のみ。他 Profile の挙動は変えない。resource 単位の必須化や Client のフラグは採らない。
8. **PAR は ADR-0003 の「Txn を `/authorize` より前に作る」形**（§8）。`request_uri` は 256 bit 乱数のハッシュ保存、寿命 60 秒、1 回だけ消費。confidential は `clientauth` で認証。`fapi` では `request_uri` のない認可要求を拒否。

### タスク

依存関係の順に並べる。1 は独立した小タスク、2〜5 がクライアント認証、6 が PAR、7〜8 が DPoP、9 が FAPI Profile、10〜11 が結合と文書。

| # | タスク | 内容 | 完了条件 |
| --- | --- | --- | --- |
| 1 | Web Legacy Profile | [ADR-0009](adr/0009-web-legacy-profile.md) の実装。`ProfileWebLegacy`、`pkcePolicy` の三値、認可要求の `openid` + `nonce` 判定、トークン要求の Downgrade 検知、`storagetest` に challenge 空の Code、`conformance/clients.json` を `web-legacy` に、`expected-failures.json` に `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`。Basic OP プランを再実行して conformance.md に記録 | ADR-0009 §2〜§3 の全分岐のテスト、既存 Profile の回帰、Basic OP の評価対象が 5 → 30 前後に増えること |
| 2 | `keys` の拡張と取得器 | PS256 の生成と検証（FAPI 2.0 §5.4.1）、JWK Thumbprint（RFC 7638）の公開、`resourceserver/jwt.go` の JWKS キャッシュを `keys.RemoteSet`（仮）に移設（`Cache-Control` 尊重、未知 `kid` の再取得と間引き、失敗時は手元の鍵）。`cimd.NewTransport` と接続先検査を `internal/safehttp` に移し、`cimd.NewTransport` は委譲で残す | `resourceserver` と `cimd` の既存テストが変わらないこと、PS256 で署名した JWT の往復 |
| 3 | `client` の資格情報と `private_key_jwt` の受理 | `Client.JWKS` / `JWKSURI`、`WebParams` / `MachineParams` の `JWKS` / `JWKSURI`（`Secret` との排他、併記の拒否、構築時の鍵検証）、Profile 規則表の `authMethods` に `private_key_jwt`、`AcceptsAuthMethod` を「集合 ∧ 資格情報」に。CIMD 文書の `token_endpoint_auth_method=private_key_jwt` と `jwks` / `jwks_uri` の受理（CIMD §4.1。`client_secret_post` は拒否のまま）。Store: clients の列追加（memory / SQLite / PostgreSQL の次の番号）と `storagetest` | 鍵を持つ Client の往復、シークレットと鍵の同時指定がエラー、CIMD 文書の 3 通り（`none` / 鍵あり / 共有シークレット）の判定、`profile_test.go` の表の更新 |
| 4 | `clientauth` パッケージとアサーション検証 | `token/clientauth.go` を `clientauth` に移設。`client_assertion` の検証（ADR-0010 §2）。`clientauth.Store.RecordJTI` と `replay_ids` 表（memory / SQLite / PostgreSQL、`Purge` に追加、`storagetest` の 4 ケース）。HTTP 層の `client_assertion` の取り出しと複数方式の併用拒否。Discovery の `token_endpoint_auth_methods_supported` と `token_endpoint_auth_signing_alg_values_supported` | インラインの `jwks` で `authorization_code` / `refresh_token` / `client_credentials` が通る、`aud` がエンドポイント URL だと `invalid_client`、同じ `jti` の 2 回目が `invalid_client`、同時 2 件で 1 件だけ成功（`-count=3`）、既存のシークレット認証の回帰 |
| 5 | `jwks_uri` の取得 | `clientauth` の URL 単位の取得器キャッシュ（件数上限、期限）、`internal/safehttp` の Transport、サイズ上限 64 KB、CIMD Client の `jwks_uri` に `TrustPolicy` を適用、`Engine.Config` の設定項目（`cimd.Config` と揃える） | 鍵の回転（`kid` 追加）が再取得で効く、特殊用途アドレスの拒否、取得不能時に手元の鍵で続く・手元になければ `invalid_client`、`TrustPolicy` 外の `jwks_uri` の拒否 |
| 6 | PAR（RFC 9126） | `POST /par`、`request_uri`（256 bit 乱数、ハッシュ保存、60 秒、CAS で 1 回消費）、Txn を `/authorize` より前に作る、confidential の `clientauth` 認証、`/authorize` の `request_uri` 解釈（`client_id` 以外のパラメータは無視）、Discovery の `pushed_authorization_request_endpoint`。`dpop_jkt` と `DPoP` ヘッダの受理はタスク 7 | PAR → `/authorize` → Code 交換の完走、`request_uri` の再利用と期限切れの拒否、認証のない confidential の PAR が `invalid_client`、`/authorize` 側パラメータの無視 |
| 7 | `dpop` パッケージとトークンエンドポイント | Proof の解析と検証（RFC 9449 §4.3）、Thumbprint、`Family.JKT` / `AccessToken.JKT` / `AuthorizationCode.DPoPJKT`（列追加と `storagetest`）、`dpop_jkt`（認可要求と PAR、`DPoP` ヘッダとの一致）、Code 交換と Refresh での鍵の照合、`token_type: DPoP`、JWT の `cnf.jkt`、Introspection の `jkt` と `token_type`、`dpop.Store.RecordJTI`、nonce（`Config.DPoP.NonceSecret`、`use_dpop_nonce`、`DPoP-Nonce`）、Discovery の `dpop_signing_alg_values_supported`、CIMD の `dpop_bound_access_tokens` | Proof ありで拘束されたトークンが出る、別鍵の Refresh が拒否される、`dpop_jkt` 不一致の Code 交換が `invalid_grant`、`htm` / `htu` / `iat` / `jti` の各違反、nonce の要求と再試行、Proof なしは従来どおり Bearer |
| 8 | `resourceserver` の DPoP | `Authorization: DPoP` と `DPoP` ヘッダの受理、`ath` と `jkt` の照合（Introspection の `jkt` / JWT の `cnf.jkt`）、拘束トークンの Bearer 提示の拒否（§7.1）、`WWW-Authenticate: DPoP algs="..."`、`jti` の差し替え可能なキャッシュ、任意の nonce（§9、既定無効） | 正しい Proof で 200、鍵違い・`ath` 違い・Bearer 提示で 401、Bearer トークンは従来どおり |
| 9 | FAPI Profile | `ProfileFAPI` と `NewFAPI`、規則表の `requirePAR` `requireDPoP` `rotateRefreshToken` `maxCodeTTL`、`RotateRefreshToken` の `next == nil`（Rotation なし。3 Adapter と `storagetest`）、PAR なし・Proof なしの拒否、RS256 のアサーション拒否、認可コード寿命の上限、ID Token の既定 ES256 | FAPI 2.0 §5.3.2 の各要件のテスト、Rotation なしで Refresh が繰り返せる、他 Profile の回帰 |
| 10 | `examples`・E2E・Conformance | `cmd/server` と `console` に `fapi` と「シークレット / 鍵」の選択、`oauthclient` に `private_key_jwt` / PAR / DPoP。`tests/` の E2E（`private_key_jwt` + PAR + DPoP の完走、`fapi` の Rotation なし、CIMD Client の `private_key_jwt`）。Conformance Suite の FAPI 2.0 Security Profile プランを実行し、構成と結果を conformance.md に記録 | E2E 通過、FAPI 2.0 プランの結果が記録されていること（不合格があれば理由と対応方針） |
| 11 | 文書 | ADR-0010 の状態更新と実装結果、ADR-0004 / 0005 / 0006 / 0007 / 0008 / 0009 への追記（ADR-0010「既存 ADR への影響」）、CLAUDE.md の不変条件（Rotation の例外）、`docs/interaction-api.md`（`profile` に `fapi`）、`docs/embedding.md`（鍵の登録、DPoP nonce の設定、`fapi` の使い方）、`docs/specifications.md` の P2 の状態、README、各パッケージ `doc.go` | — |

タスク 1 と 2 は独立で並行できる。3 は 2 の後（鍵の検証に `keys` を使う）。4 は 3 の後、5 は 4 の後。6 は 4 の後（`clientauth` を使う）で 5 と並行できる。7 は 4 と 6 の後。8 は 7 の後。9 は 6〜8 の後。10〜11 は 9 の後。

### M4a で明示的に先送りするもの

- Token Exchange（RFC 8693）と RAR（RFC 9396）。M4b（ADR-0011）
- mTLS（RFC 8705）。FAPI 2.0 は DPoP か mTLS のどちらかでよく、コアに TLS の扱いを持ち込まない
- resource 単位の送信者拘束の必須化（`Config.Resources`）。Profile `fapi` で足りる。要望が出た時点で足す
- Resource Server 側の DPoP nonce の既定有効化。`resourceserver` に任意機能として置くだけにする
- `request_uri` を Client が自前でホストする JAR（RFC 9101）。PAR の `request_uri` のみ受ける
- FAPI 2.0 Message Signing（JAR / JARM）。P3
- EdDSA（FAPI 2.0 §5.4.1 が許す 3 つ目の方式）。PS256 / ES256 で足りる
- Rotation しない Refresh Token の失効伝播以外の運用機能（寿命の延長など）。Family の寿命まで使う単純な形にとどめる
