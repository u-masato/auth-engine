# ADR-0008: MCP 連携（Resource Indicators、MCP Client Profile、CIMD、JWT Access Token、Resource Server ミドルウェア）

- 状態: 採用（2026-10-24 合意）。**実装済み（2026-10-25、M3 タスク 1〜8）**。計画からの差分は末尾の「実装結果」に記す
- 日付: 2026-10-24（2026-10-25 更新）

## 文脈

M3（P1）は MCP クライアント・MCP サーバーから本エンジンを使えるようにする（[準拠仕様一覧](../specifications.md) P1、[roadmap](../roadmap.md)「M3 のタスク順序」）。基準は [MCP Authorization Specification（2026-07-28）](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) と [CIMD draft-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)。MCP 仕様が認可サーバーに課す要件は次の 4 つに整理できる。

1. クライアントは `resource`（RFC 8707）を必ず送る。認可サーバーはトークンを対象リソースに結びつけ、MCP サーバーは Audience が自分であることを検証する。
2. クライアントは事前登録なしに接続したい。CIMD（HTTPS URL を `client_id` とする）が SHOULD、Dynamic Client Registration（RFC 7591）は非推奨。
3. MCP サーバーは RFC 9728 の Protected Resource Metadata を公開し、401 / 403 の `WWW-Authenticate` で認可サーバーの所在と必要 scope を伝える。
4. PKCE S256、`iss` パラメータ（RFC 9207）、public クライアントの Refresh Token Rotation。これらは M1 / M2 で満たしている。

P0 の ADR は、これらのために `client.Resolver`、`token.Issuer` の差し替え点と、Client Profile への「MCP Client」追加を予約している（ADR-0004 §6、ADR-0006 §1、ADR-0007 §4）。本 ADR はその予約を実体化し、既存 ADR の記述を超える判断を決める。以下で「MCP 仕様」は 2026-07-28 版、「CIMD」は draft-02 の節番号を指す。

## 決定

### 1. Resource Server の登録は静的設定（Store に置かない）

```go
authengine.Config{
    Resources: []resource.Resource{{
        URI:               "https://mcp.example.com",
        Name:              "Example MCP Server",
        AccessTokenFormat: resource.FormatJWT, // 既定は FormatOpaque
        AccessTokenAlg:    "ES256",            // FormatJWT のときだけ。既定は RS256（RFC 9068 §4）
        Scopes:            []string{"files:read", "files:write"},
    }},
}
```

- Resource Server はデプロイ単位で決まり、Client のように実行時に増えない。Store と migration を増やさず、Client と同じ「構造体で渡す」方針（ADR-0002）に揃える。
- `resource.Resource.URI` は RFC 8707 §2 の resource indicator: 絶対 URI、fragment なし、query は持たないことを推奨。比較は scheme と host を小文字化した上での文字列一致（MCP 仕様「Canonical Server URI」が大文字の受理を SHOULD とするため）。末尾スラッシュの有無は区別する。
- 要求された `resource` が設定にないものは `invalid_target`（RFC 8707 §2）。認可要求では「リダイレクトしてよいエラー」（Client と redirect URI の検証後に判定するため）。
- `Scopes` は省略可。指定があれば、その resource 向けのトークンに付く scope はこの範囲に限る（範囲外は `invalid_scope`）。ただし OIDC の標準 scope（`openid` `profile` `email` `address` `phone` `offline_access`）は認可サーバー自身（ID Token、UserInfo、Refresh Token）に向けたものなので制限を受けない。これがないと MCP クライアントが `openid` と resource 向け scope を同時に要求できない。複数 `resource` ではいずれかの resource が許せばよい（各 Resource Server は関係ない scope を無視する）。
- 複数インスタンス構成で設定が食い違う運用事故は、Store に置いても防げない（設定の配布の問題）。必要になれば `resource.Store` を足す。

### 2. 登録済み Client の `resource` 制限

- ADR-0004 §2 で P1 に予約した「許可する `resource`」を `Client.Resources []string` として開放項目に加える。
- 空なら設定済み（§1）の全 resource を要求できる。指定があれば、その範囲に限る。範囲外は `invalid_target`。
- CIMD で識別する Client（§4）は事前登録がないので、常に設定済みの全 resource を要求できる。resource ごとの制限が必要なら `cimd.TrustPolicy`（§5）で `client_id` と resource の組を判定する。
- `resource` なしの要求は従来どおり受理する。Access Token の Audience は空で、AS 自身のリソース（UserInfo）向けとみなす。

### 3. `resource` はトークン発行まで引き継ぎ、Access Token の形式は resource ごとに決める

#### 引き継ぎ

| 段階 | 保存先 | 規則 |
| --- | --- | --- |
| 認可要求 | `Transaction.Request.Resource` | §1 と §2 で検証。M1 では保存のみだった |
| Code 発行 | `AuthorizationCode.Resource` | Txn の値をそのまま |
| Code 交換 | `Family.Audience`, `AccessToken.Audience` | `/token` の `resource`（RFC 8707 §2.2）は Code の `Resource` の部分集合。省略なら Code の全部 |
| Refresh | `AccessToken.Audience` | `/token` の `resource` は Family の `Audience` の部分集合への縮小。省略なら Family の全部。Family 自体は変えない（scope 縮小と同じ扱い） |
| `client_credentials` | `Family.Audience`, `AccessToken.Audience` | Client の許可範囲（§2） |

- Introspection 応答に `aud`（RFC 7662 §2.2）を載せる。Resource Server は `aud` に自分が含まれることを確認する。
- UserInfo は `openid` scope があれば `aud` に関わらず受理する。UserInfo は AS 自身のリソースであり、OIDC Core §5.3 は Access Token の Audience を制限しない。
- 複数の `resource` を 1 つのトークンに載せることは RFC 8707 §2 のとおり許す（`aud` は配列）。MCP クライアントは 1 つしか送らない。

#### 形式

- Access Token の形式（Opaque / JWT）は `resource.Resource.AccessTokenFormat` で決める。形式は Resource Server がローカル検証するか Introspection するかの都合であり、Client の属性ではない。CIMD Client は事前登録がないため Client 単位では決められない、という事情もある。
- `resource` なしの要求は Opaque（既定）。複数の `resource` を要求し形式が揃わない場合は `invalid_target`（1 つのトークンは 1 つの形式）。
- JWT は RFC 9068: ヘッダー `typ: at+jwt`、Claims は `iss` `sub` `aud` `exp` `iat` `jti` `client_id` `scope`（§2.2.1、§2.2.3）と、認可コード由来なら `auth_time` `acr` `amr`（§2.2.1）。署名は `keys` の RS256 / ES256（ADR-0002、JOSE の利用は `keys` に閉じる）。`scope` は空白区切り文字列。
- **JWT でも Store に `AccessToken` の行を持つ。** `Hash` はトークン文字列全体の SHA-256 で、Opaque と同じ。これにより Introspection と Revocation は形式に依らず同じ経路で動き、`/revoke` に JWT を渡せば `active:false` になる。
- ただし Resource Server が JWT をローカル検証する限り、失効は `exp` まで伝播しない。これは ADR-0006 §1 で Opaque を既定にした理由そのものであり、JWT を選ぶ resource は短い `AccessTokenTTL` の Client と組み合わせることを文書で求める。

`token.Issuer` は次の形で実体化する（ADR-0007 §4 の予約）。

```go
// token/issuer.go
type Issuer interface {
    // Issue はトークン平文と、Store に保存する記録を返す。
    Issue(ctx context.Context, in IssueInput) (plaintext string, rec *AccessToken, err error)
}
```

Opaque 実装は `token` パッケージ、JWT 実装は `oidc` と同様に `keys` を使う実装としてコアに置く。`Engine` が resource の設定を見て 1 要求ごとに選ぶ。

### 4. MCP Client Profile

ADR-0004 §1 の表に 4 列目を加える。

| 項目 | MCP Client |
| --- | --- |
| Client 種別 | public |
| 識別 | CIMD の HTTPS URL を `client_id` とする（§5）。Store に事前登録することもできる（CIMD §7） |
| grant_types | `authorization_code`, `refresh_token` |
| response_types | `code` |
| PKCE | S256 必須 |
| token_endpoint_auth_method | `none`（`private_key_jwt` は M4 で追加。CIMD §4.1） |
| redirect_uri 照合 | CIMD 文書の `redirect_uris` と完全一致。http loopback はポート番号を無視（RFC 8252 §7.3）。`http://localhost` を許可する |
| `resource` | 必須。欠落は `invalid_request`（RFC 8707 は欠落のエラーを定めないため）。値の検証は §1 |
| Refresh Token | 発行する。Rotation 必須、再利用検知で Family 失効（MCP 仕様 Security Considerations「Token Theft」が public クライアントの Rotation を MUST とする） |
| ID Token | `openid` scope 要求時に発行 |
| `response_mode` | `query` のみ |

- `http://localhost` を許す点だけ Native Profile と異なる。MCP 仕様「Communication Security」は redirect URI を「`localhost` か HTTPS」と定め、CIMD 文書の例も `http://localhost:3000/callback` を使うため、拒否すると相互運用できない。RFC 8252 §8.3 の懸念（`localhost` の名前解決の乗っ取り）は残るので、Interaction API で redirect URI のホスト名を同意画面に出させる（§6）。
- ADR-0004 §5 の「個別フラグの開放はしない」は維持する。MCP 向けの緩和は Profile として固定する。

### 5. CIMD の Resolver

`client.Resolver`（ADR-0007 §4）を 2 つ重ねる。

```
client.ChainResolver{ store, cimd.Resolver }   // Store にあれば優先、なければ CIMD
```

#### 対象の判定（CIMD §3）

`https://` で始まり、path を持ち、userinfo と fragment を含まず、`.` / `..` のパスセグメントを含まない `client_id` だけを CIMD として扱う。それ以外の不明な `client_id` は従来どおり `storage.ErrNotFound`。Store が発行する `client_id` は `https://` で始めない（CIMD §7）。

#### 取得（CIMD §5、§8.6、§8.7）

| 項目 | 規則 |
| --- | --- |
| HTTP | `GET`、`Accept: application/json`。リダイレクトは追従せず、200 以外はエラー |
| 上限 | 本文 5 KB。上限に達したらエラー |
| タイムアウト | 既定 5 秒（`Config.CIMD` で変更可） |
| SSRF | 接続前に名前解決し、RFC 6890 の特殊用途アドレス（loopback、private、link-local、unspecified 等）へは接続しない。`AllowLoopback` は開発用で、本番では使わない |
| スキーム | `https` のみ |

#### 文書の検証（CIMD §4、MCP 仕様「Client Registration」）

- JSON であり、`client_id` `client_name` `redirect_uris` を含むこと。
- `client_id` は取得に使った URL と単純文字列比較で一致すること。
- `token_endpoint_auth_method` は省略か `none`。`client_secret` `client_secret_expires_at` を含む文書、`client_secret_*` や `private_key_jwt` を指定する文書は拒否（M4 で `private_key_jwt` を受理する）。
- `redirect_uris` の各要素は §4 の照合規則を満たすこと。
- `grant_types` `response_types` `scope` は Profile の固定値と矛盾しないことを確認するだけで、Profile を変えない。
- `client_uri` `logo_uri` `policy_uri` は Interaction App に透過する。`logo_uri` の事前取得（CIMD §8.3）はエンジンの責務にしない。

検証に通った文書から `client.NewMCP(doc)` で `Client` を組み立てる。失敗は `invalid_client`（認可要求では redirect できないエラー、ADR-0003 §2）。

#### キャッシュ（CIMD §5.2）

- プロセス内メモリ。HTTP の `Cache-Control: max-age` を尊重し、下限 1 分・上限 24 時間（`Config.CIMD` で変更可）。ヘッダーがなければ下限。
- エラー応答と不正な文書はキャッシュしない。
- 複数インスタンス構成でのキャッシュ共有は M3 では行わない。必要になれば `cimd.Cache` インターフェースの Store 実装を足す。

#### 信頼ポリシー（CIMD §8.4、MCP 仕様「Trust Policies」）

```go
type TrustPolicy interface {
    // Allow は client_id URL を受け入れるかを返す。拒否は invalid_client。
    Allow(ctx context.Context, clientID *url.URL) error
}
```

既定は全許可。ドメイン許可リスト、初回利用の警告などは利用者が実装する。

#### Discovery

`client_id_metadata_document_supported: true` を RFC 8414 / OIDC Discovery の両方のメタデータに載せる（CIMD §6、MCP 仕様「Advertising CIMD Support」）。CIMD を無効にした構成では載せない。

### 6. Interaction API の追加

`GET /transactions/{id}` に次を加える（契約変更。`docs/interaction-api.md` に明記）。

| フィールド | 内容 |
| --- | --- |
| `client.profile` | `mcp` を追加 |
| `client.client_uri` | CIMD 文書の `client_uri`。登録済み Client では空 |
| `request.redirect_uri` | 今回の認可要求で実際に使う redirect URI（全 Profile）。MCP 仕様「Localhost Redirect URI Risks」が同意画面でのホスト名表示を MUST とするため |

Interaction App への要請として、`profile` が `mcp` のときは `client_id`（URL）のホスト名と `redirect_uri` のホスト名を表示し、`redirect_uri` が localhost / loopback なら追加の注意書きを出すこと（SHOULD）を `docs/interaction-api.md` に書く。

Grant は `client_id` 文字列をキーにするので、CIMD Client の同意記録も既存の仕組みのまま動く。`client_id` URL を変えた Client は別の Client になる（CIMD §8.9）。

### 7. Resource Server 用ミドルウェアはコアの `resourceserver` パッケージ

- MCP サーバー（Resource Server）に組み込む net/http ミドルウェア。`Engine` に依存せず、別プロセスから単独で使う。依存は標準ライブラリと `keys`（JWT 検証）だけなので、別モジュールにする理由がない（ADR-0007 §3 の判断基準は依存の分離）。
- 提供するもの:
  1. RFC 9728 のメタデータ `GET /.well-known/oauth-protected-resource[/{path}]`。`resource` `authorization_servers` `scopes_supported` `bearer_methods_supported: ["header"]` `resource_name`。
  2. Bearer 検証。未提示・無効は 401 と `WWW-Authenticate: Bearer resource_metadata="...", scope="..."`（RFC 9728 §5.1、MCP 仕様「Scope Selection Strategy」）。scope 不足は 403 と `error="insufficient_scope"`、必要 scope、`resource_metadata`（RFC 6750 §3.1、MCP 仕様「Runtime Insufficient Scope Errors」）。
  3. `TokenVerifier` インターフェースと 2 実装。Introspection（RFC 7662。Machine Profile の資格情報で `/introspect` を呼ぶ）と JWT ローカル検証（AS メタデータから `jwks_uri` を得て `keys` で検証。`typ=at+jwt`、`iss`、`aud`、`exp`、`alg` 許可リスト。RFC 9068 §4、RFC 8725）。
  4. どちらの実装でも **`aud` に自分の resource URI が含まれること** を必須で確認する（MCP 仕様「Token Handling」「Access Token Privilege Restriction」）。これを無効にする設定は置かない。
  5. 検証済みの主体（`sub` `client_id` `scope` `aud`）を `context.Context` から取り出す補助。
- scope 階層（広い scope が狭い scope を含む）の解釈は MCP サーバーの方針であり、ミドルウェアはルートごとに与えられた必要 scope の包含だけを見る。
- MCP プロトコル自体（JSON-RPC、Streamable HTTP）は実装しない。

### 8. Dynamic Client Registration（RFC 7591）は実装しない

- MCP 仕様 2026-07-28 版で非推奨（MAY）。CIMD が「事前関係なし」の場面を満たす。
- 無認証の `registration_endpoint` はごみ登録の経路になり、Store の肥大化と `client_id` 枯渇の対策（レート制限、期限付き登録、Initial Access Token）が別途必要になる。参考実装として抱える価値が薄い。
- 旧クライアントとの相互運用で必要になった時点で、Initial Access Token 必須の形で再検討する。`registration_endpoint` はメタデータに載せない。

## 既存 ADR への影響

| ADR | 変更 |
| --- | --- |
| ADR-0001 §3 | 「Dynamic Client Registration（P1 で CIMD と併せて検討）」→ 本 ADR §8 で実装しないと決定 |
| ADR-0004 §1 | Profile 表に MCP Client の列を追加（本 ADR §4）。§2 の開放項目に `Resources` を追加（§2）。§6 の予約を実体化 |
| ADR-0006 §1 | 「JWT Access Token は Token Policy の選択肢」→ resource ごとの設定で選ぶ（§3）。JWT でも Store に行を持つ |
| ADR-0007 §1, §4 | コアに `resource` `cimd` `resourceserver` パッケージを追加。`client.Resolver` を Chain で合成、`token.Issuer` を Opaque / JWT の 2 実装で実体化 |
| ADR-0003 | 変更なし。Interaction API のフィールド追加は `docs/interaction-api.md` に反映する（§6） |

各 ADR への追記は M3 タスク 9（2026-10-25）で行った。記述が食い違う場合は本 ADR が優先する。

## 影響

- Access Token の記録に `Audience` が増え、Code と Client にも列が増える（SQLite migration `00003`〜`00005`、PostgreSQL migration `00002`〜`00004`。タスクごとに 1 本ずつ追加した）。`storagetest` に `resource` の引き継ぎを加える。
- `resource` を送ってきた既存 Client の挙動が変わる: M1 / M2 では黙って受理していたが、M3 からは設定にない `resource` は `invalid_target` になる。`Config.Resources` が空の構成では `resource` 付きの要求がすべて失敗する。これは意図したフェイルクローズで、README に書く。
- コアが net/http クライアントとして外部に接続する箇所が初めてできる（`cimd`）。SSRF 対策は `cimd` に閉じ、テストで特殊用途アドレスの拒否を網羅する。
- `resourceserver` は認可サーバーではなく Resource Server 側で動くコードなので、`httpapi` と混ぜない。`Engine` を import しないことを `scripts/check-core-deps.sh` で検査する。

## 実装結果（2026-10-25）

M3 タスク 1〜8 で本 ADR を実装した。経緯は [roadmap](../roadmap.md)「M3 の実施結果」、相互運用の結果は [mcp-interop.md](../mcp-interop.md)。計画から変えた点と、計画になかった判断を節ごとに記す。これらは本 ADR の決定の一部として読む。

| 節 | 差分 |
| --- | --- |
| §1 | `resource.Normalize` は RFC 8707 §2 の「絶対 URI」をそのまま採り、`https` に限定しない（`urn:` も受理。host を持たない `scheme:` だけの値は拒否）。`Resource.AccessTokenAlg`（RS256 / ES256、既定 RS256）を追加し、`Engine.New` は JWT の resource に対応する署名鍵が `Keys` にあることを起動時に確認する。`Scopes` の制限は OIDC の標準 scope を除外する（§1 本文に追記） |
| §2 | 計画どおり。fail-closed を 1 つ足した: 設定から外された resource を Code / Family が持っていると、`resource` 未指定でも `invalid_target` にする（設定変更後に古い Family で発行し続けない） |
| §3 | `token.Issuer` の実装は `OpaqueIssuer` / `JWTIssuer` と、形式で振り分ける `ByFormat` の 3 つ。`JWTIssuer` は `oidc` ではなく `token` パッケージに置いた（Access Token は OAuth の概念。`token` → `keys` の依存は循環しない）。`keys` に `SignTyped`（`typ` ヘッダ）を追加。Introspection の `aud` は常に配列で、`resource` なしのトークンでは省略する |
| §4 | `http://localhost` はポートまで完全一致。ポートを無視するのは loopback IP リテラル（RFC 8252 §7.3 の対象）だけ。CIMD 文書に `scope` がない MCP Client は scope の上限を持たない（`Client.Scopes` 空 = 制限なし。他 Profile では空は不正のまま）。`Client.ClientURI` を追加して Store にも保存する（URL 形式の `client_id` を事前登録する経路で値が落ちないようにする。SQLite migration `00005` / PostgreSQL `00004`）。MCP Client の `resource` 欠落は `invalid_request`（リダイレクト可） |
| §5 | SSRF 対策は「接続前に名前解決」ではなく、`net.Dialer.Control` で解決後の接続先アドレスを検査する（解決と接続の間に隙間がない）。プロキシは使わない。`cimd.NewTransport` を基にしない `HTTPClient` を渡すとこの保護が外れることを文書で求める。キャッシュは `no-store` / `no-cache` も下限（1 分）で保持し、件数上限（既定 1000）を持つ。解決できない `client_id` は `client.ErrUnresolvable` で返し、認可要求では理由付きの `invalid_request`（リダイレクトしない）、トークン要求では `invalid_client` に写す。`client.ChainResolver`（Store → CIMD）はタスク 4 で `client` に置いた |
| §6 | 計画どおり。Interaction API は `Store` ではなく `Engine.Clients`（Resolver）で Client を引く。デモの loginapp は redirect URI のホスト名を全 Profile で表示する（Native の loopback にも同じ注意書きが当てはまる） |
| §7 | `IntrospectionVerifier` は応答の `token_type` が `Bearer` でない（省略を含む）トークンを拒否する（本エンジンの Refresh Token は `token_type` を持たないので Bearer として持ち込めない）。`JWTVerifier` は署名検証の前に `alg` を許可リスト（既定 RS256 / ES256）で落とし、JWKS は `Cache-Control` を [1 分, 24 時間] で尊重、未知の `kid` では `MinRefresh` を過ぎていれば再取得する。検証方式の障害（認可サーバーに到達できない）は 503。クエリやフォームの `access_token`（RFC 6750 §2.2、§2.3）は受け付けない。`keys.ImportJWKS` を追加 |
| §8 | 計画どおり。`registration_endpoint` は出さない。MCP Inspector は `client_id_metadata_document_supported: true` を見て CIMD を使い、DCR を試みなかった |

計画になかったもの:

- デモ MCP サーバー（`examples/standalone/cmd/mcp-server`）に最小の MCP（Streamable HTTP の `initialize` / `ping` / `tools/list` / `tools/call`）を実装した。公式クライアントは認可後に `initialize` を送るので、接続まで確かめるには最小限が要る。コアには MCP プロトコルを置かない（§7 のとおり）。
- CIMD の `client_id` は https 必須なので、ローカルの文書配信は自己署名証明書を使う `cmd/cimd-host` にし、`cmd/server` に `-cimd-ca` を足した。TLS 検証を外す選択肢は作らない。
