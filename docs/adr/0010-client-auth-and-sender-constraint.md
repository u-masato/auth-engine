# ADR-0010: クライアント認証と送信者拘束（private_key_jwt・PAR・DPoP・FAPI Profile）

- 状態: **草案**（2026-10-25。M4a の着手前に合意する論点 1〜4 を議論し、その結果を書き起こした。合意後に「採用」へ更新し、実装後に末尾へ「実装結果」を追記する）
- 日付: 2026-10-25

## 文脈

M4（P2）は Token Exchange、DPoP、PAR、`private_key_jwt`、RAR の 5 つで、M3 より大きい。これを 2 つのマイルストーンに分ける。

| MS | 範囲 | 到達点 |
| --- | --- | --- |
| M4a | `private_key_jwt` → PAR → DPoP | クライアント認証と送信者拘束がそろう。FAPI 2.0 Security Profile（PAR + PKCE + `private_key_jwt` + DPoP）の AS 要件を満たし、そのプランを Conformance Suite で回せる |
| M4b | Token Exchange → RAR | エージェント間の委譲と、細かい権限の表現（ADR-0011 で決める） |

分ける一番の理由は、M4a を終えると適合性を示す手段ができることである。M2 では PKCE 必須のために Basic OP 認定を見送り、[conformance.md](../conformance.md) に「PKCE を使うプロファイル（FAPI 2.0 など）で示す」と記録した。M4a はそれを実行できる状態を作る。

順番の理由:

- `private_key_jwt`（RFC 7523）は土台である。PAR の confidential クライアント認証と、M3 で先送りにした CIMD Client の `private_key_jwt`（ADR-0008 §5）が、どちらもこれを前提にする。
- PAR（RFC 9126）は、ADR-0003 の「Txn を `/authorize` より前に作る」の形で既存の状態機械に乗る。[specifications.md](../specifications.md) も「P2 の中では早めに」としている。
- DPoP（RFC 9449）は影響範囲が広い。トークンの記録（`cnf.jkt`）、両 Adapter のスキーマ、Introspection、`resourceserver` の Proof 検証に手が入る。

本 ADR は、M4a の着手前に合意が要る 4 つの論点に答える。

1. 認証方式を Client ごとに選べるようにするか（ADR-0004 §3・§5 との関係）
2. Client の鍵は `jwks` だけにするか、`jwks_uri` も受け付けるか
3. リプレイ対策の記録（クライアントアサーションと DPoP Proof の `jti`）をどこに置くか
4. DPoP の範囲（nonce、必須化の単位）。FAPI 2.0 Security Profile の AS 要件（PAR 必須、DPoP 必須、Refresh Token Rotation なし、`private_key_jwt` のみ）をどう受けるか

確認した FAPI 2.0 Security Profile（final）の AS 要件のうち、本 ADR に関わるもの:

- §5.3.2.1: confidential クライアントのみ。送信者拘束された Access Token のみ発行（DPoP または mTLS）。クライアント認証は `private_key_jwt` または mTLS。クライアントアサーションの `aud` は発行者識別子を受理する。**Refresh Token Rotation は例外的な事情がなければ使わない**。DPoP の nonce は任意（may）。認可コードの寿命は 60 秒以内。DPoP を使うなら認可コードの DPoP 鍵への拘束（RFC 9449 §10）をサポートする。JWT の `iat` / `nbf` は未来 10 秒までは受理し、60 秒を超える未来は拒否する。
- §5.3.2.2: `response_type=code` のみ。クライアント認証を伴う PAR をサポートし、**PAR を使わない認可要求を拒否**する。クライアント認証のない PAR を拒否。PAR に `redirect_uri` 必須。PKCE S256 必須。`iss` を返す（RFC 9207。実装済み）。`request_uri` の寿命は 600 秒未満。
- §5.4.1: JWS の署名アルゴリズムは PS256、ES256、EdDSA のみ。RS256 は使えない。RSA は 2048 bit 以上。

## 決定

### 1. 認証方式は Profile が許す集合の中から、登録時の資格情報で決める（論点 1）

ADR-0004 §3 は「`token_endpoint_auth_method` は Profile が決める」としている。これを「許す集合を Profile が決め、その中のどれを使うかは登録時に渡した資格情報で決まる」と読み替える。§1 の表はすでに Web を「`client_secret_basic`（`client_secret_post` も受理）」、Machine を「P2 で `private_key_jwt` 追加」と書いており、Profile が複数方式を持つことを織り込んでいた。§5 が禁じるのは安全でない組み合わせを個別フラグで開けることであり、confidential クライアントが共有シークレットか非対称鍵かを選ぶのはどちらも安全な選択である。

- **方式のフィールドは置かない。** Client が持つのは資格情報だけ（`SecretHash`、新設の `JWKS` / `JWKSURI`）。コンストラクタがどれか 1 つだけが入っている状態を保証する。シークレットがあれば `client_secret_basic` / `client_secret_post`、鍵があれば `private_key_jwt`、どちらもなければ `none`。「方式」と「資格情報」を別々に持つと食い違いが起きうるので片方だけにする。`AcceptsAuthMethod(m)` は「Profile が許す集合に含まれ、かつ対応する資格情報を持つ」で判定する。
- **Profile ごとの許す集合。**

  | Profile | 許す集合 | 選び方 |
  | --- | --- | --- |
  | Web / Web Legacy / Machine | シークレット、`private_key_jwt` | 登録時に鍵を渡すか渡さないか |
  | Native | `none` | 選択なし |
  | MCP | `none`、`private_key_jwt` | CIMD 文書の `token_endpoint_auth_method` と `jwks` / `jwks_uri`（CIMD §4.1、ADR-0008 §5 の予約） |
  | FAPI（§7） | `private_key_jwt` | 選択なし |

- **コンストラクタ。** `WebParams` / `MachineParams` に `JWKS` と `JWKSURI` を足す。`Secret` と鍵の同時指定、`JWKS` と `JWKSURI` の同時指定（RFC 7591 §2）はエラー。鍵を渡したらシークレットは生成せず、戻り値の `Secret` は空。鍵は構築時に `keys` で検証する（公開鍵のみ、`kid` が一意、署名用途）。`keys` は他のコアパッケージを import しない葉なので、`client` → `keys` の依存は ADR-0007 の向きを崩さない。
- **MCP Client が鍵を持っても Profile 規則表の `confidential` は変えない。** 表の `confidential` は「共有シークレットを持つか」の意味で使われている（`client.go`）。鍵を持つ MCP Client の Refresh Token の扱いは §6 の DPoP の規則（public Client として鍵に拘束）に従う。
- **Discovery.** `token_endpoint_auth_methods_supported` に `private_key_jwt` を足し、`token_endpoint_auth_signing_alg_values_supported` を出す（RFC 8414 §2）。
- **変えないもの。** Interaction API（認証方式は同意画面に出ない）。`examples` の `console` の登録フォームには「シークレット / 鍵」の選択を足す。

### 2. クライアントアサーションの検証（RFC 7523 §3、RFC 7521 §4.2）

- `client_assertion_type` は `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` のみ。
- `iss` と `sub` はどちらも `client_id` に一致。フォームの `client_id` は任意だが、あれば一致すること。
- `aud` は**発行者識別子のみ**を受理する。トークンエンドポイントの URL は受理しない。FAPI 2.0 §5.3.2.1 と、改訂中の RFC 7523bis が発行者識別子に寄せる方向に合わせる。
- `exp` 必須。`iat` から `exp` までの幅に上限を置く（既定 5 分、設定で変更可）。`iat` / `nbf` は未来 10 秒まで許容（FAPI 2.0 §5.3.2.1）。
- `jti` 必須。重複は §5 の記録で弾く。
- `alg` は許可リスト（PS256、ES256、RS256）。`none` と HMAC 系は拒否。`kid` で鍵を選び、`kid` がなければ `alg` が合う鍵が 1 つのときだけ試す。FAPI Profile（§7）の Client は RS256 を拒否する。
- 失敗理由は区別せず `invalid_client`（既存のシークレット認証と同じ。クライアント列挙を助けない）。シークレットとアサーションの同時提示は、既存の Basic + フォームと同じく `invalid_request`（RFC 6749 §2.3）。

### 3. 認証ロジックは `clientauth` パッケージに置く

今の `token/clientauth.go` を新しい文脈パッケージ `clientauth` に出す。トークンエンドポイントと PAR（§8）が同じ認証を行い、`token` の中にあると `authorization` が `token` を import することになるため。`clientauth.Service` は `client.Resolver`、鍵の取得器（§4）、`jti` を記録する `clientauth.Store`（§5）を持つ。HTTP 層は資格情報の取り出し（Basic、フォーム、`client_assertion`）だけを行い、判断は `clientauth` に書く。

### 4. 鍵は `jwks` と `jwks_uri` の両方を受け、取得器は `keys` に 1 つ置く（論点 2）

- **両方受ける。タスクは分ける。** `jwks` は `private_key_jwt` と同じタスクに含め、`jwks_uri` はその次のタスクにする。Conformance Suite は鍵を直接登録できるので、`jwks` だけで FAPI の実行に進める。`jwks_uri` が要るのは鍵を回す運用と CIMD の MCP Client である。
- **取得器は `keys` に 1 つ置き、共用する。** `resourceserver/jwt.go` の JWKS キャッシュ（`keySet`）を `keys` に移し（仮に `keys.RemoteSet`）、`resourceserver.JWTVerifier` と `clientauth` の両方がそれを使う。振る舞いは今のものをそのまま仕様にする: `Cache-Control: max-age` を [1 分, 24 時間] で尊重、未知の `kid` で再取得しその間隔を間引く（1 分）、取得失敗時は手元の鍵で続け、手元に鍵がなければ fail-closed。`resourceserver` の既存テストが変わらないことを移設の確認にする。
- **接続先の制限。** `https` のみ、リダイレクト追従なし、サイズ上限（既定 64 KB。RSA 2048 の JWK は 1 本 500 バイト前後）、タイムアウト、特殊用途アドレスの拒否。`keys` 自体はポリシーを持たず `*http.Client` を受け取るだけにし、SSRF 対策の Transport は呼び出し側が注入する。
- **SSRF 対策の Transport の置き場。** `cimd.NewTransport` と接続先アドレスの検査を `internal/safehttp`（名前は仮）に移し、`cimd` と `clientauth` の両方から使う。`cimd.NewTransport` は薄い委譲として残し、[embedding.md](../embedding.md) の手順を壊さない。
- **キャッシュの単位は URL。** `clientauth` が `jwks_uri` ごとに取得器を持ち、件数上限と期限で追い出す。Client ID ではなく URL を鍵にするのは、CIMD 文書の再取得で `jwks_uri` が変わったときに自然に新しい鍵へ切り替わるため（CIMD §8.4.1）。インラインの `jwks` は Client オブジェクトに載っているので文書の再取得で更新される。登録時に先回りして取得はせず、最初の認証で取る。
- **CIMD Client の `jwks_uri` の信頼。** `client_id` との同一 origin は求めない（CIMD draft-02 に規定がなく、§8.2 の例も鍵を別サービスで管理する構成を想定している）。代わりに、文書 URL に適用している `cimd.TrustPolicy` を `jwks_uri` のホストにも適用する。ドメイン許可リストを使う運用で、鍵の配信元だけが許可外になることを防ぐため。登録済み Client の `jwks_uri` は構築時に `https` の絶対 URL であることだけ検証する。
- **取得した鍵の扱い。** 公開鍵のみ（秘密鍵成分があれば文書ごと拒否）、`kid` の重複は拒否、`use: enc` の鍵は無視。再取得しても `kid` が見つからなければ `invalid_client`。
- **設定。** 取得のタイムアウト、サイズ上限、キャッシュの上下限と件数は `cimd.Config` と同じ項目になる。`Engine.Config` で 1 つの「外部取得」設定にまとめるか別に持つかは、実装時に embedding.md の読みやすさで決める。

### 5. `jti` のリプレイ記録は Store Port の 1 メソッドで行う（論点 3）

プロセス内メモリでは複数インスタンスで防げないので、Store に置く。

- **Port メソッドは 1 つ。** `RecordJTI(ctx, hash string, expiresAt time.Time) error`。未登録なら挿入して nil、既にあれば `storage.ErrAlreadyExists`。読み出しや削除は置かない。ADR-0005 §2 の表に 1 行足す形で、実現は「`INSERT`、一意制約違反を `ErrAlreadyExists` に写像」。
- **定義は使う側の文脈に置き、Adapter の実装は 1 つ。** `clientauth.Store` と `dpop.Store`（§6）が同じシグネチャの `RecordJTI` をそれぞれ宣言する。Go は同一シグネチャのメソッドを持つ interface を埋め込めるので `authengine.Store` の合成はそのまま通り、Adapter は 1 つのテーブルで両方を満たす。ADR-0007 の「使う側の文脈で定義する」は崩れない。
- **鍵は用途・発行者・`jti` の組の SHA-256（16 進）。** 用途は `client_assertion` と `dpop`、発行者はアサーションでは `client_id`、DPoP Proof では `jkt`。RFC 7523 §3 の `jti` の一意性は発行者単位なので、別の Client が同じ文字列を使っても衝突しない。ハッシュにするのは列幅を固定し `jti` の長さを気にしないためで、秘密値ではないので定数時間比較は要らない。組の作り方は `internal/` の小さい関数に置き、両文脈で共有する。
- **検証の順序。** 署名とクレームの検証を通したあとに記録し、記録が成功したときだけ受理する。未認証の要求で表を膨らませないためと、同じアサーションが同時に 2 件来たとき片方だけが通るため。Store がエラーを返したら受理せず内部障害（500）にする。
- **期限。** アサーションは `exp` に時刻ずれの許容を足した時刻、DPoP Proof は受理する時刻幅の終端。期限が過ぎた行が残っていても同じ鍵が来たら重複として拒否する。期限切れを再利用可能にする分岐は作らない。
- **掃除は `Store.Purge` に乗せる。** 新しいスケジューラ契約は増やさない。
- **保存。** 表 `replay_ids(hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)` と `expires_at` の索引。`storage/memory` は期限付きの map。`storagetest` に、初回は成功・2 回目は `ErrAlreadyExists`・`Purge` で期限切れだけ消える・同じ鍵の同時記録でちょうど 1 件だけ成功する、の 4 ケースを足す。
- **Resource Server 側は別。** `resourceserver` は Store を持たないので、Proof の `jti` 検知は差し替え可能な小さい interface にし、既定はプロセス内の件数・期限つきキャッシュとする。複数インスタンスでは防げないことと、nonce で窓を狭める推奨を文書に書く（RFC 9449 §11.1）。

### 6. DPoP（RFC 9449）

- **Proof が提示されたら拘束する。** FAPI Profile（§7）以外では DPoP は要求ごとの任意で、Proof があれば拘束し、なければ従来の Bearer。既存 Profile の挙動は変わらない。
- **拘束の記録。** `Family.JKT`（Refresh Token の拘束。public Client で Proof があるときだけ。RFC 9449 §5 のとおり confidential の Refresh Token は鍵に拘束しない）と `AccessToken.JKT`（トークンごと。Refresh 時はそのときの Proof の鍵）。値は JWK Thumbprint（RFC 7638、SHA-256、base64url）。Refresh 時は `Family.JKT` があれば同じ鍵の Proof を要求する。
- **認可コードの拘束（§10、FAPI で必須）。** `dpop_jkt` を `Request` と `AuthorizationCode` に持ち、Code 交換時に Proof の鍵と照合して違えば `invalid_grant`。PAR では本体の `dpop_jkt` と `DPoP` ヘッダの両方を受け（§10.1 で両方 MUST）、両方あって不一致なら拒否。Interaction App には出さない。
- **外に見える形。** トークン応答の `token_type` は `DPoP`（§5）。JWT Access Token は `cnf.jkt`（§6.1）。Introspection はトップレベルに `jkt` と `token_type: DPoP`（§6.2）。Discovery に `dpop_signing_alg_values_supported`。Proof のエラーは `invalid_dpop_proof`（400）。Proof の `alg` 許可リストは §2 と同じ PS256 / ES256 / RS256。
- **Proof の検証と受理時刻幅。** §4.3 の手順どおり（`typ=dpop+jwt`、非対称 `alg`、`jwk` に秘密鍵成分がない、署名、`htm`、`htu`（クエリとフラグメントを除いて正規化比較）、`nonce`、`iat`、`ath`）。`iat` は過去 5 分、未来 10 秒まで。§5 の `jti` 記録の期限は `iat` + 5 分 + 許容ずれ。
- **nonce は AS 側で実装し、発行は設定で有効にする（§8）。** 方式はステートレスで、`Config.DPoP.NonceSecret` と時刻の窓（5 分）の HMAC。現在と直前の窓を受理する。秘密が設定されていれば、トークンエンドポイントは nonce のない Proof に `use_dpop_nonce`（400）と `DPoP-Nonce` ヘッダを返し、成功応答にも次の nonce を載せる（§8.2）。設定がなければ Proof は `iat` の窓だけで受理する。RFC 9449 §8 も FAPI も nonce は任意なので既定を要求にはしない。複数インスタンスでは秘密を共有しないと nonce が通らないため、設定なしで常時発行する形は採らない。RS 側（§9）は `resourceserver` に任意機能として置き、既定は無効。
- **置き場。** Proof の解析と検証、Thumbprint、nonce は新しい文脈パッケージ `dpop` に置き、`token`・`authorization`（PAR）・`resourceserver` が使う。`resourceserver` は `Engine` に依存しないまま `dpop` だけを import する（`keys` を import している今と同じ関係。`scripts/check-core-deps.sh` の検査対象に加える）。`jti` の記録先は `dpop.Verifier` が受け取る小さい interface にし、AS 側は Store、RS 側はプロセス内キャッシュを渡す。Thumbprint の計算は `keys` にある非公開関数を公開する。
- **Resource Server 側。** `Authorization: DPoP <token>` と `DPoP` ヘッダを受け、Proof を `ath` 付きで検証し、トークンの `jkt`（Introspection の `jkt` か JWT の `cnf.jkt`）と一致することを確認する。拘束されたトークンを Bearer として提示されたら拒否（§7.1）。未提示・無効は `WWW-Authenticate: DPoP algs="..."`（§7.1）。
- **CIMD 文書の `dpop_bound_access_tokens`（§5.2）。** `true` なら、その MCP Client には Proof のないトークン要求を拒否する。Client 側が自分を厳しくする宣言であり、緩める方向のフラグではないので受け入れる。

### 7. FAPI 2.0 の要件は Profile `fapi` として束ねる（論点 4）

FAPI 2.0 が AS に求めるものは「PAR 必須」「DPoP 必須」「Refresh Token Rotation なし」「`private_key_jwt` のみ」「認可コード 60 秒以内」が一組になっている。PAR と Rotation は resource の性質ではなく Client の性質であり、束で来る要件を個別フラグで開けるのは ADR-0004 §5 が禁じた形である。同じ §5 が「新しい要求には Profile を足して応じる」と決めており、ADR-0009 の `web-legacy` も前例になる。

| 項目 | FAPI |
| --- | --- |
| Client 種別 | confidential |
| grant_types / response_types | `authorization_code`, `refresh_token` / `code` |
| PKCE | S256 必須 |
| token_endpoint_auth_method | `private_key_jwt` のみ。`alg` は PS256 / ES256（RS256 は拒否。FAPI 2.0 §5.4.1） |
| redirect_uri 照合 | `https` の完全一致。開発用の緩和（`AllowInsecureLocalhost`）なし（§5.3.2.2-8） |
| PAR | 必須。PAR を経由しない認可要求は `invalid_request`（§5.3.2.2-3）。PAR に `redirect_uri` 必須（§5.3.2.2-6） |
| DPoP | 必須。Proof のないトークン要求は `invalid_dpop_proof`。`dpop_jkt` による認可コードの拘束をサポート（§5.3.2.1-12） |
| Refresh Token | 発行する。**Rotation しない**（§5.3.2.1-9）。同じトークンを Family の寿命まで使う |
| 認可コード寿命 | `Config.CodeTTL` に関係なく 60 秒を上限（§5.3.2.1-11） |
| ID Token | `openid` 要求時に発行。署名は ES256 / PS256（既定 ES256） |
| `resource` | 任意 |
| `response_mode` | `query` のみ |

- Rotation を止める根拠: RFC 9700 §4.14 は confidential クライアントの Refresh Token にはクライアント認証による拘束で足りるとしており、`private_key_jwt` で認証する `fapi` はこれを満たす。public Client（Native / MCP）は DPoP で拘束されても Rotation を続ける。どちらも許される中で、既存の挙動を変えないほうを選ぶ。
- Port は `RotateRefreshToken` の `next` に nil を許し、「旧トークンを active のまま残して Access Token だけ足す」意味にする（ADR-0005 §2 の表を修正）。
- Profile 規則表に `requirePAR` `requireDPoP` `rotateRefreshToken` `maxCodeTTL` の列を足し、`fapi` 以外は今の値を書く。
- コンストラクタは `client.NewFAPI(FAPIParams, now)`。鍵（`JWKS` か `JWKSURI`）は必須、`Secret` と `AllowInsecureLocalhost` の項目はない。
- 名前は FAPI 2.0 Security Profile に適合する confidential Client であることを示す `fapi`（値は `"fapi"`）。業種（金融）ではなく満たす要件の集合を指す。

### 8. PAR（RFC 9126）

PAR の設計は本 ADR の論点ではないが、§1〜§7 から決まる点を記録する。詳細は実装タスクで決め、本 ADR の実装結果に記録する。

- `POST /par`（RFC 9126 §2）で認可要求パラメータを受け、ADR-0003 の Txn を `/authorize` より前に作る。応答の `request_uri` は `urn:ietf:params:oauth:request_uri:` + 256 bit 乱数、`expires_in` は 60 秒（FAPI 2.0 §5.3.2.2-12 の 600 秒未満を満たす）。`request_uri` の値はハッシュで保存し、`/authorize` で 1 回だけ消費する（CAS）。
- confidential Client は §3 の `clientauth` で認証する。public Client は `client_id` のみ。認証のない confidential の PAR は `invalid_client`。
- `/authorize` に `request_uri` が来たら、ほかのパラメータは `client_id` 以外無視する（RFC 9126 §4）。`fapi` では `request_uri` のない認可要求を拒否する（§7）。
- Discovery に `pushed_authorization_request_endpoint` を出す。`require_pushed_authorization_requests` は Profile ごとの性質なので Discovery には出さない（Client ごとの PKCE 要否を出さないのと同じ。ADR-0009 §6）。
- `DPoP` ヘッダと `dpop_jkt` の扱いは §6。

## 検討した代替案

1. **認証方式を Client の明示的なフィールドにする。** 資格情報と食い違う状態（鍵を持つのに `client_secret_basic` など）を禁じる検証が別に要る。資格情報から導けば不正な状態が存在しない（§1）。
2. **`jwks` だけを受ける。** M4a の到達点（FAPI の実行）には足りるが、鍵の回転と CIMD の MCP Client（CIMD §8.2 の例は `jwks_uri`）に対応できない。両方受け、タスクを分ける（§4）。
3. **`jwks_uri` の取得器を `clientauth` に新しく書く。** `cimd`（文書）と `resourceserver`（JWKS）に続く 3 つ目の取得実装になる。「参考実装のわかりやすさ」に反するので `keys` に 1 つ置いて共用する（§4）。
4. **`jti` の記録をプロセス内メモリにする。** 複数インスタンスで防げない。
5. **`jti` を `(kind, issuer, jti)` の生の列で一意制約にする。** `jti` の長さに上限が要り、行も長くなる。ハッシュ 1 列に劣る。
6. **送信者拘束の必須化を resource の設定（`Config.Resources`）に置く。** M3 の「Access Token の形式は resource ごと」と同型で一度は有力だったが、FAPI の要件には PAR 必須と Rotation なしが含まれ、これらは resource の性質ではない。要件を束ねて Profile にする（§7）。要望が出れば resource 単位の必須化を後から足せる。
7. **DPoP の必須化・PAR の必須化・Rotation の有無を Client のフラグにする。** ADR-0004 §5 が却下したエスケープハッチ。
8. **DPoP nonce を常時発行する。** 複数インスタンスで秘密を共有しないと nonce が通らず、クライアントの再試行が収束しない。設定で有効にする（§6）。
9. **mTLS（RFC 8705）。** FAPI 2.0 は DPoP か mTLS のどちらかでよい。コアに TLS の扱いを持ち込まない。
10. **Web Profile 全体の Rotation を止める。** 既存クライアントの防御が下がる。`fapi` に限る（§7）。

## 既存 ADR への影響

- ADR-0004 §1 の表に FAPI の列を足し、`token_endpoint_auth_method` の行を「許す集合」に書き換える。§2 の開放項目に「クライアント認証の資格情報（シークレットか鍵か）」を足す。§3 を「許す集合を Profile が決める」に改める。§4 に `NewFAPI` と `JWKS` / `JWKSURI` を足す。§5 に「ADR-0010 で FAPI を Profile として追加した」と追記する。§6 の「`private_key_jwt` の CIMD Client は M4 で受理する」を本 ADR への参照にする。
- ADR-0005 §2 の表に `RecordJTI` を足し、`RotateRefreshToken` に `next == nil` の意味を足す。§6 の契約テストに `replay_ids` と Rotation なしのケースを足す。
- ADR-0006 §4「Refresh Token Rotation」に `fapi` の例外を書く。§1 の JWT Access Token に `cnf.jkt` を足す。
- ADR-0007 に `clientauth`、`dpop`、`internal/safehttp`、`keys` の取得器を足す。`resourceserver` の依存先に `dpop` を加える。
- ADR-0008 §5「`private_key_jwt` の CIMD Client は M4」を本 ADR への参照にする。
- ADR-0009 末尾の「roadmap 上の位置」を「M4a のタスク 1」にする。
- CLAUDE.md の不変条件「Refresh Token Rotation」を「`fapi` Profile を除く」と限定する。「JOSE の利用は `keys` に閉じる」は変えない（`clientauth` / `dpop` は `keys` の `Verify` を使う）。

## 影響

- Interaction API の契約変更: `client.profile` に `fapi` が増える（[interaction-api.md](../interaction-api.md)）。同意画面の扱いは `web` と同じでよい。
- 保存形式: clients に `jwks` `jwks_uri`、families に `jkt`、access_tokens に `jkt`、authorization_codes に `dpop_jkt`、PAR の `request_uri` の記録、`replay_ids` 表。SQLite / PostgreSQL に migration を足し、番号は各 Adapter の次の番号を使う（M3 タスク 2 の教訓）。
- `keys`: PS256 の生成と検証（FAPI 2.0 §5.4.1）、Thumbprint の公開、取得器（`RemoteSet`）。
- `resourceserver`: `JWTVerifier` の JWKS 取得を `keys` の取得器に委譲（挙動は変えない）、DPoP の受理。
- examples: `cmd/server` の Profile の switch と `console` に `fapi` と「シークレット / 鍵」の選択、`oauthclient` に `private_key_jwt` と DPoP、PAR。
- Conformance: FAPI 2.0 Security Profile のプラン（`private_key_jwt` + DPoP の variant）を回し、結果を [conformance.md](../conformance.md) に記録する。Basic OP の再実行（ADR-0009）も同じ文書に記録する。
- テスト: §1〜§8 の各分岐と、既存 Profile の挙動が変わらないこと（`profile_test.go` の表と `authorization` / `token` の回帰）。

## 未決・確認事項

合意の前に確かめる、または実装時に決める点。

1. Conformance Suite の FAPI 2.0 プランが Refresh Token の Rotation をどう扱うか（Rotation する AS を不合格にするか）。§7 の判断には影響しないが、conformance.md の想定結果に書く。
2. `Config.DPoP.NonceSecret` の名前と、`cimd.Config` と鍵取得の設定を 1 つにまとめるか（§4、§6）。embedding.md を書くときに決める。
3. PAR の `request_uri` の保存場所（Txn に列を足すか、別の表にするか）。§8 の実装タスクで決める。
