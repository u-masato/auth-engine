# ADR-0009: PKCE を任意にする confidential Profile（Web Legacy）

- 状態: 採用（2026-10-25 合意）。**未実装**。実装後に末尾へ「実装結果」を追記する
- 日付: 2026-10-25

## 文脈

全 Profile で PKCE S256 を必須にしている（ADR-0001 §3、ADR-0004 §1・§5、RFC 9700 §2.1.1）。2026-10-24 に OpenID Foundation Conformance Suite の Basic OP プラン（`oidcc-basic-certification-test-plan`）を実行したところ、35 モジュール中 30 が `code_challenge` のない認可要求から始まり、`invalid_request: code_challenge is required` で止まって評価できなかった（[conformance.md](../conformance.md)「PKCE 必須との非互換」）。OIDC Core は Code フローに PKCE を求めないので、これは Suite の不具合ではない。

このときは「現状維持（案 1）」を選び、将来必要になれば Web Profile を緩めず、ADR-0004 §5 に従って新しい Profile を足すと記録した。本 ADR はその条項を実体化する。目的は Basic OP の**認定ではなく、Suite による評価範囲を広げること**に置く。

RFC 9700 §2.1.1 は Authorization Code の injection（§4.5）への対策を、public クライアントには PKCE で、confidential クライアントには PKCE か OIDC の `nonce` で求めている。認可サーバーには、PKCE への対応と、PKCE Downgrade 攻撃（§4.8）の防止を求めている。

## 決定

### 1. Profile `web-legacy` を追加する

`ProfileWebLegacy`（値は `"web-legacy"`）を足す。Web Profile との違いは PKCE の扱いだけで、ほかはすべて Web と同じにする。

| 項目 | Web Application | Web Legacy |
| --- | --- | --- |
| Client 種別（RFC 6749 §2.1） | confidential | confidential |
| grant_types / response_types | `authorization_code`, `refresh_token` / `code` | 同左 |
| token_endpoint_auth_method | `client_secret_basic`（`client_secret_post` も受理） | 同左 |
| redirect_uri 照合 | 完全一致、`https` のみ（開発用の localhost 設定あり） | 同左 |
| Refresh Token / ID Token | 発行する。Rotation 必須 / `openid` 要求時に発行 | 同左 |
| **PKCE** | **S256 必須** | **提示されたら S256 で検証する。省略する場合は `openid` scope と `nonce` が必須** |

- 名前に `legacy` を入れ、推奨しない選択肢であることを名前で示す。新しく作るクライアントは `web` を使う。
- Engine 側に、この Profile を有効にするための設定（opt-in）は置かない。Profile を選んで Client を登録すること自体を明示的な選択とみなす（ADR-0004 §5「個別フラグを置かない」）。
- Conformance 専用にはしない。認定はデプロイされた設定に対して受けるので、実際に使える Profile として置く。

### 2. 認可要求での判定（RFC 7636 §4.4.1、RFC 9700 §2.1.1）

Client と redirect URI の検証が済んだ後に判定するので、エラーはすべてリダイレクトで返す。

1. `code_challenge` があれば、Profile に関係なく従来どおり検証する。`code_challenge_method` は `S256` に限り、構文も検証する。`plain` は受け付けない。
2. `code_challenge` がなく、Client が PKCE 必須の Profile なら `invalid_request`（従来どおり）。
3. `code_challenge` がなく、Client が `web-legacy` なら、次の 2 つをどちらも満たすときだけ受け付ける。どちらかが欠けたら `invalid_request`。
   - `scope` に `openid` を含む
   - `nonce` がある（空文字は不可）

3 は RFC 9700 §2.1.1 の「confidential クライアントは PKCE の代わりに `nonce` を使ってよい」に対応する。`nonce` を ID Token と照合するのはクライアントの責務（OIDC Core §3.1.3.7）。エンジンが保証するのは、`nonce` がないまま PKCE なしの Code を発行しないことまで。`nonce` の乱数としての強さは検証しない。

### 3. トークン要求での判定（RFC 7636 §4.6、RFC 9700 §4.8）

| 発行時の Code | `code_verifier` | 結果 |
| --- | --- | --- |
| challenge あり | あり | S256 で照合する（従来どおり） |
| challenge あり | なし | `invalid_grant` |
| challenge なし | なし | 照合しない（`web-legacy` のみ。ほかの Profile ではこの状態の Code は作られない） |
| challenge なし | あり | `invalid_grant`（Downgrade 攻撃の検知、RFC 9700 §4.8） |

- 不変条件「Code 交換は先に消費し、検証失敗でも戻さない」は変えない。上の判定は消費の後、Code に保存した情報で行う。
- PKCE 必須の Profile では、従来どおり消費の前に `code_verifier` の欠落を弾く。既存 Profile の挙動を変えないため。
- challenge が空の Code を `VerifyS256` に渡す経路は作らない。

### 4. 条件表と API の形

Profile の条件表では、PKCE を真偽値ではなく三値で持つ。`false` を「任意」の意味に流用すると、Machine の「該当なし」と区別できず、表を読んだだけでは意味が分からなくなるため。

```go
type pkcePolicy int

const (
	pkceNotApplicable pkcePolicy = iota // Authorization Code Grant を使わない（Machine）
	pkceRequired                        // S256 必須（Web / Native / MCP）
	pkceIfPresent                       // 提示されたら検証、省略時は openid + nonce 必須（Web Legacy）
)
```

- `Client.RequiresPKCE()` は今の意味（必須か）のまま残す。`web-legacy` では `false` を返す。
- コンストラクタは `client.NewWebLegacy(client.WebParams, now)`。パラメータは Web と共通にする。
- Profile は登録後に変えられない（ADR-0004 §4）。`web` から移るときは Client を作り直す。

### 5. 保存形式

`AuthorizationCode.CodeChallenge` と `CodeChallengeMethod` が空文字なら、「PKCE なしで発行した Code」と解釈する。列は SQLite / PostgreSQL ともに `TEXT NOT NULL` なので migration は要らない。`storage/storagetest` に challenge が空の Code を保存して読み戻すケースを足し、全 Adapter に通させる。

### 6. Discovery

`code_challenge_methods_supported: ["S256"]` は変えない（RFC 8414 §2、RFC 9700 §2.1.1）。Client ごとの PKCE 要否は Discovery には出さない。

### 7. Conformance Suite での扱い

- [conformance/clients.json](../../conformance/clients.json) の 2 クライアントを `web-legacy` で登録する。
- `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` は §2 の 3 によって `invalid_request` になる。これは意図した結果なので `expected-failures.json` に登録する。したがって Basic OP の認定は取れない。認定を目標にしない判断（2026-10-24）は変えない。
- ほかの 29 モジュールが評価対象に加わる見込み。Suite は Code フローで `nonce` を送る前提だが、モジュールごとに実際に送っているかは再実行で確かめ、結果を conformance.md に記録する。

## 検討した代替案

1. **現状維持**（2026-10-24 の判断）。Suite で評価できるのは 5 モジュールのまま。30 モジュールの内容は自前テストで押さえているが、外部の検証を通っていない。
2. **Web Profile の PKCE を任意にする。** 既存の Web クライアントすべての防御が下がる。ADR-0004 §1 の「Web は PKCE 必須」も崩れる。
3. **開発用フラグ（`AllowPKCEless` など）を置く。** ADR-0004 §5 が却下したエスケープハッチであり、デプロイ設定を対象とする認定にも使えない。
4. **`web-legacy` で PKCE も `nonce` も任意にする（認定を取れる形）。** Code injection に対して、エンジンが保証できる防御がクライアント認証と redirect URI の一致だけになる。RFC 9700 §2.1.1 の条件をクライアント任せにすることになり、「BCP が禁止・非推奨とする選択肢は存在させない」（ADR-0001 §2-2）との乖離が大きい。評価範囲の差は 1 モジュールしかないため採らない。

## 既存 ADR への影響

- ADR-0001 §3「PKCE を使わない Authorization Code Grant」に「（ADR-0009 の `web-legacy` で `nonce` を伴う場合を除く）」を加える。「影響」の「PKCE 非対応のレガシークライアントは接続できない」も同じように限定する。
- ADR-0004 §1 の表に Web Legacy の列を足す。§3「PKCE の有無・方式」は開放しないまま、Profile が決めることを明記する。§4 に `NewWebLegacy` を足す。§5 に「ADR-0009 で、前例どおり Profile として追加した」と追記する。§6（MCP）にならい、§7 に本 ADR の要約を置く。
- ADR-0005 は変えない（§5 の空文字の意味づけは本 ADR に置き、`storagetest` で保証する）。
- CLAUDE.md の不変条件の「PKCE なし…は実装しない」を「PKCE なしは ADR-0009 の `web-legacy` に限り、`openid` と `nonce` を必須とする」に変える。

## 影響

- Interaction API の契約変更: `client.profile` に `web-legacy` が増える（[interaction-api.md](../interaction-api.md)）。利用者から見た同意画面の扱いは `web` と同じでよい。
- README・[embedding.md](../embedding.md)・[docs/README.md](../README.md) の「PKCE 非対応のクライアントは接続できない」を「`nonce` を使う OIDC クライアントは `web-legacy` で接続できる」に改める。
- examples: `cmd/server` の Profile の switch と `console` の登録フォームに `web-legacy` を足す。`cmd/server` は登録済みの Client を飛ばすので、Conformance を再実行する前に `conformance.db` を消す手順を conformance.md に書く。
- テスト: §2 の各分岐、§3 の 4 通りの組み合わせ、PKCE を付けた要求が `web-legacy` でも従来どおり検証されること、既存 Profile の挙動が変わらないこと（`profile_test.go` の表と `authorization` / `token` の回帰）。
- roadmap 上の位置は M4a のタスク 1（[roadmap.md](../roadmap.md)「M4a のタスク順序（案）」、[ADR-0010](0010-client-auth-and-sender-constraint.md)）。小さく、合意済みで、M4a と同じく Conformance Suite の評価範囲を広げる目的を持つため。
