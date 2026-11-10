# Day 4 Code 交換、Access Token、ID Token、鍵

[← Day 3](day3-transaction.md) ｜ [索引](README.md) ｜ [Day 5 →](day5-token-lifecycle.md)

## 目標

- トークンエンドポイントのクライアント認証が、失敗の理由を区別しない理由を説明できる
- `exchangeCode` の処理順を再現し、「先に消費、検証失敗でも戻さない」がどこに書かれているかを示せる
- Code の再利用を検知したときに失効させる範囲（Token Family）と、許容している競合の窓を説明できる
- Access Token の形式（Opaque / JWT）が何で決まるか、ID Token と JWT Access Token の違いを説明できる
- `keys.Set` の署名・検証・ローテーションの仕組みを説明できる

## この日の用語

| 用語 | 意味 | 出てくる場所 |
| --- | --- | --- |
| トークンエンドポイント | `POST /token`。grant_type に応じて Code 交換・Refresh・client_credentials を処理する | `token.Service.Exchange` |
| クライアント認証 | トークンエンドポイントで Client が自分を証明すること。方式は `client_secret_basic`（Authorization ヘッダ）、`client_secret_post`（フォーム）、`none`（public Client） | `authenticateClient`、`Credentials` |
| `invalid_client` / `invalid_grant` | RFC 6749 §5.2 のエラー。前者はクライアント認証の失敗（401）、後者は Code・Refresh Token・redirect URI・PKCE の不一致（400） | `token/errors.go` |
| Code の消費 | Code を 1 回だけ使えるよう消費済みにすること。検証より先に行い、検証に失敗しても戻さない | `ConsumeAuthorizationCode` |
| Token Family | 1 回の Code 交換から派生するトークンの集まり。失効の単位 | `token.Family` |
| `FamilyID` | Code 発行時に前もって決めておく Family の ID。再利用を検知したときに失効させる対象を特定する | `AuthorizationCode.FamilyID` |
| 再利用検知 | 消費済みの Code が再び提示されたら、その Code の Family を失効させること（RFC 6749 §4.1.2） | `revokeFamilyOnReuse` |
| 競合の窓 | 同時の交換で、勝者の Family 作成より先に敗者の失効が走ると失効できない、数マイクロ秒の隙間。理由を付けて許容している | `revokeFamilyOnReuse` のコメント |
| Opaque Access Token | 意味を持たない乱数文字列のトークン（接頭辞 `at_`）。検証は Introspection で行う | `OpaqueIssuer` |
| JWT Access Token | RFC 9068 の署名付きトークン。`typ: at+jwt`、`aud` は Resource。JWKS でローカル検証できる | `JWTIssuer` |
| `token.Issuer` / `ByFormat` | Access Token を発行するインターフェースと、形式ごとに振り分ける実装 | `token/issuer.go` |
| Audience | Access Token の向け先の Resource の一覧。空なら認可サーバー自身（UserInfo）向けで Opaque になる | `AccessToken.Audience` |
| 絶対期限 / スライド期限 | Refresh Token の寿命。Family 作成から 30 日と、最終使用から 14 日の早い方 | `newRefreshToken` |
| ID Token | 「誰がいつどう認証されたか」を Client に伝える署名付き JWT（OIDC Core §2）。`aud` は client_id | `oidc.IDTokenIssuer` |
| `auth_time` / `amr` / `acr` | 認証時刻、認証方法、認証の強度。Interaction App が渡した値を載せる | `idTokenClaims` |
| `at_hash` | 同時に発行した Access Token のハッシュの左半分（OIDC Core §3.1.3.6）。ID Token と Access Token を結びつける | `AccessTokenHash` |
| JWK / JWKS | 公開鍵の JSON 表現と、その集合（RFC 7517）。`/jwks` で公開する | `keys.Set.JWKS` |
| `kid` | 鍵の ID。公開鍵の RFC 7638 サムプリントから作る | `thumbprint` |
| 鍵ローテーション | 署名鍵を差し替えること。旧鍵は検証鍵として残し、JWKS にも出し続ける | `Set.AddSigning`、`Set.Remove` |
| アルゴリズム混同 | トークンのヘッダの `alg` を書き換えて、意図しない方式で検証させる攻撃（RFC 8725 §3.1）。鍵側の alg との一致を要求して防ぐ | `Set.Verify` |

## 読む順

1. [architecture.md §5 のシーケンス図の後半](../architecture.md#authorization-flow)（`POST /token` 以降）と [§7「失効の範囲」「Opaque と JWT」](../architecture.md#token-lifecycle)
2. [ADR-0006 トークン形式と Token Operations](../adr/0006-tokens-and-token-operations.md)
3. RFC 6749 §4.1.3（トークン要求）、§5.2（エラー応答）、§4.1.2（Code の再利用で失効させる）。RFC 7636 §4.6。OIDC Core §2、§3.1.3.6（`at_hash`）。RFC 8725 §3.1（アルゴリズム混同）
4. コード
   - [token/clientauth.go](../../token/clientauth.go) — `Credentials` `authenticateClient`
   - [token/service.go](../../token/service.go) — `Exchange` `exchangeCode` `revokeFamilyOnReuse` `issueAccessToken` `newRefreshToken` `narrowAudience`
   - [token/token.go](../../token/token.go) — `Family` `AccessToken` `RefreshToken`
   - [token/issuer.go](../../token/issuer.go)、[token/jwt.go](../../token/jwt.go)、[token/idtoken.go](../../token/idtoken.go)
   - [oidc/idtoken.go](../../oidc/idtoken.go)
   - [keys/keys.go](../../keys/keys.go)、[keys/jwks.go](../../keys/jwks.go)
   - [httpapi/token.go](../../httpapi/token.go)、[httpapi/discovery.go](../../httpapi/discovery.go) の `handleJWKS`

## 解説

### 1. Exchange の入口: 認証してから grant_type を見る

`Service.Exchange` の順序:

1. `authenticateClient` — まず Client を確定する
2. `grant_type` が空なら `invalid_request`、未知なら `unsupported_grant_type`
3. `Client.Allows(gt)` でなければ `unauthorized_client`（Profile が決める。Day 2）
4. `exchangeCode` / `refresh` / `clientCredentials` に振り分ける

`authenticateClient` の失敗は、理由を問わず同じ `invalid_client`（"client authentication failed"）になる。

- `client_id` が空
- 未登録（`storage.ErrNotFound`）
- Profile が受け付けない認証方式（たとえば Native が `client_secret_basic` で来た、Web がシークレットなしで来た）
- シークレットの不一致

「その `client_id` は存在するがシークレットが違う」と「存在しない」を区別すると、`client_id` の列挙に使われる。例外は CIMD の解決失敗（`client.ErrUnresolvable`）で、こちらは理由を返す。URL 形式の `client_id` の文書を取れない理由は、登録済み Client の列挙には役立たず、MCP クライアントの開発者にとっては必要な情報だからである。

資格情報を取り出すのは HTTP 層の `clientCredentials` で、Basic 認証の `user` / `pass` を `url.QueryUnescape` で復号している。RFC 6749 §2.3.1 は、Basic に入れる前に client_id とシークレットを form-urlencode するよう定めているためで、`TestBasicCredentialsAreFormDecoded` がこれを確かめている。

### 2. exchangeCode: 先に消費する

```go
code, err := s.Store.ConsumeAuthorizationCode(ctx, rand.Hash(req.Code), now)
switch {
case errors.Is(err, storage.ErrCodeAlreadyUsed):
	s.revokeFamilyOnReuse(ctx, code, now)
	return nil, protocolErr(CodeInvalidGrant, "authorization code is invalid")
case errors.Is(err, storage.ErrNotFound):
	return nil, protocolErr(CodeInvalidGrant, "authorization code is invalid")
// ...
}
```

`ConsumeAuthorizationCode` は 1 回の原子的な操作で「未消費・未期限なら消費済みにして内容を返す」。**検証より前に**これを呼ぶのがこの関数の要点である。

その後の検証:

1. `code.ClientID != c.ID` → `invalid_grant`（別 Client に発行された Code）
2. 認可要求に `redirect_uri` があったなら（`RedirectURIExplicit`）、トークン要求にも同じ値が必須。なかった場合も、提示されたら一致を要求する（RFC 6749 §4.1.3）
3. `authorization.VerifyS256(code.CodeChallenge, req.CodeVerifier)`（RFC 7636 §4.6）
4. `narrowAudience` — `resource` の絞り込み（Day 7）

どれかで失敗しても、Code は**消費済みのまま戻さない**。攻撃者が盗んだ Code で `code_verifier` を総当たりすることはできず、1 回外した時点でその Code は使えなくなる。正規の Client にとっては、検証に失敗した Code を再利用できないことになるが、それは Client 側のバグなので認可をやり直せばよい。ここでも fail-closed を選んでいる。

検証を通ったら、Code から **Token Family** を組み立てる。`Family.ID` には Code 発行時に決めておいた `code.FamilyID` を使い、`Scopes` と `Audience` は Code の値の写し、`AuthenticatedAt` / `AMR` / `ACR` も写しておく（Refresh のときの ID Token に要る。Day 5）。

最後に `Store.IssueTokens(family, access, refresh)` で、Family と最初のトークンを**1 回の原子的な操作で**保存する。このとき Adapter は Grant が active であることを確かめ、失効していれば `ErrGrantRevoked`（→ `invalid_grant`）を返して何も保存しない。Code 発行から交換までの間に連携解除されたケースを、ここで止める。

### 3. Code の再利用を検知したら Family を失効させる

RFC 6749 §4.1.2 は、Code が 2 回使われたら「その Code に基づいて発行したトークンを（可能なら）すべて失効させるべき」としている。2 回目の提示は、Code が漏れて攻撃者が使った（または正規の Client が使った後に攻撃者が使おうとした）兆候だからである。

`ConsumeAuthorizationCode` は、消費済みの Code について**元の記録と** `ErrCodeAlreadyUsed` を一緒に返す。だから呼び出し側は `code.FamilyID` を知ることができ、`RevokeTokenFamily` で失効させられる。Adapter が消費済み Code を期限まで削除しないのはこのためである（[token/store.go](../../token/store.go) のコメント）。

失効させるのは **Grant ではなく Family** である（CLAUDE.md の不変条件）。Grant は client_id × subject に 1 つなので、Grant を失効させると、同じユーザーが同じ Client で並行して持っている別のセッション（別の Family）まで巻き込む。漏れたのはこの Code に由来するトークンだけなので、範囲をそこに絞る。

> **読むときの注意**: [storage/errors.go](../../storage/errors.go) の `ErrCodeAlreadyUsed` のコメントは「この Code に由来する Grant を失効させる」と書かれているが、実装（`revokeFamilyOnReuse`）と不変条件は Family である。M1 の実施結果（[roadmap.md](../roadmap.md)）で Grant から Family に変えた際、コメントが残ったものと思われる。

`revokeFamilyOnReuse` のコメントには、**許容している競合の窓**が書いてある。同じ Code の 2 つの要求がほぼ同時に届き、勝者が `IssueTokens` する前に敗者が `RevokeTokenFamily` を呼ぶと、Family はまだ存在しないので失効できず（`ErrNotFound` を無視する）、勝者のトークンは有効なまま残る。この窓は 1 要求の中の数マイクロ秒で、しかも PKCE 必須の下では `code_verifier` を持たない攻撃者は勝者になれない。Family の作成を Resume 時に前倒しすれば窓は消えるが、その複雑さに見合わない、という判断である。**完全ではない保証を、その理由とともにコメントに残している**ことに注目してほしい。

### 4. Access Token の発行: Issuer インターフェース

```go
type Issuer interface {
	Issue(ctx context.Context, in IssueInput) (plaintext string, rec *AccessToken, err error)
}
```

`Issuer` は「平文（応答に載せる）」と「記録（Store に保存する）」の組を返す。実装は 3 つある。

| 実装 | 平文 | 記録の `Hash` |
| --- | --- | --- |
| `OpaqueIssuer` | `at_` + 256 bit 乱数 | 平文の SHA-256 |
| `JWTIssuer` | RFC 9068 の JWT（`typ: at+jwt`） | **JWT 文字列全体**の SHA-256 |
| `ByFormat` | 形式に応じて上の 2 つに振り分ける | — |

**JWT でも Store に記録を持つ**のが重要である。こうすると Introspection と Revocation は形式に関係なく同じ経路（`LookupAccessToken`）で動く。違いは、Resource Server が JWKS でローカル検証した場合に、Store の失効が `exp` まで伝わらないことだけである（Day 7）。

形式を決めるのは Client ではなく **Resource** である（`issueAccessToken`）。Audience が空なら Opaque、あれば先頭の Resource の `EffectiveFormat()` と `EffectiveAlg()` を使う。複数の Resource の形式が揃っていることは、`resource.Set.Resolve` が `ErrMixedFormats` で保証済みなので、先頭を見れば足りる。形式は「その Resource Server がローカル検証したいか、Introspection するか」の都合で決まるので、Resource の属性にしてある（ADR-0008 §3）。

有効期限は `IssueInput.expiresAt()` の 1 か所で決める。JWT の `exp` と Store の `ExpiresAt`（Introspection の `exp`）がずれないようにするためである。

### 5. Refresh Token の期限

Profile が許せば（Web / Native / MCP）、`exchangeCode` は Refresh Token も発行する。

- `Family.ExpiresAt = now + RefreshTokenTTL`（絶対期限、既定 30 日）
- `newRefreshToken` は `now + RefreshTokenIdleTTL`（スライド期限、既定 14 日）と `Family.ExpiresAt` の**早い方**を期限にする

Rotation のたびにスライド期限は延びるが、Family の絶対期限は超えない（Day 5）。

### 6. ID Token

`scope` に `openid` が含まれ、Profile が ID Token を出すなら、`IDTokens.IssueIDToken` を呼ぶ（OIDC Core §3.1.3.3）。実装は `oidc.IDTokenIssuer` で、`token` パッケージは `IDTokenIssuer` インターフェースだけを知っている（Day 1）。

| Claim | 値 | 根拠 |
| --- | --- | --- |
| `iss` | Issuer | OIDC Core §2 |
| `sub` | Interaction App が渡した `subject` | 同上 |
| `aud` | `[client_id]` | 同上。JWT Access Token の `aud`（Resource）と違う |
| `exp` / `iat` | 発行時刻 + `IDTokenTTL`（既定 1 時間） | 同上 |
| `auth_time` | `Outcome.AuthenticatedAt` | 同上 |
| `nonce` | 認可要求の `nonce` | §3.1.2.1。リプレイ対策 |
| `at_hash` | Access Token の SHA-256 の左半分を base64url | §3.1.3.6 |
| `amr` / `acr` | Interaction App が渡した値 | §2 |

`profile` や `email` に対応する Claims（`name`、`email` など）は ID Token に**載せない**。Code フローでは UserInfo から返す（OIDC Core §5.4）。ID Token は「誰がいつどう認証されたか」だけを表す、という割り切りである。

ID Token の生成は `IssueTokens` の**後**に行う。署名に失敗すると 500 になるが、Store にはすでに Family とトークンが保存されている（architecture.md §7 の最後）。トークンは平文が返らないので誰も使えず、期限が来れば消える。

### 7. keys: 署名鍵セット

`keys.Set` は go-jose/v4 を使う唯一の場所である（ADR-0002）。

- **アルゴリズムは RS256 と ES256 だけ**。`none` と HS256 などの共有鍵方式は扱わない（RFC 8725 §3.2）
- **kid は公開鍵の RFC 7638 サムプリント**。同じ鍵からは常に同じ kid ができる
- **署名鍵はアルゴリズムごとに 1 本**。`AddSigning` で差し替えると、旧鍵は検証鍵として残り、JWKS にも出続ける。古い鍵は `Remove` で外す。こうすると、旧鍵で署名された ID Token を Relying Party がまだ検証できる
- **`Verify` は kid で鍵を選び、ヘッダの `alg` が鍵のアルゴリズムと一致することを要求する**。RSA 公開鍵を HMAC の共有鍵として使わせる「アルゴリズム混同」を防ぐ（RFC 8725 §3.1）
- **`JWKS()` は公開鍵だけを出す**（`TestJWKSHasNoPrivateMaterial`）。`/jwks` は 1 時間のキャッシュを許す。ローテーションは新旧の鍵を重複期間に両方公開することで吸収する
- `ExportPrivate` / `ImportPrivate` は秘密鍵を含む JSON の入出力で、デモが `keys.json` に保存するのに使う。保管と保護は利用者の責務である

`SignTyped` は `typ` ヘッダを指定して署名する。ID Token は `JWT`、JWT Access Token は `at+jwt` で、Resource Server は `at+jwt` 以外を拒否する（RFC 9068 §4）。ID Token を Access Token として持ち込まれる混同を、ヘッダで区別する。

## 手を動かす

### 1. トークンエンドポイントのテスト

```bash
go test -race -run 'TestClientAuthentication|TestInvalidGrant|TestCodeReuseRevokesFamily|TestConcurrentExchange|TestIDTokenIssuedForOpenID' -v ./token/
```

`TestConcurrentExchange` を読み、同じ Code を並行に交換したとき「成功はちょうど 1 回」をどう確かめているかを見る。不安定さを疑ったら `-count=3` で何回か回す（CLAUDE.md）。

```bash
go test -run 'TestSignVerifyRoundTrip|TestRotation|TestKidIsThumbprint|TestJWKSHasNoPrivateMaterial' -v ./keys/
```

### 2. 壊して確かめる

| 変更 | 落ちるテスト |
| --- | --- |
| `exchangeCode` の `s.revokeFamilyOnReuse(ctx, code, now)` の行を消す | `token` の `TestCodeReuseRevokesFamily`、`httpapi` の `TestFullAuthorizationCodeFlow` |
| `exchangeCode` の `VerifyS256` の検査ブロックを消す | `token` の `TestInvalidGrant/pkce_mismatch` と `TestInvalidGrant/malformed_verifier`。**`httpapi` のテストは通る** |
| `storage/memory` の `ConsumeAuthorizationCode` で `c.ConsumedAt = now` を消す | `storage/memory` の `TestContract/AuthorizationCode` と `TestContract/AuthorizationCodeConcurrentConsume`、`token` の `TestInvalidGrant` の多数、`TestCodeReuseRevokesFamily`、`TestConcurrentExchange`、`TestExchangeAudienceErrors` |

3 つ目の変更で `TestInvalidGrant/pkce_mismatch` のような「1 回しか交換していないはずのテスト」まで落ちる理由を、テストのコードを読んで説明すること（ヒント: 各ケースは交換が `invalid_grant` で失敗した後、Store の `ConsumeAuthorizationCode` をもう一度直接呼び、Code が消費済みのまま残っていること、つまり fail-closed であることを確かめている）。

### 3. デモで ID Token を見る

Day 3 の通常モードが残っていると `flow` が URL を出して止まるので、先に止めてから自動承認モードで起動する。

```bash
.claude/skills/run-demo/scripts/demo.sh stop
```

```bash
.claude/skills/run-demo/scripts/demo.sh start -auto-approve
```

```bash
.claude/skills/run-demo/scripts/demo.sh flow
```

開発者コンソール（`http://127.0.0.1:8083`）でもフローを流し、ID Token の検証結果（署名、`iss` / `aud` / `exp` / `nonce`）の表示を確かめる。続けて JWKS を取得し、ID Token のヘッダの `kid` が JWKS のどの鍵かを突き合わせる。

```bash
curl -s http://localhost:8080/jwks
```

## 確認問題

1. トークン要求で、Code の消費を PKCE の検証の後に移したら、どんな攻撃が可能になるか。
2. `ConsumeAuthorizationCode` が、消費済みの Code について「エラーだけ」ではなく「元の記録とエラー」を返すのはなぜか。
3. Code の再利用を検知したとき、Grant ではなく Family を失効させる理由を説明せよ。
4. JWT Access Token にも Store の記録を持たせる利点と、それでも残る制約は何か。
5. 鍵をローテーションした直後、旧鍵を `Remove` すると何が起きるか。

<details>
<summary>解答</summary>

1. 検証に失敗しても Code が未消費のまま残るので、盗んだ Code に対して `code_verifier` を何度でも試せる（オンラインの総当たり）。また、検証が通るまで Code が生きているので、正規の Client と攻撃者の間で「先に通った方が勝つ」競争が長く続く。先に消費すれば、試せるのは 1 回だけになる。
2. 呼び出し側（`exchangeCode`）が `FamilyID` を知り、その Family を失効させるためである。エラーだけだと、どの Family を失効させればよいかわからない。そのため Adapter は消費済み Code を期限まで削除せずに残しておく契約になっている。
3. 漏えいの兆候があるのは、その Code から作られたトークン（1 つの Family）だけである。Grant は client_id × subject に 1 つしかないので、Grant を失効させると、同じユーザーが同じ Client で持つ別の端末・別のセッションのトークンまで無効になる。影響範囲を最小にしつつ、漏れた可能性のあるものは確実に止める。
4. 利点: Introspection と Revocation が Opaque と同じ経路で動き、Introspection で検証する Resource Server には失効が即座に伝わる。発行の監査も同じ記録で取れる。制約: Resource Server が JWKS でローカル検証する場合、Store の失効を知る手段がないので、`exp` までは有効と判定される。そのため JWT を選ぶ Resource は、短い `AccessTokenTTL` の Client と組み合わせる前提になる。
5. 旧鍵で署名された、まだ期限内の ID Token や JWT Access Token が、JWKS から旧鍵が消えた時点で検証できなくなる（Relying Party / Resource Server 側では未知の kid になる）。旧鍵は、それで署名したトークンの最長の有効期限と、JWKS のキャッシュ期間（1 時間）が過ぎるまで残す必要がある。
</details>
