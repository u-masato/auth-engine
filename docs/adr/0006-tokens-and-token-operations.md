# ADR-0006: トークン形式と Token Operations

- 状態: 採用（2026-10-24 合意）。2026-10-25 更新: M3 で JWT Access Token と Audience を追加（[ADR-0008](0008-mcp-integration.md) §3）
- 日付: 2026-10-24（2026-10-25 更新）

## 文脈

技術スタック案は「Access Token は Opaque を標準、ID Token は JWT」とし、別途「Token Operations（Mint / Reissue / Revoke / Inspect / RevokeGrant）」を管理用操作として置く。
この妥当性と、プロトコル処理との境界を決める。

## 決定

### 1. Access Token は Opaque を既定とする（採用）

理由:

- 失効が即時に効く。JWT では有効期限まで失効を伝播できず、結局 Introspection か短寿命化が必要になる。
- Resource Server への鍵配布・アルゴリズム合意が不要。
- トークンに Claims を載せないため、Claims の変更＝再発行という問題が起きない。

帰結:

- Resource Server はトークン検証に **Introspection（RFC 7662）を使う**。したがって Introspection は「推奨」ではなく **P0 の後半（M2）で必須** とする。同一プロセスの Resource Server 向けには Go API `Inspect` を直接呼べるようにする。
- MCP 等で Resource Server がローカル検証を望む場合に備え、**JWT Access Token（RFC 9068）を選択肢** として P1 で追加する。発行経路を `token.Issuer` インターフェースの背後に置き、P0 では Opaque 実装のみを持つ。

M3（2026-10-25）で JWT Access Token を次の形で追加した（ADR-0008 §3）。Opaque が既定であることは変わらない。

- **形式は Client ではなく resource ごとに決める。** `Config.Resources` の `AccessTokenFormat`（Opaque / JWT）と `AccessTokenAlg`（RS256 / ES256）で選ぶ。形式は Resource Server がローカル検証するか Introspection するかの都合であり、Client の属性ではない。`resource` なしの要求は常に Opaque。複数 `resource` で形式が揃わない要求は `invalid_target`。
- `token.Issuer` の実装は `OpaqueIssuer`、`JWTIssuer`、形式で振り分ける `ByFormat` の 3 つ。`Engine` は `ByFormat` を配線し、`token.Service` が Audience 先頭の resource 設定で形式を決める。
- JWT は RFC 9068: `typ: at+jwt`、`iss` `sub` `aud`（常に配列）`exp` `iat` `jti` `client_id` `scope`、認可コード由来なら `auth_time` `acr` `amr`。署名は `keys` の署名鍵。
- **JWT でも Store に `AccessToken` の行を持つ**（`Hash` はトークン文字列全体の SHA-256）。Introspection と Revocation は形式に依らず同じ経路で動く。ただし Resource Server がローカル検証する限り失効は `exp` まで伝播しない。これは上の「Opaque を既定とする理由」そのものであり、JWT を選ぶ resource には短い `AccessTokenTTL` の Client を組み合わせることを文書で求める。
- **Audience。** 認可要求の `resource`（RFC 8707）は `Family.Audience` として引き継ぎ、トークン要求の `resource` でその部分集合に絞った値を `AccessToken.Audience` に付ける。Introspection 応答に `aud` を載せ（RFC 7662 §2.2）、Resource Server は形式に依らず `aud` に自分が含まれることを確認する。UserInfo は AS 自身のリソースなので `openid` scope があれば `aud` に関わらず受理する。

形式: `at_` などの短い接頭辞 + 256 bit 乱数の base64url。接頭辞はログやシークレットスキャナでの識別用。保存は SHA-256 ハッシュのみ（ADR-0005）。

### 2. ID Token は JWT（採用）

- OIDC Core §2 の要求どおり JWS 署名付き JWT。既定 RS256、選択で ES256（ADR-0002）。
- 必須 Claims: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`（`max_age` 要求時または常時）, `nonce`（要求時）, `at_hash`（Access Token 同時発行時）。
- `amr`, `acr` は Interaction App の `Outcome` から転記する。
- Claims の中身（`name`, `email` 等）は Interaction App が `Outcome.claims` で渡したスナップショットを使う。エンジンは scope と Claims の対応（OIDC Core §5.4）でフィルタするだけで、値の生成は行わない。

### 3. UserInfo の Claims の出所

Txn が消費された後も `/userinfo` は Claims を返す必要がある。選択肢と判断:

| 案 | 判断 |
| --- | --- |
| Grant に Claims スナップショットを保存し、UserInfo はそれを返す | **採用（P0）**。Hydra の consent session と同じ考え方。Interaction App が同意時点の Claims を渡す |
| UserInfo 時に Interaction App へ Claims を問い合わせる（`ClaimsProvider` Port） | **P2 で任意の拡張点として追加**。常に最新の Claims が必要な利用者向け。P0 ではインターフェースだけ予約しない（YAGNI） |

### 4. Token Family と Refresh Token Rotation

- Code 交換 1 回ごとに **Token Family** を作る。Refresh Token の Rotation はこの Family 内で連鎖する。
- Rotation 時に旧 Refresh Token は `rotated` になる。`rotated` のトークンが再提示されたら **Family 全体を失効**（RFC 9700 §4.14.2）。Grant は失効させない（別デバイスのセッションまで巻き込まない）。
- Refresh Token の有効期間: Family 作成からの絶対期限（既定 30 日）と、最終使用からのスライド期限（既定 14 日）の両方を持つ。P0 は絶対期限のみでもよい。

### 5. Token Operations の境界

| 操作 | 判断 | 理由 |
| --- | --- | --- |
| `Inspect(token)` | 採用（M2） | Introspection エンドポイントと同じ Use Case。Go API として公開 |
| `RevokeToken(token)` | 採用（M2） | Revocation（RFC 7009）と同じ Use Case。Refresh Token の失効は Family 全体を失効 |
| `RevokeGrant(clientID, subject)` | 採用（M2） | 「このアプリとの連携を解除する」ための管理操作。プロトコル上の対応物はなく、Go API のみ |
| `ListGrants(subject)` | 採用（M2） | 同上。Interaction App が「連携済みアプリ一覧」を描くための読み取り |
| `Mint`（信頼されたバックエンドから任意 Access Token 発行） | **却下（P0〜P2）** | 下記 |
| `Reissue` | **却下** | Opaque では Claims を持たないため成立しない。JWT AT を導入しても「新規発行 + 旧失効」の組合せで表現できる |

`Mint` を却下する理由:

- Grant を経ないトークンは「誰が何に同意したか」の記録を持たず、Introspection・RevokeGrant・監査の前提を壊す。
- 「信頼されたバックエンドがトークンを得る」要求は、RFC に対応物がある。サービス自身の権限なら **Client Credentials**（M2 M2M Profile）、ユーザーの代理なら **Token Exchange**（RFC 8693、P2）。参照実装としては既存仕様に写像する方が読者に伝わる。
- どうしても必要な場合は P2 以降で「Token Exchange の `actor_token` を持つ Impersonation」として設計し、発行元認証・監査ログを必須とする。独自の Mint API は置かない。

### 6. 監査ログ

- トークン発行・失効・Code 再利用検知・Rotation 再利用検知は `slog` に構造化イベントとして出す（`event=token.issued` 等）。
- 監査ログの永続化はコアの責務にしない。利用者が `slog.Handler` で転送する。

## 影響

- `token` パッケージは `Issuer`（`OpaqueIssuer` / `JWTIssuer` / `ByFormat`）を持ち、`Family` を集約として管理する。ID Token の組立と署名は `oidc` パッケージ。
- Introspection・Revocation エンドポイントを M2 に前倒しする（ロードマップ参照）。
