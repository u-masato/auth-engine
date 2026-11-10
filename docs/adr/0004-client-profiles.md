# ADR-0004: Client Profile

- 状態: 採用（2026-10-24 合意）。2026-10-25 更新: M3 で MCP Client Profile を追加（[ADR-0008](0008-mcp-integration.md) §4）。2026-10-25 更新: PKCE を任意にする Web Legacy Profile を追加（[ADR-0009](0009-web-legacy-profile.md)、未実装）。2026-11-11 追記: シークレットの再発行（§8）。この追記は**草案**で、実装とともに PR に出しており、マージで確定する
- 日付: 2026-10-24（2026-11-11 更新）

## 文脈

RFC 6749 は Client に多数の選択肢（grant type、response type、クライアント認証方式、PKCE の有無、redirect URI の照合規則）を与える。これを利用者に選ばせると、安全でない組み合わせが生まれる。
技術スタック案の「Client Profile で用途別に固定する」方針を採用し、何を固定し何を開放するかを決める。

## 決定

### 1. 5 つの標準 Profile と固定項目

P0 は Web / Native / Machine の 3 つ。MCP Client は M3 で追加した（§6、ADR-0008 §4）。Web Legacy は Conformance Suite（Basic OP）で評価できる範囲を広げるために追加した（§7、ADR-0009）。

| 項目 | Web Application | Native / CLI | Machine to Machine | MCP Client（M3） | Web Legacy（ADR-0009） |
| --- | --- | --- | --- | --- | --- |
| Client 種別（RFC 6749 §2.1） | confidential | public | confidential | public | confidential |
| 識別 | 登録済み `client_id` | 同左 | 同左 | CIMD 文書の HTTPS URL を `client_id` とする。`Store` に事前登録することもできる（CIMD §7） | 登録済み `client_id` |
| grant_types | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` | `client_credentials` | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` |
| response_types | `code` | `code` | なし | `code` | `code` |
| PKCE | S256 必須 | S256 必須 | 該当なし | S256 必須 | 提示されたら S256 で検証。省略時は `openid` scope と `nonce` が必須（RFC 9700 §2.1.1）。`code_challenge` なしで発行した Code に `code_verifier` が来たら `invalid_grant`（§4.8） |
| token_endpoint_auth_method | `client_secret_basic`（`client_secret_post` も受理） | `none` | `client_secret_basic`（P2 で `private_key_jwt` 追加） | `none`（`private_key_jwt` は M4） | Web と同じ |
| redirect_uri 照合 | 完全一致、`https` のみ（開発用に `http://localhost` / loopback を許可する設定あり） | 完全一致。ただし loopback（`http://127.0.0.1` / `http://[::1]`）はポート番号を無視して照合（RFC 8252 §7.3）。カスタムスキーム・`https` のクレーム URL も可 | なし | CIMD 文書の `redirect_uris` と完全一致（`https`、または `http://localhost`）。loopback IP リテラルはポート番号を無視。`http://localhost` はポートまで完全一致 | Web と同じ |
| `resource`（RFC 8707） | 任意 | 任意 | 任意 | **必須**。欠落は `invalid_request` | 任意 |
| Refresh Token | 発行する。Rotation 必須 | 発行する。Rotation 必須、再利用検知で Token Family を失効（RFC 9700 §4.14） | 発行しない | Native と同じ（MCP 仕様 Security Considerations「Token Theft」） | Web と同じ |
| ID Token | `openid` scope 要求時に発行 | 同左 | 発行しない | `openid` scope 要求時に発行 | `openid` scope 要求時に発行（PKCE なしの要求は `openid` 必須なので必ず発行） |
| `response_mode` | `query` のみ | `query` のみ | — | `query` のみ | `query` のみ |

`localhost` ホスト名は RFC 8252 §8.3 の推奨に従い Native では既定で許可しない（loopback IP リテラルを使う）。MCP Client だけは `http://localhost` を許可する。MCP 仕様「Communication Security」が redirect URI を「`localhost` か HTTPS」と定め、CIMD 文書の例も `http://localhost:3000/callback` を使うため、拒否すると相互運用できない。RFC 8252 §8.3 の懸念（名前解決の乗っ取り）は残るので、Interaction App に redirect URI のホスト名を同意画面に出させる（[Interaction API 仕様](../interaction-api.md)「`profile` が `mcp` のとき」）。

### 2. 利用者に開放する項目

- `client_id`（未指定なら生成）、表示名、ロゴ URL、ポリシー URL
- `redirect_uris`（Profile の照合規則の範囲内）
- `allowed_scopes`（Client が要求できる scope の上限）
- `client_secret`（confidential のみ。エンジンが生成して 1 回だけ返す。保存はハッシュ）。登録後は再発行できる（2026-11-11 追加。草案）。`Client.RotateSecret` が新しい値を生成し、`Store.RotateClientSecret` がハッシュだけを置き換える。保存した時点で旧シークレットは無効になり、新旧を併用する期間は置かない（§8）。発行済みのトークンと Grant には触れない
- トークン有効期間（Profile ごとの上限内で短縮のみ可。例: Access Token 既定 1 時間、上限 24 時間）
- ID Token 署名アルゴリズム（RS256 / ES256）
- 許可する `resource`（`Resources`。M3 で追加。空なら `Config.Resources` に設定済みの全 resource を要求でき、指定があればその範囲に限る。ADR-0008 §2）
- `client_uri`（`ClientURI`。M3 で追加。CIMD 文書から取り込み、Interaction App に透過する）

### 3. 開放しない項目

- grant_types / response_types / response_mode
- PKCE の有無・方式（Profile が決める。PKCE を省略できるのは Web Legacy だけで、その場合も `openid` と `nonce` を必須とする。ADR-0009）
- token_endpoint_auth_method（Profile が決める）
- redirect URI の照合規則（ワイルドカード、部分一致は提供しない）
- Refresh Token Rotation の有無

### 4. API の形

```go
c, secret, err := client.NewWeb(client.WebParams{
    Name:         "Example Web",
    RedirectURIs: []string{"https://app.example.com/callback"},
    Scopes:       []string{"openid", "profile", "email"},
})
```

- 生成関数は Profile ごとに 1 つ（`NewWeb`, `NewWebLegacy`, `NewNative`, `NewMachine`, `NewMCP`）。`NewWebLegacy` は `NewWeb` と同じ `WebParams` を受け取る。不正なパラメータは生成時に `error` で返し、不正な Client 値は存在させない。`NewMCP` だけはパラメータではなく CIMD 文書（`MetadataDocument`）と取得元 URL を受け取り、CIMD §3〜§4 の検証（`client_id` の形式、文書 URL との一致、共有シークレットの拒否）を行う。
- `Client` は Profile を保持し、`Allows(grantType)`, `MatchRedirectURI(uri)`, `AuthenticationMethod()` などの問い合わせを Profile に委譲する。エンドポイント側に Profile の条件分岐を書かない。
- Profile は登録後に変更できない。用途が変わる場合は Client を作り直す。

### 5. 「エスケープハッチ」を置かない

Custom Profile（任意組み合わせ）は提供しない。PKCE 非対応のレガシークライアントは接続できないことを意図した制約として明記する。要望が出た場合も、新たな Profile（例: `Confidential Native`）を追加する形で応じ、個別フラグの開放はしない。M3 の MCP Client はこの方針どおり Profile として追加した。`http://localhost` の許可も MCP Profile に固定し、他 Profile には開放していない。PKCE の省略も同じ方針で、Web Profile を緩めたりフラグを置いたりせず、Web Legacy Profile として追加した（§7、ADR-0009）。PKCE も `nonce` も使わないクライアントは引き続き接続できない。

### 6. MCP Client Profile（M3 で追加）

P0 では「将来の Profile」として、Client の取得経路を `client.Resolver` インターフェースにする差し替え点だけを確保していた（ADR-0007 §4）。M3 で次の形で実体化した（ADR-0008 §4〜§5）。

- 条件は §1 の表のとおり。public、CIMD（Client ID Metadata Document）の HTTPS URL を `client_id` とし、`resource` 必須。
- 取得経路は `client.ChainResolver{Store, cimd.Resolver}`。`Store` にあればそれを優先し、なければ URL 形式の `client_id` だけを CIMD として取得する。URL 形式でない不明な `client_id` は従来どおり `storage.ErrNotFound`。
- CIMD 文書に `scope` がない MCP Client は scope の上限を持たない（`Scopes` 空 = 制限なし）。他 Profile では `Scopes` 空は不正のまま。事前登録のないクライアントの scope は resource ごとの上限（`resource.Resource.Scopes`）で絞る。
- `token_endpoint_auth_method=private_key_jwt` の CIMD Client は M4 で受理する。

### 7. Web Legacy Profile（2026-10-25 追加、未実装）

Conformance Suite の Basic OP プランは PKCE なしの認可要求を前提にしており、PKCE 必須のままでは 35 モジュール中 30 を評価できなかった（[conformance.md](../conformance.md)）。2026-10-24 の判断で予約した「必要なら新しい Profile で対応する」を、ADR-0009 で実体化した。

- 条件は §1 の表のとおり。Web との違いは PKCE だけで、提示されたら S256 で検証し、省略する場合は `openid` scope と `nonce` を必須とする（RFC 9700 §2.1.1）。トークン要求では PKCE Downgrade（RFC 9700 §4.8）を `invalid_grant` で拒否する。
- 条件表の PKCE は真偽値ではなく三値（該当なし / 必須 / 提示されたら検証）で持つ。`Client.RequiresPKCE()` は「必須か」の意味のまま残す。
- Engine 側に有効化の設定は置かない。新しく作るクライアントは Web を使う。

### 8. シークレットの再発行（2026-11-11 追加。草案）

状態は草案で、実装とともに PR に出している。マージで確定する。

confidential クライアント（Web / Machine）のシークレットは、登録後に再発行できる。これまでは手段がなく、漏えいしたら Client を作り直すしかなかった。作り直すと Grant がすべて失効し、ユーザーは同意をやり直すことになる。

- **形。** `Client.RotateSecret()` が新しいシークレット（256 bit 乱数）を生成し、ハッシュを差し替えた Client と平文を返す。保存は `Store.RotateClientSecret(ctx, id, secretHash)` で行う。値の指定は受け付けない（登録時の `WebParams.Secret` は既存システムからの移行のためのもので、再発行には要らない）。public クライアントでは `client.ErrInvalid`。
- **即時に切り替える。** 保存した時点で旧シークレットは使えなくなり、新旧を併用する期間は置かない。Client 側の設定を差し替えるまで、トークンエンドポイントへの要求は `invalid_client` になる（発行済みの Access Token はそのまま使える）。併用期間を持つ形（旧ハッシュと期限を別に保存する）も検討したが、採らなかった。漏えいへの対応では旧シークレットを直ちに止めるのが正しく、併用は「無停止で定期交換したい」場合のための機能である。それには列の追加と、認証のたびに期限を見る分岐が要る。無停止の交換は、M4a の `private_key_jwt`（ADR-0010。鍵を複数登録できる）で、共有シークレットより素直に実現できる。
- **Store の専用メソッドにする。** `UpdateClient` は読んでから書く使い方（`GetClient` → `Client.Update` → `UpdateClient`）なので、`UpdateClient` がシークレットのハッシュも書くと、再発行より前に読んだ Client の保存で旧シークレットが戻る。無効にしたはずの値が黙って有効に戻るのは、他の項目の「後から保存した方が勝つ」とは重さが違う。そこでシークレットの書き込みを `RotateClientSecret` だけにし、`UpdateClient` はシークレットに触れないようにした（ADR-0005 §2）。
- **トークンと Grant には触れない。** 再発行は Client 認証の資格情報の交換であり、ユーザーの同意とは別のものである。攻撃者が Refresh Token も得ているおそれがあるなら、運用者が Grant を失効させる（`grant.Service.Revoke`。対象は `grant.Service.ListByClient` で一覧できる）。

## 影響

- Client の登録はまず Go API のみ（`Store.CreateClient`）。登録用 HTTP API・CLI は `examples/` に置き、コアには含めない。2026-11-11 に、運用者向けの管理 API の例として `examples/standalone/adminapi`（Bearer 認証付きの JSON API。Client の一覧・登録・更新・削除、シークレットの再発行、Client ごとの Grant の一覧と失効）を置いた。コアに HTTP の管理 API を入れない方針は変えていない。2026-10-25 に更新（`Client.Update` → `Store.UpdateClient`）と削除（`Store.DeleteClient`）を追加した。`Client.Update` は §2 の開放項目だけを受け取り、`Store.UpdateClient` は保存済みの Profile と違う値を `storage.ErrStateConflict` で拒否する（§4）。
- Profile の条件表は `client/profile.go` にテーブルとして持ち、テストで表と実装の一致を検証する。MCP Client の列も同じテーブルにある。Web Legacy の列も同じテーブルに足す（ADR-0009 §4）。
