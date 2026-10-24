# ADR-0004: Client Profile

- 状態: 採用（2026-10-24 合意）。2026-10-25 更新: M3 で MCP Client Profile を追加（[ADR-0008](0008-mcp-integration.md) §4）
- 日付: 2026-10-24（2026-10-25 更新）

## 文脈

RFC 6749 は Client に多数の選択肢（grant type、response type、クライアント認証方式、PKCE の有無、redirect URI の照合規則）を与える。これを利用者に選ばせると、安全でない組み合わせが生まれる。
技術スタック案の「Client Profile で用途別に固定する」方針を採用し、何を固定し何を開放するかを決める。

## 決定

### 1. 4 つの標準 Profile と固定項目

P0 は Web / Native / Machine の 3 つ。MCP Client は M3 で追加した（§6、ADR-0008 §4）。

| 項目 | Web Application | Native / CLI | Machine to Machine | MCP Client（M3） |
| --- | --- | --- | --- | --- |
| Client 種別（RFC 6749 §2.1） | confidential | public | confidential | public |
| 識別 | 登録済み `client_id` | 同左 | 同左 | CIMD 文書の HTTPS URL を `client_id` とする。`Store` に事前登録することもできる（CIMD §7） |
| grant_types | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` | `client_credentials` | `authorization_code`, `refresh_token` |
| response_types | `code` | `code` | なし | `code` |
| PKCE | S256 必須 | S256 必須 | 該当なし | S256 必須 |
| token_endpoint_auth_method | `client_secret_basic`（`client_secret_post` も受理） | `none` | `client_secret_basic`（P2 で `private_key_jwt` 追加） | `none`（`private_key_jwt` は M4） |
| redirect_uri 照合 | 完全一致、`https` のみ（開発用に `http://localhost` / loopback を許可する設定あり） | 完全一致。ただし loopback（`http://127.0.0.1` / `http://[::1]`）はポート番号を無視して照合（RFC 8252 §7.3）。カスタムスキーム・`https` のクレーム URL も可 | なし | CIMD 文書の `redirect_uris` と完全一致（`https`、または `http://localhost`）。loopback IP リテラルはポート番号を無視。`http://localhost` はポートまで完全一致 |
| `resource`（RFC 8707） | 任意 | 任意 | 任意 | **必須**。欠落は `invalid_request` |
| Refresh Token | 発行する。Rotation 必須 | 発行する。Rotation 必須、再利用検知で Token Family を失効（RFC 9700 §4.14） | 発行しない | Native と同じ（MCP 仕様 Security Considerations「Token Theft」） |
| ID Token | `openid` scope 要求時に発行 | 同左 | 発行しない | `openid` scope 要求時に発行 |
| `response_mode` | `query` のみ | `query` のみ | — | `query` のみ |

`localhost` ホスト名は RFC 8252 §8.3 の推奨に従い Native では既定で許可しない（loopback IP リテラルを使う）。MCP Client だけは `http://localhost` を許可する。MCP 仕様「Communication Security」が redirect URI を「`localhost` か HTTPS」と定め、CIMD 文書の例も `http://localhost:3000/callback` を使うため、拒否すると相互運用できない。RFC 8252 §8.3 の懸念（名前解決の乗っ取り）は残るので、Interaction App に redirect URI のホスト名を同意画面に出させる（[Interaction API 仕様](../interaction-api.md)「`profile` が `mcp` のとき」）。

### 2. 利用者に開放する項目

- `client_id`（未指定なら生成）、表示名、ロゴ URL、ポリシー URL
- `redirect_uris`（Profile の照合規則の範囲内）
- `allowed_scopes`（Client が要求できる scope の上限）
- `client_secret`（confidential のみ。エンジンが生成して 1 回だけ返す。保存はハッシュ）
- トークン有効期間（Profile ごとの上限内で短縮のみ可。例: Access Token 既定 1 時間、上限 24 時間）
- ID Token 署名アルゴリズム（RS256 / ES256）
- 許可する `resource`（`Resources`。M3 で追加。空なら `Config.Resources` に設定済みの全 resource を要求でき、指定があればその範囲に限る。ADR-0008 §2）
- `client_uri`（`ClientURI`。M3 で追加。CIMD 文書から取り込み、Interaction App に透過する）

### 3. 開放しない項目

- grant_types / response_types / response_mode
- PKCE の有無・方式
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

- 生成関数は Profile ごとに 1 つ（`NewWeb`, `NewNative`, `NewMachine`, `NewMCP`）。不正なパラメータは生成時に `error` で返し、不正な Client 値は存在させない。`NewMCP` だけはパラメータではなく CIMD 文書（`MetadataDocument`）と取得元 URL を受け取り、CIMD §3〜§4 の検証（`client_id` の形式、文書 URL との一致、共有シークレットの拒否）を行う。
- `Client` は Profile を保持し、`Allows(grantType)`, `MatchRedirectURI(uri)`, `AuthenticationMethod()` などの問い合わせを Profile に委譲する。エンドポイント側に Profile の条件分岐を書かない。
- Profile は登録後に変更できない。用途が変わる場合は Client を作り直す。

### 5. 「エスケープハッチ」を置かない

Custom Profile（任意組み合わせ）は提供しない。PKCE 非対応のレガシークライアントは接続できないことを意図した制約として明記する。要望が出た場合も、新たな Profile（例: `Confidential Native`）を追加する形で応じ、個別フラグの開放はしない。M3 の MCP Client はこの方針どおり Profile として追加した。`http://localhost` の許可も MCP Profile に固定し、他 Profile には開放していない。

### 6. MCP Client Profile（M3 で追加）

P0 では「将来の Profile」として、Client の取得経路を `client.Resolver` インターフェースにする差し替え点だけを確保していた（ADR-0007 §4）。M3 で次の形で実体化した（ADR-0008 §4〜§5）。

- 条件は §1 の表のとおり。public、CIMD（Client ID Metadata Document）の HTTPS URL を `client_id` とし、`resource` 必須。
- 取得経路は `client.ChainResolver{Store, cimd.Resolver}`。`Store` にあればそれを優先し、なければ URL 形式の `client_id` だけを CIMD として取得する。URL 形式でない不明な `client_id` は従来どおり `storage.ErrNotFound`。
- CIMD 文書に `scope` がない MCP Client は scope の上限を持たない（`Scopes` 空 = 制限なし）。他 Profile では `Scopes` 空は不正のまま。事前登録のないクライアントの scope は resource ごとの上限（`resource.Resource.Scopes`）で絞る。
- `token_endpoint_auth_method=private_key_jwt` の CIMD Client は M4 で受理する。

## 影響

- Client の登録はまず Go API のみ（`Store.CreateClient`）。登録用 HTTP API・CLI は `examples/` に置き、コアには含めない。
- Profile の条件表は `client/profile.go` にテーブルとして持ち、テストで表と実装の一致を検証する。MCP Client の列も同じテーブルにある。
