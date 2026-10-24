# ADR-0004: Client Profile

- 状態: 採用（2026-10-24 合意）
- 日付: 2026-10-24

## 文脈

RFC 6749 は Client に多数の選択肢（grant type、response type、クライアント認証方式、PKCE の有無、redirect URI の照合規則）を与える。これを利用者に選ばせると、安全でない組み合わせが生まれる。
技術スタック案の「Client Profile で用途別に固定する」方針を採用し、何を固定し何を開放するかを決める。

## 決定

### 1. 3 つの標準 Profile と固定項目

| 項目 | Web Application | Native / CLI | Machine to Machine |
| --- | --- | --- | --- |
| Client 種別（RFC 6749 §2.1） | confidential | public | confidential |
| grant_types | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` | `client_credentials` |
| response_types | `code` | `code` | なし |
| PKCE | S256 必須 | S256 必須 | 該当なし |
| token_endpoint_auth_method | `client_secret_basic`（`client_secret_post` も受理） | `none` | `client_secret_basic`（P2 で `private_key_jwt` 追加） |
| redirect_uri 照合 | 完全一致、`https` のみ（開発用に `http://localhost` / loopback を許可する設定あり） | 完全一致。ただし loopback（`http://127.0.0.1` / `http://[::1]`）はポート番号を無視して照合（RFC 8252 §7.3）。カスタムスキーム・`https` のクレーム URL も可 | なし |
| Refresh Token | 発行する。Rotation 必須 | 発行する。Rotation 必須、再利用検知で Token Family を失効（RFC 9700 §4.14） | 発行しない |
| ID Token | `openid` scope 要求時に発行 | 同左 | 発行しない |
| `response_mode` | `query` のみ | `query` のみ | — |

`localhost` ホスト名は RFC 8252 §8.3 の推奨に従い Native では既定で許可しない（loopback IP リテラルを使う）。

### 2. 利用者に開放する項目

- `client_id`（未指定なら生成）、表示名、ロゴ URL、ポリシー URL
- `redirect_uris`（Profile の照合規則の範囲内）
- `allowed_scopes`（Client が要求できる scope の上限）
- `client_secret`（confidential のみ。エンジンが生成して 1 回だけ返す。保存はハッシュ）
- トークン有効期間（Profile ごとの上限内で短縮のみ可。例: Access Token 既定 1 時間、上限 24 時間）
- ID Token 署名アルゴリズム（RS256 / ES256）
- P1 以降: 許可する `resource`（audience）

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

- 生成関数は Profile ごとに 1 つ（`NewWeb`, `NewNative`, `NewMachine`）。不正なパラメータは生成時に `error` で返し、不正な Client 値は存在させない。
- `Client` は Profile を保持し、`Allows(grantType)`, `MatchRedirectURI(uri)`, `AuthenticationMethod()` などの問い合わせを Profile に委譲する。エンドポイント側に Profile の条件分岐を書かない。
- Profile は登録後に変更できない。用途が変わる場合は Client を作り直す。

### 5. 「エスケープハッチ」を置かない

Custom Profile（任意組み合わせ）は P0 では提供しない。PKCE 非対応のレガシークライアントは接続できないことを意図した制約として明記する。要望が出た場合も、新たな Profile（例: `MCP`、`Confidential Native`）を追加する形で応じ、個別フラグの開放はしない。

### 6. 将来の Profile

- **MCP Client**（P1）: public、CIMD（Client ID Metadata Document）で動的に識別、`resource` 必須。登録済み Client ではなく URL を `client_id` とするため、Client の取得経路が `Store` ではなく `ClientResolver` インターフェースになる。P0 の時点でこの差し替え点だけ確保する（ADR-0007）。

## 影響

- Client の登録はまず Go API のみ（`Store.CreateClient`）。登録用 HTTP API・CLI は `examples/` に置き、コアには含めない。
- Profile の条件表は `client/profile.go` にテーブルとして持ち、テストで表と実装の一致を検証する。
