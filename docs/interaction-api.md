# Interaction API 仕様（Interaction App 実装者向け）

- 対象バージョン: M2（2026-10-24）
- 設計の背景: [ADR-0003 Interaction App との契約](adr/0003-interaction-contract.md)
- 参考実装: [examples/standalone/loginapp](../examples/standalone/loginapp/loginapp.go)

エンジンはログイン・同意画面を持たない。`/authorize` を受けると Authorization Transaction（以下 Txn）を作り、ブラウザをあなたの Interaction App へ送る。Interaction App はこの API で Txn の内容を取得し、結果を返し、ブラウザをエンジンへ戻す。

## 全体の流れ

```
1. ブラウザ → エンジン   GET /authorize?...                 Txn 作成、結合 Cookie を発行
2. エンジン → ブラウザ   302 {InteractionURL}?txn={txn_id}
3. あなたのアプリ        GET  {InteractionAPI}/transactions/{txn_id}     ← バックチャネル
4. あなたのアプリ        ログイン・同意 UI（エンジンは関与しない）
5. あなたのアプリ        POST {InteractionAPI}/transactions/{txn_id}/complete  （または /reject）
                         → 200 {"resume_url": "..."}
6. あなたのアプリ → ブラウザ   302 resume_url
7. ブラウザ → エンジン   GET /authorize/resume?txn=...&token=...  Cookie 照合、Code 発行
8. エンジン → ブラウザ   302 {redirect_uri}?code=...&state=...&iss=...
```

ブラウザの URL に載るのは Txn ID だけである。要求内容（scope や client）は必ず 3 のバックチャネルで取得する。

## 接続

- ベース URL は利用者が `httpapi.Server.InteractionHandler()` を bind したアドレス。インターネットに公開しないこと。
- 認証は `Authorization: Bearer <token>`。トークンはエンジン側の `httpapi.Config.InteractionAuth`（既定 `BearerAuthenticator`）に設定した値。
- 認証失敗は `401` と `WWW-Authenticate: Bearer realm="interaction"`。
- 要求本文は JSON、64 KB まで。未知のフィールドがあると `400 invalid_body`。
- 応答は常に `Content-Type: application/json`、`Cache-Control: no-store`。

## エラー応答の形

```json
{"error": "not_found", "error_description": "transaction not found"}
```

| HTTP | `error` | 意味 | 推奨する扱い |
| --- | --- | --- | --- |
| 400 | `invalid_body` | JSON が不正、または未知のフィールド | 実装の不具合。修正する |
| 400 | `invalid_outcome` | 結果が契約に反する（後述） | 実装の不具合、または `max_age` 違反。説明文を見て対処 |
| 401 | `unauthorized` | Bearer トークン不一致 | 設定を確認 |
| 404 | `not_found` | Txn が存在しない | 「最初からやり直してください」を表示 |
| 409 | `not_pending` | 既に Complete / Reject 済み | 同上。二重送信の可能性 |
| 410 | `expired` | Txn の期限切れ（既定 10 分） | 同上 |
| 500 | `server_error` | エンジン内部エラー | 一時的な障害として表示 |

## GET /transactions/{txn_id}

Txn の内容を返す。画面を描くために必要な情報だけを含み、`state`・`nonce`・`code_challenge` は含めない。

```json
{
  "id": "k2f...",
  "status": "pending",
  "created_at": "2026-10-24T12:00:00Z",
  "expires_at": "2026-10-24T12:10:00Z",
  "client": {
    "client_id": "web-app",
    "name": "Example Web",
    "profile": "web",
    "logo_uri": "https://app.example.com/logo.png",
    "policy_uri": "https://app.example.com/policy"
  },
  "request": {
    "scopes": ["openid", "profile"],
    "prompt": ["login"],
    "max_age": 300,
    "login_hint": "alice@example.com",
    "ui_locales": "ja en",
    "acr_values": "urn:example:acr:mfa",
    "resource": ["https://api.example.com"]
  }
}
```

| フィールド | 説明 |
| --- | --- |
| `status` | `pending` / `completed` / `rejected` / `consumed`。画面を出すのは `pending` のときだけ |
| `client.profile` | `web` / `native` / `machine`。Native は端末上のアプリなので、同意画面の文言を変えるときに使う |
| `request.scopes` | クライアントが要求した scope。ユーザーはこの部分集合を承認できる |
| `request.prompt` | OIDC の `prompt`。`none` を含むなら UI を出してはならない。ログイン状態がなければ `login_required` で Reject する。`login` は再認証、`consent` は同意画面の再表示を求めている |
| `request.max_age` | 秒。認証がこれより古ければ再認証させる。満たさない `authenticated_at` を送るとエンジンが `invalid_outcome` で拒否する |
| `request.login_hint` 他 | 透過。エンジンは解釈しない |

`completed` / `rejected` のときは `outcome` または `rejection` も返す（デバッグ用）。

## POST /transactions/{txn_id}/complete

ユーザーが認証され、同意した。

```json
{
  "subject": "user-42",
  "authenticated_at": "2026-10-24T12:03:00Z",
  "granted_scopes": ["openid", "profile"],
  "amr": ["pwd", "otp"],
  "acr": "urn:example:acr:mfa",
  "claims": {"name": "Alice", "email": "alice@example.com", "email_verified": true}
}
```

| フィールド | 必須 | 制約 |
| --- | --- | --- |
| `subject` | 必須 | 空でない文字列。エンジンにとって不透明。ID Token の `sub`、Grant のキーになる。安定した識別子（内部 ID）を使い、メールアドレスのように変わり得る値は避ける |
| `authenticated_at` | 必須 | RFC 3339。実際に認証した時刻。既存セッションを再利用した場合はそのセッションの認証時刻 |
| `granted_scopes` | 必須 | `request.scopes` の空でない部分集合。すべて拒否する場合は Reject を使う |
| `amr` | 任意 | 認証方式（RFC 8176）。ID Token に転記 |
| `acr` | 任意 | 認証コンテキスト。ID Token に転記 |
| `claims` | 任意 | UserInfo に載せる Claims のスナップショット。エンジンは OIDC Core §5.4 の対応表に従い、付与された scope に対応する標準 Claims だけを返す（標準外の Claims はそのまま返す）。`sub` などエンジンが決める Claims は無視される。ID Token には載せない |

成功: `200 {"resume_url": "https://as.example.com/authorize/resume?txn=...&token=rs_..."}`

ブラウザを `resume_url` へ 302 で送る。`resume_url` は単回使用で、Txn の期限内に使われなければ無効になる。

## POST /transactions/{txn_id}/reject

ユーザーが拒否した、または進められない。

```json
{"error": "access_denied", "error_description": "The user denied the request"}
```

| `error` | 使う場面 |
| --- | --- |
| `access_denied` | ユーザーが同意しなかった |
| `login_required` | `prompt=none` でログイン状態がない |
| `consent_required` | `prompt=none` で同意が必要 |
| `interaction_required` | `prompt=none` で何らかの操作が必要 |
| `server_error` | Interaction App 側の障害 |

成功: `200 {"resume_url": "..."}`。エンジンは Resume 時にクライアントへエラー応答（`error`, `error_description`, `state`, `iss`）をリダイレクトで返す。

## 守ってほしいこと

1. **Txn ID を自アプリのセッションに紐づける。** `?txn=` で届いた ID をセッションに保存し、POST では保存済みの値だけを使う。攻撃者が用意した Txn を被害者に完了させる攻撃（login CSRF）を自アプリ側で防ぐ。エンジン側はクライアントの `state` と PKCE に依存している。
2. **ログインフォームに CSRF 対策を入れる。** これはあなたのアプリの通常の責務である。
3. **`granted_scopes` はユーザーが実際に見て承認したものだけ。** 要求外の scope はエンジンが拒否するが、要求内でも見せていない scope を付与してはならない。
4. **`authenticated_at` を偽らない。** `max_age` の判定に使う。
5. **`resume_url` をログに残さない。** 単回使用トークンを含む。
6. **Interaction API を公開ネットワークに出さない。** 内部ネットワークか、少なくとも IP 制限の内側に置く。

## GET /grants?subject=...&client_id=...

同じ `client_id` × `subject` に対する過去の同意（Grant）を返す。`subject` は必須。`client_id` を付けると、その Client に対する有効な Grant だけ（0 または 1 件）を返す。付けなければ `subject` の有効な Grant をすべて返す（「連携済みアプリ一覧」用）。失効済みの Grant は含まない。

```json
{
  "grants": [
    {
      "client_id": "web-app",
      "subject": "user-42",
      "scopes": ["openid", "profile"],
      "created_at": "2026-10-01T09:00:00Z",
      "updated_at": "2026-10-24T12:03:00Z"
    }
  ]
}
```

Claims は返さない。`subject` がないときは `400 invalid_request`。

### 同意のスキップ

ログイン後に `GET /grants?subject={subject}&client_id={txn.client.client_id}` を呼び、`request.scopes` が返ってきた `scopes` に含まれていれば同意画面を省いて Complete してよい。ただし `request.prompt` に `consent` が含まれていれば必ず同意画面を出す。`prompt=none` で同意が足りない場合は `consent_required` で Reject する。

Grant の `scopes` は過去の同意の和集合である。Complete の `granted_scopes` はその回に承認された scope だけを渡せばよく、エンジン側で和集合に加える。

### 連携の解除

「このアプリとの連携を解除する」操作は M2 では HTTP では提供せず、Go API `Engine.Grants.Revoke(ctx, clientID, subject)` で行う（Grant と配下の全トークンが失効する）。Interaction App が別プロセスの場合は、HTTP での提供が必要になった時点で `DELETE /grants` を追加する。

## Go から直接呼ぶ場合

Interaction App が Go で書かれ、エンジンを同一プロセスに埋め込む構成では、HTTP を介さず `authorization.Service` の `Complete` / `Reject` を直接呼べる。契約（検証・エラー）は HTTP と同一である。
