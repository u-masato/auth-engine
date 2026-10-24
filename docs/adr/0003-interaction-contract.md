# ADR-0003: Interaction App との契約（Authorization Transaction の引き渡し）

- 状態: 採用（2026-10-24 合意）
- 日付: 2026-10-24

## 文脈

ヘッドレス構成の核心は「ログインと同意を外部アプリに委ね、その結果だけを安全に受け取る」契約である。
技術スタック案ではこの契約が定義されていない。これを本 ADR で定める。

先行事例として Ory Hydra の login/consent flow（`login_challenge` → accept → `redirect_to` で Hydra に戻す二段階）がある。本設計も「外部アプリは結果をバックチャネルで伝え、ブラウザは一度エンジンに戻ってから Code を受け取る」二段階方式を採るが、login と consent を 1 つの Transaction に統合して往復回数を減らす。

## 用語

- **Protocol Engine**（以下エンジン）: 本 OSS。
- **Interaction App**: ログイン・同意を行う外部アプリケーション。利用者が実装する。
- **Authorization Transaction**（以下 Txn）: 1 回の `/authorize` 要求から Code 発行（または失敗）までを表す状態機械。

## 決定

### 1. 契約は Go の Use Case として定義し、HTTP はその一表現とする

契約の正本は `authorization` パッケージの 3 つの操作である。

```go
// /authorize を受けて Txn を作り、Interaction App へ送るための情報を返す。
Begin(ctx, AuthorizationRequest) (BeginResult, error)
// Interaction App が結果を伝える。成功時は Resume URL を返す。
Complete(ctx, TxnID, Outcome) (ResumeURL, error)
Reject(ctx, TxnID, Rejection) (ResumeURL, error)
// ブラウザが Resume URL に戻ってきたとき、Code を発行して Client にリダイレクトする。
Resume(ctx, TxnID, ResumeToken, BrowserBinding) (ClientRedirect, error)
```

- **同一プロセス構成**: Interaction App が Go で書かれエンジンを埋め込む場合、この Go API を直接呼ぶ。
- **別プロセス構成**（前提構成）: `httpapi` が同じ操作を **Interaction API** として HTTP で公開する。
- どちらでも状態遷移と検証ロジックは同一である。テストは Go API に対して書き、HTTP 層は薄く保つ。

### 2. フロー

```
Client ──(1) GET /authorize──▶ Engine
                                │ 検証OK → Txn 作成（state=pending）
                                │ ブラウザ結合 Cookie を設定
                                ◀─(2) 302 → {interaction_url}?txn={txn_id}
Browser ──(3)──────────────────▶ Interaction App
                                │ (4) GET  {interaction_api}/transactions/{txn_id}   ← バックチャネル
                                │ ログイン・同意 UI（エンジンは関与しない）
                                │ (5) POST {interaction_api}/transactions/{txn_id}/complete
                                │      → 200 {"resume_url": ".../authorize/resume?txn=...&token=..."}
                                ◀─(6) 302 → resume_url
Browser ──(7) GET /authorize/resume──▶ Engine
                                │ Cookie 照合・ResumeToken 単回消費・Code 発行
                                ◀─(8) 302 → {redirect_uri}?code=...&state=...&iss=...
```

### 3. 各ステップの規則

#### (1)(2) Begin

- `/authorize` の検証は RFC 6749 §4.1.1 と RFC 7636 §4.3、OIDC Core §3.1.2.2 に従う。
- `client_id` 不明または `redirect_uri` 不一致のときは **Client へリダイレクトしない**（RFC 6749 §4.1.2.1）。この場合のみエンジンが最小限のエラーページを描く。描写は `ErrorRenderer` インターフェースで差し替え可能とし、既定実装はプレーンな HTML 1 枚とする。
- それ以外の検証失敗（`invalid_scope`、`unsupported_response_type` 等）は Interaction App を介さず直接 Client へエラーリダイレクトする。
- Txn には要求パラメータ全体、Client の表示情報、作成時刻、期限（既定 10 分）、ブラウザ結合値のハッシュを保存する。
- Txn ID は 256 bit の乱数（`crypto/rand`、base64url）。URL に載るのは Txn ID のみで、要求内容は載せない。
- Interaction App へのリダイレクト先 `interaction_url` はエンジン設定で 1 つ固定する。Client ごとの分岐はさせない。

#### (4) Txn の参照

Interaction App は Txn ID をキーにバックチャネルで内容を取得する。URL に署名付き JWT で内容を載せる方式は、Interaction App 側に鍵検証を要求するため採らない。

返す内容:

| フィールド | 内容 |
| --- | --- |
| `id`, `expires_at`, `status` | Txn の識別と期限 |
| `client` | `client_id`, 表示名, Profile 種別, ロゴ・ポリシー URL（登録されていれば） |
| `requested_scopes` | 要求 scope |
| `prompt`, `max_age`, `login_hint`, `ui_locales`, `acr_values` | OIDC Core §3.1.2.1 のヒント群。エンジンは解釈せず透過する |
| `existing_grant` | 同じ Client × subject に既存 Grant があれば、その付与済み scope（同意スキップ判断の材料。subject は Interaction App がログイン後に照会する形になるため、ここでは `lookup` 用の別エンドポイントとして提供する） |

`prompt=none` や `max_age` の扱いはエンジンでは判断できない（ユーザーセッションを持たない）。Interaction App が `prompt=none` でログイン状態を確認できなければ `login_required` で Reject する、という責務分担を README に明記する。

#### (5) Complete / Reject

`Outcome`（成功）:

| フィールド | 必須 | 内容 |
| --- | --- | --- |
| `subject` | 必須 | エンジンにとって不透明な文字列。空文字は拒否 |
| `authenticated_at` | 必須 | 認証時刻。`max_age` が要求されていれば `now - authenticated_at <= max_age` をエンジンが検証し、満たさなければ `login_required` 相当として失敗させる |
| `granted_scopes` | 必須 | `requested_scopes` の部分集合。部分集合でなければ拒否 |
| `amr`, `acr` | 任意 | ID Token にそのまま載せる |
| `claims` | 任意 | ID Token / UserInfo 用の Claims スナップショット（ADR-0006） |
| `remember_consent` | 任意 | Grant を永続化するか（既定 true） |

`Rejection`:

| フィールド | 内容 |
| --- | --- |
| `error` | `access_denied`, `login_required`, `consent_required`, `interaction_required`, `server_error` のいずれか（RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6） |
| `error_description` | 任意 |

規則:

- Complete / Reject は Txn の状態を `pending → completed | rejected` に **CAS（compare-and-swap）で 1 回だけ** 遷移させる。2 回目以降は `409 Conflict`。
- 期限切れ Txn への Complete / Reject は `410 Gone`。
- 成功応答には `resume_url` と、その中の `ResumeToken`（256 bit 乱数、単回使用、Txn に保存するのはハッシュ）を含める。
- Code は **この時点では発行しない**。Interaction App は Code を目にしない。

#### (7)(8) Resume

- `ResumeToken` のハッシュが一致し、Txn が `completed | rejected`、未期限、かつ **ブラウザ結合 Cookie が一致** するときのみ進める。
- 成功なら Code を発行し、Txn を `consumed` へ CAS 遷移させる。応答には `code`, `state`, `iss`（RFC 9207）を付ける。`response_mode` は `query` のみ。
- `rejected` なら Client へエラーリダイレクト。
- 不一致・再利用・期限切れは Client へリダイレクトせず、エラーページ（`ErrorRenderer`）を描く。

#### ブラウザ結合（Txn ハイジャック対策）

- `/authorize` でエンジンが Cookie `__Host-ae_bind` を発行する（未保持の場合のみ。保持済みなら再利用するので同一ブラウザで複数 Txn を並行できる）。属性: `Secure; HttpOnly; SameSite=Lax; Path=/`。
- Txn にはこの Cookie 値の SHA-256 を保存する。Resume は top-level GET ナビゲーションなので `SameSite=Lax` でも Cookie が送られる。
- これにより、Resume URL が漏れても **別ブラウザからは Code を受け取れない**。
- 開発用に `__Host-` プレフィックスなし・`Secure` なしを許す設定を置くが、既定は有効。無効化はログに警告を出す。
- Cookie を使えない環境向けの代替は P0 では提供しない。

### 4. Interaction API の認証と配置

- Interaction API は公開エンドポイント群（`/authorize` `/token` 等）とは **別の `http.Handler`** として提供する。利用者は内部ネットワーク専用のリスナーに bind できる。
- 認証は `InteractionAuthenticator` インターフェースで差し替え可能とし、既定実装は **事前共有の Bearer トークン**（`crypto/subtle.ConstantTimeCompare`）とする。mTLS は配置側（リバースプロキシ等）で実現する想定で、P0 ではエンジンに実装しない。
- Interaction App を OAuth Client として登録して `client_credentials` で認証させる案は、循環依存と初期設定の複雑化を招くため却下する。

### 5. タイムアウトと状態機械

```
pending ──Complete──▶ completed ──Resume──▶ consumed
   │                      │
   └──Reject──▶ rejected ─┴──Resume──▶ consumed
   │
   └──expires_at 経過──▶（どの遷移も失敗。掃除は Storage の Purge で行う）
```

| 期限 | 既定 | 設定可否 |
| --- | --- | --- |
| Txn 全体（Begin → Resume） | 10 分 | 可（上限 1 時間） |
| ResumeToken（Complete → Resume） | Txn 期限に従う。別途短縮しない | — |
| Authorization Code | 60 秒 | 可（上限 10 分、RFC 6749 §4.1.2） |

### 6. 脅威と対策の対応表

| 脅威 | 対策 |
| --- | --- |
| Txn ID の推測 | 256 bit 乱数 |
| Resume URL の盗用（別ブラウザ） | ブラウザ結合 Cookie |
| Resume URL の再利用 | ResumeToken 単回消費、Txn の CAS 遷移 |
| Interaction API のなりすまし | Bearer 認証、内部リスナーへの分離 |
| 攻撃者が開始した Txn を被害者に完了させる（login CSRF 型） | エンジン側では Client の `state` と PKCE に依存（RFC 9700 §4.7）。Interaction App 側で「自アプリのセッションに Txn ID を紐づける」ことを推奨事項として文書化 |
| AS Mix-Up | `iss` パラメータ（RFC 9207） |
| Code の横取り・再利用 | PKCE S256 必須、Code 単回消費、再利用検知時は当該 Code 由来の Grant を失効（RFC 6749 §4.1.2、RFC 9700 §4.5） |
| Interaction App が要求外の scope を付与 | `granted_scopes ⊆ requested_scopes` をエンジンが検証 |
| 古い認証での `max_age` 違反 | `authenticated_at` をエンジンが検証 |

## 却下した代替案

- **Complete 応答で Client 向け最終リダイレクト URL（Code 入り）を返し、Interaction App がそこへ転送する**: 往復が 1 回減るが、Code が Interaction App を通過し、ブラウザ結合の検査点がなくなる。
- **login と consent を別 Txn（二段階 challenge）にする**: Hydra 方式。同意を省くかどうかは Interaction App が判断すればよく、エンジンが 2 つの状態機械を持つ必要はない。
- **署名付き JWT で要求内容を Interaction App に渡す（ステートレス）**: Interaction App 側の鍵検証が必要になり、「少ない設定で使える」目標に反する。

## 影響

- Interaction App 実装者向けの仕様書（HTTP の具体的な JSON 形式、エラーコード、推奨事項）を `docs/interaction-api.md` として P0 中に書く。
- `examples/standalone` には「常に同じユーザーで自動承認する」テストモードの Interaction App を同梱し、E2E テストと Conformance Suite の双方で使う。
- PAR（RFC 9126、P2）は「Txn を `/authorize` より前に作る」だけで同じ状態機械に乗る。
