# OpenID Conformance Suite（Basic OP）

- 対象: OpenID Foundation Conformance Suite の `oidcc-basic-certification-test-plan`
  （variant: `server_metadata=discovery`, `client_registration=static_client`）
- 状態: **準備済み・未実行**（2026-10-24）。Suite は公開 Docker イメージがなくソースからの
  Maven ビルドが必要なため、M2 ではローカルで回すための構成・設定・手順まで整備し、実行と結果の
  記録は次の作業とする。実行したらこの文書の「結果」を更新すること。

## 構成

```
Docker（Conformance Suite）                      ホスト
┌──────────────────────────────────────┐        ┌──────────────────────────────────────┐
│ server  https://localhost.emobix.co.uk:8443 │ ──▶ │ auth-engine  http://host.docker.internal:8080 │
│  （テストランナー + 内蔵ブラウザ）             │ ──▶ │ loginapp     http://host.docker.internal:8082 │
│ mongodb, nginx                        │        │ Interaction API 127.0.0.1:8081（内部）      │
└──────────────────────────────────────┘        └──────────────────────────────────────┘
```

- Suite はコンテナ内から OP にアクセスするので、Issuer は `http://host.docker.internal:8080` にする。
  エンジンは既定で localhost 以外の http Issuer を拒否するため、`Config.AllowInsecureIssuer`
  （examples では `-allow-insecure-issuer`）で緩和する。**本番では使わない**。
- Interaction App は `examples/standalone/loginapp` を `-auto-approve` で使う。Cookie セッションにより
  `prompt=none`（セッションなしなら `login_required`）、`prompt=login`（再認証）、`max_age`
  （超過時は再認証、未超過なら元の `auth_time`）を解釈する。
- Suite 側の Client は [conformance/clients.json](../conformance/clients.json) で静的登録する
  （Web Profile、`client_secret_basic` / `client_secret_post` 両対応。シークレットは
  `client.WebParams.Secret` で指定）。redirect URI は Suite の alias `auth-engine` に対応する
  `https://localhost.emobix.co.uk:8443/test/a/auth-engine/callback` と、クエリ付きの変種。
- Suite の設定は [conformance/basic-op.json](../conformance/basic-op.json)。

## 手順

前提: Docker、Java 17+、Maven、Python 3（`requests`）。`localhost.emobix.co.uk` は Suite が
配布する証明書に合わせて 127.0.0.1 に解決されるホスト名。

1. auth-engine を起動する（端末 1）。DB と鍵は使い捨てでよい。

   ```bash
   cd examples/standalone && go run ./cmd/server \
     -issuer http://host.docker.internal:8080 -allow-insecure-issuer \
     -login-url http://host.docker.internal:8082/login \
     -auto-approve -clients ../../conformance/clients.json \
     -db ./conformance.db -keys ./conformance-keys.json
   ```

2. Suite を取得・ビルド・起動し、テストプランを実行する（端末 2）。

   ```bash
   ./conformance/run.sh
   ```

   `run.sh` は `../conformance-suite` に Suite を clone して `mvn package` し、`docker compose up -d` の後に
   `scripts/run-test-plan.py` でプランを実行する。結果は `https://localhost.emobix.co.uk:8443/` の
   UI でも確認できる（devmode のためログイン不要）。

3. 失敗したテストを `expected-failures.json` と突き合わせ、想定外の失敗はエンジンを修正する。

## 想定される結果（実行前の見積もり）

| 分類 | テスト（抜粋） | 見込み | 根拠 |
| --- | --- | --- | --- |
| Discovery / JWKS | `oidcc-discovery-endpoint-verification`, `oidcc-server` | 通る | OIDC Discovery 1.0 の必須項目を返す。`id_token_signing_alg_values_supported` に RS256 |
| Code フロー | `oidcc-server`, `oidcc-ensure-request-with-valid-pkce-succeeds`, `oidcc-ensure-post-request-succeeds` | 通る | PKCE S256 必須、`POST /authorize` 対応 |
| redirect_uri | `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-redirect-uri-in-authorization-request`, `oidcc-redirect-uri-query-OK`, `oidcc-redirect-uri-query-added/mismatch/regex` | 通る | 完全一致。OIDC 要求では `redirect_uri` 必須（M2 で修正） |
| client 認証 | `oidcc-server-client-secret-post`, `oidcc-ensure-client-id-in-token-endpoint...` | 通る | `client_secret_basic` / `client_secret_post` |
| Code の再利用 | `oidcc-codereuse`, `oidcc-codereuse-30seconds` | 通る | 単回消費、再利用で Family 失効 |
| ID Token | `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, `oidcc-id-token-hint`, `oidcc-max-age-1`, `oidcc-max-age-10000`, `oidcc-ensure-request-with-acr-values-succeeds` | 通る | `auth_time` は常に含む。`max_age` は loginapp が解釈し、エンジンも検証 |
| prompt | `oidcc-prompt-login`, `oidcc-prompt-none-logged-in`, `oidcc-prompt-none-not-logged-in` | 通る | loginapp の Cookie セッションで判断 |
| UserInfo / Claims | `oidcc-userinfo-get`, `oidcc-userinfo-post-header`, `oidcc-userinfo-post-body`, `oidcc-scope-profile/email/address/phone/all` | 通る | OIDC Core §5.4 の対応表で絞る。デモ Claims は loginapp が全項目を渡す |
| Refresh | `oidcc-refresh-token` | 通る | Rotation、Refresh 応答の ID Token は `auth_time` を保ち `nonce` を含まない |
| Request Object | `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`, `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported` | 通る（拒否として） | `request_not_supported` / `request_uri_not_supported` を返す。Discovery で `request_parameter_supported: false` |
| claims パラメータ | `oidcc-claims-essential`, `oidcc-claims-locales` | 通る（スキップまたは無視） | `claims_parameter_supported: false`。未知のパラメータは無視する |
| 鍵ローテーション | `oidcc-server-rotate-keys` | **失敗を想定** | テスト中に手動で鍵を差し替える必要がある。examples には鍵差し替えの操作がない（`expected-failures.json`） |
| Dynamic Registration | `oidcc-registration-*` | 対象外 | `client_registration=static_client` のプランには含まれない |

## 結果

未実行。実行後にここへ Suite のバージョン、実行日、プランの結果一覧（PASS / WARNING / FAILURE / SKIPPED）、
`expected-failures.json` との差分を記録する。

## 補足

- Suite はブラウザ操作を内蔵ブラウザで自動化する。loginapp は `-auto-approve` で画面を出さないので
  `basic-op.json` の `browser` 設定は不要。
- Issuer を http にしているのはローカル実行の都合。Suite は devmode では http の OP を許容するが、
  警告が出る場合がある。https で回したい場合はリバースプロキシを前段に置き、Issuer を https にする。
