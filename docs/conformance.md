# OpenID Conformance Suite（Basic OP）

- 対象: OpenID Foundation Conformance Suite の `oidcc-basic-certification-test-plan`
  （variant: `server_metadata=discovery`, `client_registration=static_client`）
- 状態: **実行済み（2026-10-24、Suite release-v5.3.3）**。結果は本文末尾。要点: Basic OP プランは
  PKCE を付けない認可要求を正とするため、PKCE 必須のエンジン（ADR-0004 §5）では 35 モジュール中
  PKCE に依存しない 5 モジュールしか評価できない。その 5 件は PASSED 2・REVIEW 2（期待どおりの
  エラーページ）・SKIPPED 1（許容された挙動）。

## 構成

```
Docker（Conformance Suite）                      ホスト
┌──────────────────────────────────────┐        ┌──────────────────────────────────────┐
│ server  https://localhost.emobix.co.uk:8443 │ ──▶ │ auth-engine  http://host.docker.internal:8080 │
│  （テストランナー + 内蔵ブラウザ）             │ ──▶ │ loginapp     http://host.docker.internal:8082 │
│ mongodb, nginx                        │        │ Interaction API 127.0.0.1:8081（内部）      │
└──────────────────────────────────────┘        └──────────────────────────────────────┘
```

- Suite は GitLab のコンテナレジストリに公開イメージがある（`registry.gitlab.com/openid/conformance-suite:release-v5.3.3`
  と同 `/nginx`）。リポジトリの `docker-compose-prebuilt.yml` で起動でき、Java / Maven は不要。
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
- Suite の設定は [conformance/basic-op.json](../conformance/basic-op.json)。`browser` セクションは必須で、
  これがないと Suite は認可 URL を開かず WAITING のまま 4 分でタイムアウトする（サーバーログ
  `Could not find a match for url`）。loginapp は画面を出さないので、通常は callback の到着を待つだけでよい。
  エラーページを見せるべきテスト（redirect_uri 不一致）は `override` で「Authorization error」の表示を待ち、
  画面を撮って REVIEW にする。
- `expected-failures.json` / `expected-skips.json` は Suite の `--expected-failures-file` /
  `--expected-skips-file` の形式。`configuration-filename` はフルパスと照合されるので `*basic-op.json`。

## 手順

前提: Docker（compose v2）、Python 3、git。`localhost.emobix.co.uk` は Suite が配布する証明書に合わせて
127.0.0.1 に解決される公開 DNS 名。

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

   `run.sh` は `../conformance-suite` に Suite を clone し、公開イメージで `docker compose up -d` した後、
   venv に入れた `scripts/run-test-plan.py` でプランを実行する。結果の zip は `conformance/.work/export/` に、
   詳細は `https://localhost.emobix.co.uk:8443/` の UI で確認できる（devmode のためログイン不要）。
   ポート 8080〜8082 が使えないときは `OP_PORT=8090 ./conformance/run.sh` のようにし、auth-engine 側の
   `-issuer` / `-public-addr` / `-interaction-addr` / `-login-addr` / `-login-url` も合わせる。
   `RERUN=1:2,1:35` で一部のモジュールだけ再実行できる（番号は `--list` の出力）。

3. 失敗したテストを `expected-failures.json` と突き合わせ、想定外の失敗はエンジンを修正する。

## 想定される結果（実行前の見積もり。実際には PKCE の非互換で大半が評価できなかった。下の「結果」を参照）

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

## 結果（2026-10-24、Suite release-v5.3.3、プラン `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`）

### PKCE 必須との非互換

Basic OP プランの 35 モジュールのうち 30 は、`code_challenge` を付けない認可要求から始まる
（OIDC Core は PKCE を要求しないため）。エンジンは全 Profile で PKCE S256 を必須にしており
（ADR-0004 §5「PKCE 非対応のレガシークライアントは接続できない」、RFC 9700 §2.1.1）、これらは
認可エンドポイントで `invalid_request: code_challenge is required` を返して INTERRUPTED になる。
これはエンジンの不具合ではなく設計上の選択で、Suite 側に Basic OP プランで PKCE を常用させる
設定はない（PKCE を使うのは FAPI 系と eKYC の Security Profile テストのみ）。

したがって Basic OP の**認定は現状の設計では取れない**。選択肢は次のとおり:

1. 現状維持。Basic OP 認定は目標にせず、PKCE を使うプロファイル（FAPI 2.0 Security Profile など、M4 以降）で適合性を示す
2. Conformance 実行専用の緩和（`AllowPKCEless` のような開発用フラグ）を置き、認定ではなく「PKCE 以外の実装の検証」に使う。CLAUDE.md の不変条件と ADR-0004 §5 に反するため、置くなら ADR で範囲を限定する
3. Web Profile に限り PKCE を任意にする（RFC 9700 §2.1.1 は confidential クライアントに PKCE か `nonce` のどちらかを求めており、OIDC では `nonce` で代替できる）。ADR-0004 §1 の条件表の変更になる

**判断（2026-10-24）: 1 を採る。** PKCE 必須は維持し、Basic OP 認定は目標にしない。理由:
主な利用者（MCP クライアント、Native アプリ、BFF 経由の SPA）は PKCE を使うため制約にならず、
ADR-0001「選ばせない」・ADR-0004 §5・RFC 9700 と整合する。2 は ADR-0004 §5 が却下したエスケープハッチであり、
認定にも使えない（認定はデプロイされた設定に対して行う）。3 は `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
（`nonce` なしでも成功を要求）があるため「PKCE か `nonce`」では足りず、Web Profile を素の RFC 6749 まで
緩めることになる。将来 Basic OP 認定が必要になった場合は、Web Profile を緩めるのではなく ADR-0004 §5 に従って
新しい Profile（例: confidential、PKCE は提示されれば検証・省略可）を追加し、その Profile のクライアントで
認定を受ける。ADR の変更はその時点で行う。

### 評価できた 5 モジュール

| モジュール | 結果 | 内容 |
| --- | --- | --- |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | **PASSED**（48 SUCCESS、0 WARNING） | PKCE 付きの完全なフロー: Discovery、認可、Code 交換（`client_secret_basic`）、ID Token の署名・`iss`・`aud`・`nonce`・`at_hash`・`auth_time` 検証、UserInfo の `sub` 一致 |
| `oidcc-response-type-missing` | **PASSED** | `response_type` なしの要求に `invalid_request` をリダイレクトで返す |
| `oidcc-ensure-registered-redirect-uri` | **REVIEW** | 未登録の `redirect_uri` ではリダイレクトせずエラーページを表示（OIDC Core §3.1.2.1）。Suite が画面を撮り、人が確認する項目 |
| `oidcc-ensure-request-object-with-redirect-uri` | **REVIEW** | 同上（`request` オブジェクト付き、RFC 6749 §3.1.2） |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | **SKIPPED**（期待どおり） | `request_not_supported` を返す。Suite はこれを許容された挙動として検知しスキップする |

`oidcc-ensure-request-with-valid-pkce-succeeds` が通っていることから、ID Token・JWKS・UserInfo・クライアント認証の
基本経路は Suite の検証条件を満たしている。残り 30 モジュールが検証している内容は自前のテストで押さえる:

| Suite のモジュール | 自前テスト |
| --- | --- |
| `oidcc-server`, `oidcc-userinfo-get`, `oidcc-alternate-happy-flow` | `httpapi` の `TestFullAuthorizationCodeFlow`、`tests/lifecycle_test.go` の `TestOIDCTokenLifecycle` |
| `oidcc-userinfo-post-header`, `oidcc-userinfo-post-body` | `httpapi` の `TestUserInfoPostWithAuthorizationHeader`、`TestFullAuthorizationCodeFlow`（POST 本文） |
| `oidcc-scope-profile/email/address/phone/all` | `oidc/oidc_test.go` の `TestFilterClaims`、`oidc/userinfo_test.go` |
| `oidcc-prompt-login`, `oidcc-prompt-none-logged-in / not-logged-in` | `tests` の `TestPromptNoneWithLoginSession` |
| `oidcc-max-age-1`, `oidcc-max-age-10000` | `tests` の `TestMaxAgeReauthentication`、`authorization/service_test.go`（`max_age` 違反の拒否） |
| `oidcc-display-page/popup`, `oidcc-id-token-hint`, `oidcc-login-hint`, `oidcc-ui-locales`, `oidcc-claims-locales`, `oidcc-ensure-request-with-acr-values-succeeds`, `oidcc-ensure-request-with-unknown-parameter-succeeds` | `httpapi` の `TestAuthorizeAcceptsHintsAndUnknownParameters` |
| `oidcc-codereuse`, `oidcc-codereuse-30seconds` | `token/service_test.go` の `TestCodeReuseRevokesFamily`、E2E |
| `oidcc-refresh-token` | `token/refresh_test.go`、E2E |
| `oidcc-server-client-secret-post`, `oidcc-ensure-post-request-succeeds` | `httpapi` の `TestTokenEndpointClientAuth`、`TestAuthorizeErrors`（POST /authorize） |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | `authorization/request_test.go`（`nonce` は任意） |
| `oidcc-server-rotate-keys` | `keys/keys_test.go` の検証鍵の保持。JWKS 公開中の差し替えは未検証 |

### 実行時に直したこと

- `browser` セクションなしでは Suite が認可 URL を開かない → 設定に追加
- エラーページを見せるテストで callback を待ってタイムアウト → `override` でエラーページの表示を待つ
- `expected-skips.json` の `configuration-filename` がフルパスと照合されず「unexpected skip」→ `*basic-op.json`

### Suite が確認した項目（評価できたモジュールのログより）

- Discovery: 必須キーの存在、`token_endpoint_auth_methods_supported` が `client_secret_basic` を含むこと
- JWKS: 公開鍵のみ（秘密鍵・対称鍵なし）、構造、全鍵に `kid`、`kid` の一意性、サポートされる kty / alg
- 認可応答: `state` の一致、`code` の存在、`iss`（RFC 9207）
- トークン応答・ID Token（PKCE 付きフロー）: 署名、`iss` / `aud` / `exp` / `iat` / `nonce` / `at_hash` / `auth_time`、UserInfo の `sub` 一致
- WARNING は 0 件。INFO の "Skipped evaluation ... client jwks" は、設定に Client の JWKS（ID Token 暗号化用）を
  置いていないための省略で、問題ではない

REVIEW になった 2 件（および `oidcc-response-type-missing` の画面確認項目）は Suite の UI
（`https://localhost.emobix.co.uk:8443/plan-detail.html?plan=<id>`）で撮影された画面を人が確認する。
エンジンのエラーページは `httpapi.PlainErrorRenderer` の最小 HTML で、`invalid_request` と説明文を表示している。

### 未確認

- `oidcc-server-rotate-keys` など PKCE を付けない 30 モジュールは評価できていない（上記）。`expected-failures.json` の
  `oidcc-server-rotate-keys` の項目は到達していないため未検証
- Refresh、Code 再利用、`prompt` / `max_age`、scope ごとの Claims、ヒント類は Suite では未評価（上の表の自前テストのみ）

## 補足

- Suite はブラウザ操作を内蔵ブラウザで自動化する。loginapp は `-auto-approve` で画面を出さないので
  `basic-op.json` の `browser` 設定は不要。
- Issuer を http にしているのはローカル実行の都合。Suite は devmode では http の OP を許容するが、
  警告が出る場合がある。https で回したい場合はリバースプロキシを前段に置き、Issuer を https にする。
