# 組み込みガイド（エンジンを自分のサービスに載せる人向け）

- 対象バージョン: M3 タスク 3 時点の main（2026-10-25）
- 前提: Go 1.26 以上。OAuth 2.0 の Authorization Code + PKCE の流れを知っていること
- 動く全体像: [examples/standalone/cmd/server/main.go](../examples/standalone/cmd/server/main.go)（エンジン + Interaction API + デモのログイン画面を 1 プロセスで起動する）

この文書は、エンジンを自分のサービスに組み込む手順と、本番に出す前に決めることをまとめる。
コードは Example テストとして置いてあり、`go test` で実際に動かしている。pkg.go.dev でも読める。この文書からはそこへリンクする。

## 1. 責務の分担

エンジンはヘッドレスである。プロトコルの処理と、Transaction・Grant・トークンの状態管理だけを受け持つ（[ADR-0001](adr/0001-scope-and-principles.md)、[ADR-0003](adr/0003-interaction-contract.md)）。

| エンジンが提供するもの | 組み込む側が用意するもの |
| --- | --- |
| `/authorize`、`/token`、`/revoke`、`/introspect`、`/userinfo`、`/jwks`、Discovery | ログイン画面と同意画面（Interaction App） |
| PKCE・redirect URI・Client 認証の検証 | ユーザー管理、パスワードや MFA などの認証手段 |
| Code・トークン・Resume Token の発行と単回消費 | 永続化先の DB と Store Adapter の選択 |
| Refresh Token の Rotation と再利用検知 | 署名鍵の保管とローテーションの運用 |
| ID Token の署名と JWKS の公開 | Client の登録手段（管理画面、CLI、構成ファイルなど） |
| 監査イベントの `slog` への出力 | ログの転送と保管、期限切れデータの定期削除の起動 |

ブラウザから見た流れと、Interaction App が呼ぶ API は [Interaction API 仕様](interaction-api.md) にある。1 プロセス内でこの流れを最初から最後まで通すコードは [`httpapi` の Example (AuthorizationCodeFlow)](../httpapi/example_test.go) にある。

## 2. 最小の配線

```
Store ─┐
Keys  ─┼─▶ authengine.New(Config) ─▶ *Engine ─▶ httpapi.New(Config) ─┬─▶ PublicHandler()      … Issuer の URL で公開
       │                                                              └─▶ InteractionHandler() … 内部ネットワークだけ
Clients（Store.CreateClient で事前に登録）
```

1. **Engine を作る。** 必須は `Issuer`・`Store`・`Keys` の 3 つ。例は [`ExampleNew`](../example_test.go)。
2. **HTTP 層を作る。** `httpapi.New` に `Engine`、`InteractionURL`（ログイン画面の URL）、`InteractionAuth` を渡す。例は [`httpapi.ExampleNew`](../httpapi/example_test.go)。
3. **2 つの Handler を別々のリスナーで公開する。** 理由は §5 に書く。
4. **Client を登録する。** 方法は §4 に書く。
5. **Interaction App を用意する。** [Interaction API 仕様](interaction-api.md) に従って実装する。参考実装は [examples/standalone/loginapp](../examples/standalone/loginapp/loginapp.go)。

`Config` の TTL は 0 のままなら既定値になる。

| 設定 | 既定 | 上限 | 根拠 |
| --- | --- | --- | --- |
| `TransactionTTL`（ログイン画面の持ち時間） | 10 分 | 1 時間 | ADR-0003 |
| `CodeTTL` | 60 秒 | 10 分 | RFC 6749 §4.1.2 |
| `IDTokenTTL` | 1 時間 | 24 時間 | — |
| `RefreshTokenTTL` / `RefreshTokenIdleTTL` | 30 日 / 14 日 | idle は絶対期限以下 | ADR-0006 |
| Access Token（Client ごとに `AccessTokenTTL`） | 1 時間 | 1 分〜24 時間 | ADR-0004 §2 |

## 3. Store を選ぶ

| Adapter | 向いている構成 | 開き方 |
| --- | --- | --- |
| [`adapters/sqlite`](../adapters/sqlite) | 1 台のホスト。複数プロセスからの書き込みも SQLite のロックで直列化する | `sqlite.Open(ctx, path)`。例: [`ExampleOpen`](../adapters/sqlite/example_test.go) |
| [`adapters/postgres`](../adapters/postgres) | 複数台で水平に並べる構成 | `postgres.Open(ctx, dsn)`、または自前の `*sql.DB` を `Migrate` してから `postgres.New`。例: [example_test.go](../adapters/postgres/example_test.go) |
| `storage/memory` | 単体テストだけ。**本番では使わない** | `memory.New()` |

- Adapter は別の Go Module である。コアのモジュールは DB ドライバーに依存しないので、使う Adapter だけを `go get` する。
- `Open` は埋め込みのマイグレーション（goose をライブラリとして使う）を適用してから返す。goose CLI は要らない。
- SQLite の `:memory:` は使えない。接続ごとに別の DB になるので、ファイル DB を使う。
- 自前の DB に載せたいときは `authengine.Store` を実装し、[`storage/storagetest`](../storage/storagetest/storagetest.go) の契約テストを通す。各メソッドは単体で原子的でなければならない（[ADR-0005](adr/0005-storage-port.md)）。

### 期限切れデータの削除

エンジンは期限切れの行を自動では消さない。Transaction・Authorization Code・Access Token・Refresh Token のうち `expires_at` を過ぎたものを、`Store.Purge(ctx, now)` で削除する。呼び出しは利用者のスケジューラ（cron、ジョブ、プロセス内のティッカー）から行う。

```go
go func() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := store.Purge(ctx, now); err != nil {
				logger.Error("purge failed", "error", err)
			}
		}
	}
}()
```

消さなくてもプロトコルの正しさは崩れない。期限切れの行はどの遷移でも失敗する（ADR-0003）。消す目的は DB の肥大を防ぐことである。複数のインスタンスで同時に呼んでもよい。

## 4. Client を登録する

Client は Profile ごとのコンストラクタで作り、`Store.CreateClient` で登録する。grant_type・PKCE・認証方式・redirect URI の照合規則は Profile が固定するので、個別に設定する項目はない（[ADR-0004](adr/0004-client-profiles.md)）。

| 用途 | コンストラクタ | Example |
| --- | --- | --- |
| サーバー側でシークレットを保持できる Web アプリ（BFF を含む） | `client.NewWeb` | [`ExampleNewWeb`](../client/example_test.go) |
| CLI、デスクトップ、モバイル（public） | `client.NewNative` | [`ExampleNewNative`](../client/example_test.go) |
| サービス間通信、Introspection を呼ぶ Resource Server | `client.NewMachine` | [`ExampleNewMachine`](../client/example_test.go) |

- **シークレットは作成時に 1 度だけ平文で返る。** Store に残るのは SHA-256 ハッシュだけなので、後から取り出すことはできない。ログに出さずに Client へ渡す。
- **登録用の HTTP API はない。** Store に更新の操作もないので、設定を変えるときは Client を作り直す。登録の手段は組み込む側で用意する。例として、デモサーバーの `-clients` オプションは JSON ファイルから登録する（[main.go](../examples/standalone/cmd/server/main.go) の `registerClientsFromFile`）。開発者コンソールは画面から登録する。
- **ブラウザ上の JavaScript（SPA）から `/token` を直接呼ぶ構成には対応していない。** エンジンは CORS ヘッダーを返さない。SPA はバックエンド（BFF）を Web Profile の Client として登録し、トークンはサーバー側に置く。
- PKCE を実装していないクライアントは接続できない。これは意図した制約である。

## 5. HTTP への公開

### 2 つの Handler を分ける

| Handler | 届く必要がある相手 | 置き場所 |
| --- | --- | --- |
| `PublicHandler()` | ブラウザ、Client、Resource Server | `Issuer` の URL（インターネット） |
| `InteractionHandler()` | Interaction App のサーバーだけ | 内部ネットワーク。**インターネットに公開しない** |

Interaction API を呼べる者は「誰がログインしたか」を任意に宣言できる。認証は `InteractionAuth` で行うが、ネットワークでも分離して二重に守る。

- 既定の `httpapi.BearerAuthenticator{Token: ...}` を使うなら、トークンは 256 bit 以上の乱数にして、Secret Manager などで Interaction App と共有する。
- mTLS や社内ゲートウェイのヘッダーで認証したいときは、`InteractionAuthenticator` を自分で実装して差し替える。例は [`ExampleInteractionAuthenticator`](../httpapi/example_test.go)。

### Issuer とパス

- `Issuer` は `https` の絶対 URL で、**パスを含められない**。エンドポイントは Issuer 直下の固定パス（`httpapi.PathAuthorize` などの定数）に置く。そのため、`https://example.com/auth/` のようなサブパスにはマウントできない。`as.example.com` のように専用のホストを割り当てるのがいちばん単純である。
- 同じホストで別のルートと同居させるなら、外側の `http.ServeMux` で `httpapi.Path*` の各パスを `PublicHandler()` に振り分ける。
- エンジンは URL を `Issuer` から組み立てる。`Host` ヘッダーや `X-Forwarded-*` は見ないので、TLS をリバースプロキシで終端してもよい。ただし `Issuer` には利用者から見える外部の URL を設定すること。
- `http` の Issuer を許すのは `localhost` と loopback だけである。`AllowInsecureIssuer` は Docker 内の検証などに使う開発用の緩和で、本番では使わない。

### Cookie

`/authorize` は、ブラウザ結合のために Cookie `__Host-ae_bind` を発行する（`Secure; HttpOnly; SameSite=Lax; Path=/`。ADR-0003 §3「ブラウザ結合」）。`__Host-` プレフィックスの Cookie は https でしか保存されない。そのため、http の開発環境に限って `httpapi.Config.InsecureCookies` を true にする。本番では false のままにする。

Interaction App は別のホストに置いてよい。Cookie を照合するのは、ブラウザがエンジンのホストへ戻ってくる Resume のときだけである。

### エラーページ

`client_id` が不明、`redirect_uri` が不一致など、Client へリダイレクトしてはいけないエラーのときは、エンジンがブラウザにエラーページを返す。既定の `PlainErrorRenderer` は装飾のない HTML なので、自社のデザインにしたいときは `ErrorRenderer` を実装して差し替える。例は [`ExampleErrorRenderer`](../httpapi/example_test.go)。

### `http.Server` の設定

エンジンは `http.Handler` を返すだけで、リスナーとタイムアウトは利用者が持つ。少なくとも `ReadHeaderTimeout` を設定する（Slowloris 対策）。レート制限・WAF・ヘルスチェック用のエンドポイントもエンジンには含まれないので、前段か外側の Handler で用意する。

## 6. 署名鍵

- `Keys` には **RS256 の署名鍵が必須**である（OIDC Core §15.1）。ES256 は任意で、Client ごとに `IDTokenAlg` で選べる。
- **鍵は保存して使い回す。** 起動のたびに生成すると、発行済みの ID Token を Client が検証できなくなる。`Set.ExportPrivate` で書き出し、`keys.ImportPrivate` で復元する。例は [`ExampleImportPrivate`](../keys/example_test.go)。書き出した内容は秘密鍵そのものである。保護（Secret Manager、権限 0600 など）は利用者の責務とする。
- **複数のインスタンスで同じ鍵セットを読む。** インスタンスごとに鍵が違うと、JWKS の内容が要求ごとに変わってしまう。
- **ローテーション**は、`AddSigning` で新しい鍵に差し替え、旧鍵で署名したトークンが期限切れになってから `Remove` する。差し替えた後も、旧鍵は検証鍵として JWKS に残る。差し替えたら `ExportPrivate` で保存し直し、すべてのインスタンスに配る。旧鍵も検証鍵として保存されるので、再起動しても JWKS から消えない。手順は [`ExampleSet_AddSigning`](../keys/example_test.go) にある。

## 7. Resource Server

- Access Token の受け手（API）は `Config.Resources` に静的に列挙する（RFC 8707、[ADR-0008](adr/0008-mcp-integration.md) §1）。一覧にない `resource` を指定した要求は `invalid_target` になる。
- Access Token の形式は resource ごとに `Resource.AccessTokenFormat` で選ぶ（ADR-0008 §3）。`resource` を指定しない要求のトークンは常に Opaque になる。1 つの要求で複数の resource を指定するときは、それらの形式が揃っていなければならず、混在すると `invalid_target` になる。

| 形式 | 中身 | Resource Server での検証 | 失効の伝わり方 |
| --- | --- | --- | --- |
| `resource.FormatOpaque`（既定） | `at_` で始まる乱数 | Introspection か Go API の `Inspect` | すぐ伝わる |
| `resource.FormatJWT` | RFC 9068 の JWT（`typ: at+jwt`。署名は `AccessTokenAlg` で RS256 / ES256、既定は RS256） | `/jwks` の公開鍵でローカル検証。Introspection も使える | ローカル検証では `exp` まで伝わらない |

- **Opaque の検証**は次のどちらかで行う。
  - **別プロセスのとき**: `POST /introspect`（RFC 7662）を呼ぶ。Resource Server 自身を Machine Profile の Client として登録し、その資格情報で認証する。
  - **同じプロセスのとき**: Go API の `engine.Token.Inspect` を呼ぶ。例は [`token.ExampleService_Inspect`](../token/example_test.go)。
  - どちらの場合も、`active` が true であることに加えて、`aud`（Go API では `Introspection.Audience`）に自分の resource URI が含まれ、必要な scope が付いていることを確かめる。ほかの Resource Server 向けに発行されたトークンを受け入れないためである（RFC 8707 §2）。
- **JWT の検証**では、`typ` が `at+jwt` であること（ID Token との混同を防ぐ）、`iss` が Issuer と一致すること、`aud` に自分の resource URI が含まれること、`exp` が未来であること、`alg` が許可したものであることを確かめる（RFC 9068 §4）。例は [`token.ExampleJWTIssuer`](../token/example_test.go)。
  - JWT を選ぶ resource には、`AccessTokenTTL` の短い Client を組み合わせる。失効させても、ローカル検証では `exp` まで有効に見えるためである。
  - `Engine.New` は、JWT を選んだ resource の署名アルゴリズムに対応する鍵が `Keys` にあることを起動時に確かめる。ES256 を選ぶなら ES256 の署名鍵も用意する。
  - Resource Server は JWKS をキャッシュするので、鍵をローテーションするときは §6 の手順で旧鍵を残しておく。
- 管理画面やサポート対応からの失効には Go API を使う。トークンを 1 本だけ失効させるなら `engine.Token.RevokeToken`、ユーザーと Client の連携を解除するなら `engine.Grants.Revoke` を呼ぶ。例は [`token.ExampleService_RevokeToken`](../token/example_test.go) と [`grant.ExampleService_Revoke`](../grant/example_test.go)。

## 8. ログと監査

エンジンは `Config.Logger`（`*slog.Logger`。nil なら `slog.Default()`）に構造化イベントを出す。どのイベントにも `event` 属性が付く。転送と保管は `slog.Handler` で行う。コアはログを永続化しない（ADR-0006 §6）。トークン・シークレット・Code の平文はログに出さない。

| `event` | 意味 | 監視の目安 |
| --- | --- | --- |
| `token.issued` | トークンの発行（Code 交換、Refresh、client_credentials） | 量の推移 |
| `token.rejected` | トークン要求の拒否。`error` 属性に `invalid_client`・`invalid_grant` などのエラーコードが入る | `invalid_client` の急増は総当たりの兆候 |
| `token.revoked` | Revocation エンドポイント（RFC 7009）での失効 | — |
| `code.reuse` | Authorization Code の再利用を検知し、Token Family を失効させた | **要調査**。Code の漏洩を疑う |
| `refresh.reuse` | ローテーション済みの Refresh Token の再利用を検知し、Token Family を失効させた | **要調査**。Refresh Token の漏洩を疑う |
| `refresh.client_mismatch` | 別の Client の Refresh Token が提示された | **要調査** |
| `authorize.rejected` | 認可要求の拒否。`redirectable` 属性は Client へ戻したかどうか | `redirectable=false` は Client 側の設定ミスであることが多い |
| `resume.denied` | Resume の拒否（結合 Cookie の不一致など） | 急増は Resume URL 盗用の試み |
| `http.internal_error` | 内部障害（500 を返した） | **アラート** |
| `config.insecure_issuer` / `config.insecure_cookies` | 開発用の緩和を有効にして起動した | 本番で出たら設定ミス |

## 9. 本番に出す前の確認

- [ ] `Issuer` が利用者から見える外部の https URL と一致している
- [ ] `AllowInsecureIssuer` と `InsecureCookies` が false で、起動ログに `config.insecure_*` が出ていない
- [ ] Store が SQLite（単一ホスト）か PostgreSQL である（`storage/memory` を使っていない）
- [ ] 署名鍵を保存し、すべてのインスタンスが同じ鍵セットを読む。保存先が保護されている
- [ ] `InteractionHandler()` がインターネットから届かない。`InteractionAuth` のトークンが十分に長い乱数である
- [ ] `Store.Purge` を定期的に呼んでいる
- [ ] `http.Server` に `ReadHeaderTimeout` を設定し、前段にレート制限がある
- [ ] `code.reuse`、`refresh.reuse`、`refresh.client_mismatch`、`http.internal_error` を監視している
- [ ] Interaction App が [Interaction API 仕様](interaction-api.md) の「守ってほしいこと」を満たしている

## 関連文書

- [Interaction API 仕様](interaction-api.md): Interaction App を実装する人向け
- [準拠仕様一覧](specifications.md): 対応している RFC と、まだ対応していないもの
- [設計ドキュメント](README.md): 判断の理由（ADR）
