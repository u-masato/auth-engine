# 付録 不変条件とコードの対応表

[← Day 7](day7-mcp.md) ｜ [索引](README.md)

[CLAUDE.md](../../CLAUDE.md) の「守るべき不変条件」は、変更するには ADR の修正が必要な約束である。7 日間で読んだコードのどこがそれぞれを守っているかを、表にまとめる。

## 使い方

まず下の空欄の表を、何も見ずに埋める。埋め終えたら、続く解答の表と見比べる。埋められなかった行は、対応する Day を読み直す。

| # | 不変条件 | 守っているコード | 破ったら落ちるテスト・検査 |
| --- | --- | --- | --- |
| 1 | コアの外部依存は go-jose/v4 だけ。JOSE の利用は `keys` に閉じる | | |
| 2 | Store インターフェースは使う側の文脈で定義し、ルートで合成する。`storage` は葉 | | |
| 3 | Store の各メソッドは単体で原子的。Port に `BeginTx` を置かない | | |
| 4 | 全 Port メソッドの第一引数は `context.Context`。`ctx` に値を載せて挙動を変えない | | |
| 5 | Client Profile で grant_type・PKCE・認証方式・redirect 照合を固定する。PKCE なし、`plain`、Implicit、Password Grant、DCR は実装しない | | |
| 6 | 秘密値は 256 bit 乱数で、保存は SHA-256 ハッシュのみ。比較は定数時間 | | |
| 7 | 状態遷移は fail-closed。Resume は CAS で consumed にしてから Code を作る。Code 交換は先に消費し、検証失敗でも戻さない | | |
| 8 | Code 再利用の検知で失効させるのは Token Family（Grant ではない） | | |

<details>
<summary>解答の表</summary>

「落ちるテスト」の列のうち ✔ を付けたものは、このブランチで実際に変更を入れて落ちることを確かめた。

| # | 守っているコード | 破ったら落ちるテスト・検査 | 読んだ日 |
| --- | --- | --- | --- |
| 1 | [go.mod](../../go.mod)（require は go-jose/v4 だけ）。`keys.Set` の `Sign` / `SignTyped` / `Verify` / `JWKS` / `ImportJWKS` だけが JOSE の型を扱う。`resourceserver` も `keys` 経由で検証する | [scripts/check-core-deps.sh](../../scripts/check-core-deps.sh)（`make lint` の `deps-check`）。後半で `resourceserver` が認可サーバー側に依存しないことも検査する | Day 1、Day 4 |
| 2 | `client.Store` `authorization.Store` `grant.Store` `token.Store` を [store.go](../../store.go) の `authengine.Store` が合成する。各 Service のフィールドは自分の文脈の Store 型。[storage/errors.go](../../storage/errors.go) はセンチネルエラーだけ | コンパイラ（文脈の Store にないメソッドは呼べない）。`storage/memory` を使うテストを外部テストパッケージ（`package xxx_test`）に置くのも同じ理由で、`storage/memory` はルートの `authengine` を import するため、内部テストにすると import が循環する | Day 1、Day 6 |
| 3 | `TransitionTransaction` `ConsumeAuthorizationCode` `IssueTokens` `RotateRefreshToken` `RevokeTokenFamily` `RevokeGrant` `DeleteClient`。Adapter 側は Memory の Mutex、SQLite の `writeMu` + `BEGIN IMMEDIATE`、PostgreSQL の `FOR UPDATE` と条件付き UPDATE | `storagetest.Run`。✔ SQLite の `TransitionTransaction` から status 条件を外す → `TestContract/Transaction` ほか。✔ Memory の `ConsumeAuthorizationCode` で消費を書かない → `TestContract/AuthorizationCodeConcurrentConsume` ほか。並行テストが競合を起こせない場合があることに注意（Day 6 の演習 3） | Day 3〜6 |
| 4 | 全 Store インターフェースの定義（[client/store.go](../../client/store.go) ほか）。`context.WithValue` を使うのは `resourceserver` が検証済みの `Principal` をハンドラに渡す箇所だけで、これは Port ではない | レビュー。機械的な検査はない | Day 1、Day 6 |
| 5 | `client.profileRules`（非公開の条件表）。`parseRequest` が `response_type=code` だけを受け、全要求で `code_challenge_method=S256` を必須にする。`Exchange` が受ける grant_type は 3 つだけ。Discovery（`baseMetadata`）も固定値。登録エンドポイントは存在しない | `TestProfileTable`（ADR-0004 の表との一致）。`TestParseRequestRedirectableErrors` の `implicit` `plain method` `missing code_challenge`。`TestGrantTypeErrors`。✔ Native の `requirePKCE` を `false` にする → `TestProfileTable/native` が落ちるが、`authorization` のテストは落ちない（挙動を決めているのは `parseRequest`。Day 2） | Day 2、Day 4 |
| 6 | [internal/rand](../../internal/rand/rand.go) の `Token`（256 bit）、`Hash`（SHA-256）、`HashEqual`（`subtle.ConstantTimeCompare`）。Client Secret、Code、Access / Refresh Token、Resume Token、ブラウザ結合 Cookie がすべてここを通る。`BearerAuthenticator` と `VerifyS256` も定数時間比較 | `internal/rand` のテスト。スキーマに平文の列がないこと（[00001_init.sql](../../adapters/sqlite/migrations/00001_init.sql)） | Day 1、Day 2、Day 6 |
| 7 | `authorization.Service.Resume`（`TransitionTransaction` → `issueCode` の順）。`token.Service.exchangeCode`（`ConsumeAuthorizationCode` が最初）。`narrowAudience` が設定から外れた Resource を拒否する。`JWTVerifier` は JWKS が手元になければ失敗させる | `TestInvalidGrant`（失敗した交換の後も Code が消費済みのまま）。✔ PKCE の検査を外す → `TestInvalidGrant/pkce_mismatch`。✔ Resume で Cookie を見ない → `TestResumeDenied`、`TestResumeErrors`、`TestResumeFromAnotherBrowserIsDenied` | Day 3、Day 4、Day 7 |
| 8 | `token.Service.revokeFamilyOnReuse` が `code.FamilyID` の Family を `RevokeTokenFamily` で失効させる。Refresh の再利用も `revokeFamilyOnRefreshReuse` で Family だけ | ✔ `revokeFamilyOnReuse` の呼び出しを消す → `TestCodeReuseRevokesFamily`、`TestFullAuthorizationCodeFlow`。✔ `revokeFamilyOnRefreshReuse` を消す → `TestRefreshReuseRevokesFamily`、`TestConcurrentRefresh` | Day 4、Day 5 |

</details>

## 不変条件ではないが、一貫して守られている約束

CLAUDE.md の「コーディング規約」にあるもののうち、読むうえで効いてくるもの。

| 約束 | 例 |
| --- | --- |
| プロトコルエラーは型付き（`authorization.Error` / `token.Error`）、内部障害は通常の `error` で、HTTP 層が 500 にする | `handleToken` の `errors.As(err, &perr)` |
| HTTP 層は薄く保ち、プロトコルの判断は Service に書く | `httpapi/*.go` の各 Handler |
| 永続化対象は公開フィールドの構造体。構築はコンストラクタ、変更は遷移メソッド。Adapter 以外はフィールドに直接代入しない | `client.NewWeb` と `Client.Update`、`grant.Merge`、`Status.CanTransitionTo` |
| 判断のコメントには RFC / OIDC の節番号を書く | `// RFC 6749 §4.1.3: ...` の形のコメント全般 |
| 1 ユースケース 1 ファイル、ファイルは概念別 | `token/refresh.go` `token/revoke.go` `token/introspect.go` |
| 完全ではない保証は、その理由とともにコメントに残す | `revokeFamilyOnReuse` の競合の窓、`storage/doc.go` の `DeleteClient` と進行中の Transaction |
