# Day 3 Transaction と Interaction 契約（Code 発行まで）

[← Day 2](day2-client-and-request.md) ｜ [索引](README.md) ｜ [Day 4 →](day4-code-exchange.md)

## 目標

- Transaction の状態機械と、「遷移の正当性」と「遷移の原子性」の責任分担を説明できる
- Complete（バックチャネル）と Resume（ブラウザ）の**二段階**にした理由を、攻撃の例とともに説明できる
- Resume の書き込み順序が fail-closed であることを、途中で失敗したときに何が残るかで説明できる
- Grant の upsert（`grant.Merge`）の規則を言える

## この日の用語

| 用語 | 意味 | 出てくる場所 |
| --- | --- | --- |
| Authorization Transaction | 1 回の `/authorize` 要求から Code 発行（または失敗）までの記録 | `authorization.Transaction` |
| Status | Transaction の状態。`pending` → `completed` / `rejected` → `consumed`。期限切れは Status ではなく `ExpiresAt` で判定する | `Status.CanTransitionTo` |
| CAS（compare-and-swap） | 「現在の値が期待どおりなら書き換える」を 1 操作で行うこと。同時の遷移で 1 つだけが勝つ | `TransitionTransaction` |
| `Patch` | 遷移と同時に書き込む値（Outcome、Rejection、Resume Token のハッシュ） | `authorization/store.go` |
| フロントチャネル / バックチャネル | ブラウザのリダイレクトを経由する通信と、サーバー同士の直接の通信。Complete はバックチャネル、Resume はフロントチャネル | ADR-0003 §2 |
| Begin / Complete / Reject / Resume | Interaction 契約の 4 つのユースケース。開始、成功の通知、拒否の通知、ブラウザの帰還 | `authorization/service.go` |
| Outcome | Complete で渡す成功の結果。`subject`、認証時刻、同意した scope、`amr` / `acr`、Claims | `authorization.Outcome` |
| Rejection | Reject で渡す失敗の結果。使えるエラーコードは 5 つ | `rejectionCodes` |
| `subject` | エンジンにとって不透明なユーザー識別子。ID Token の `sub` になる | `Outcome.Subject` |
| Resume Token | Complete / Reject の応答で発行する単回使用の秘密値（接頭辞 `rs_`）。ブラウザが持って戻る | `ResumeTokenPrefix` |
| Resume URL | `/authorize/resume?txn=...&token=...`。Interaction App がブラウザを戻す先 | `Server.resumeURL` |
| ブラウザ結合 Cookie | `/authorize` でブラウザに発行する Cookie。Resume が同じブラウザから来たことを確かめる | `httpapi/cookie.go` |
| `__Host-` 接頭辞 | Cookie を `Secure`・`Path=/`・`Domain` なしに強制する名前の規則。デモでは外して `ae_bind` | `bindingCookieSecure` |
| `SameSite=Lax` | 別サイトからのトップレベルの GET 遷移では Cookie を送る設定。Resume で必要 | `browserBinding` |
| fail-closed | 途中で失敗したら、安全だがやり直しが必要な状態に倒す書き方。Resume は先に `consumed` にしてから Code を作る | `Service.Resume` |
| Grant | client_id × subject に対する永続的な認可の記録（付与済み scope の和集合と Claims） | `grant.Grant` |
| Upsert / Merge | Grant がなければ作り、あれば規則に従って更新する。active なら scope は和集合、revoked なら今回の値だけで復活 | `UpsertGrant`、`grant.Merge` |
| step-up | 追加の同意で scope を段階的に増やすこと | Day 7 の `TestMCPStepUpAuthorization` |
| 同意スキップ | 既存の Grant で足りるとき、Interaction App が同意画面を省くこと | `GET /grants`、`Grants.Find` |
| `iss` 応答パラメータ | 認可応答に付ける Issuer（RFC 9207）。どの認可サーバーの応答かを Client が確かめる（Mix-Up 攻撃の対策） | `issueCode` |

## 読む順

1. [architecture.md §5 Authorization Code フロー](../architecture.md#authorization-flow) と [§6 状態とデータモデル](../architecture.md#state-model)
2. [ADR-0003 Interaction App との契約](../adr/0003-interaction-contract.md)（**最重要**。§2 のフロー、§3 の各ステップの規則、「ブラウザ結合」）
3. [interaction-api.md](../interaction-api.md)（Interaction App 実装者に向けた同じ契約の HTTP 版）
4. コード
   - [authorization/transaction.go](../../authorization/transaction.go) — `Status` `CanTransitionTo` `Transaction` `Outcome` `AuthorizationCode`
   - [authorization/store.go](../../authorization/store.go) — `Patch` と `TransitionTransaction` の契約
   - [authorization/service.go](../../authorization/service.go) — `Begin` `Complete` `Reject` `Resume` `issueCode`
   - [httpapi/authorize.go](../../httpapi/authorize.go)、[httpapi/cookie.go](../../httpapi/cookie.go)、[httpapi/interaction.go](../../httpapi/interaction.go)、[httpapi/grants.go](../../httpapi/grants.go)
   - [grant/grant.go](../../grant/grant.go)、[grant/service.go](../../grant/service.go)
   - デモの Interaction App: [examples/standalone/loginapp/loginapp.go](../../examples/standalone/loginapp/loginapp.go)

## 解説

### 1. 状態機械: 正当性はコード、原子性は Store

```go
func (s Status) CanTransitionTo(to Status) bool {
	switch s {
	case StatusPending:
		return to == StatusCompleted || to == StatusRejected
	case StatusCompleted, StatusRejected:
		return to == StatusConsumed
	}
	return false
}
```

`Status.CanTransitionTo` は「どの遷移がありうるか」を決める純粋な関数である。一方、`Store.TransitionTransaction(ctx, id, from, to, patch)` は「Status が `from` のときだけ `to` にする」CAS（compare-and-swap）で、「同時に 2 人が遷移させようとしたら 1 人だけが勝つ」ことを保証する。前者はエンジンのコード、後者は Adapter の責務である。

この分け方のおかげで、Adapter は状態機械の意味を知らなくてよい。必要なのは「`WHERE status = from` の条件付き UPDATE で、更新行数が 0 なら `ErrStateConflict`」という機械的な実装だけになる（Day 6）。

期限切れは独立した Status ではなく、`Transaction.Expired(now)`（`!now.Before(ExpiresAt)`）で判定する。期限切れへの遷移を誰かが書き込む必要がなく、Purge しなくても正しく振る舞う。

### 2. 全体の流れと、各段階で動く秘密値

architecture.md §5 のシーケンス図を手元に置き、次の表と対応させながら読む。

| 段階 | 関数 | ブラウザの URL に出るもの | エンジンが保存するもの |
| --- | --- | --- | --- |
| /authorize | `Server.handleAuthorize` → `Service.Begin` | Interaction URL `?txn=<ID>` | Transaction（`pending`）、結合 Cookie の**ハッシュ** |
| UI の材料 | `handleGetTransaction` → `Service.Transaction` | —（バックチャネル） | — |
| 結果の通知 | `handleComplete` → `Service.Complete` | —（バックチャネル） | `completed`、Outcome、Resume Token の**ハッシュ** |
| ブラウザが戻る | `handleResume` → `Service.Resume` | `/authorize/resume?txn=...&token=<Resume Token>` | `consumed`、Grant、Code の**ハッシュ** |
| Client へ | `issueCode` が返す URL | redirect URI `?code=...&state=...&iss=...` | — |

**Interaction App は Code を一度も見ない**。Complete の応答は `resume_url` だけで、Code は Resume の時点で初めて作られ、ブラウザのリダイレクトで Client に直接届く。Interaction App が侵害されても、Code やトークンを横取りする経路がない（ADR-0003 §2）。

### 3. Begin: Transaction を作る

`handleAuthorize` は先に `browserBinding` で結合 Cookie を読み、なければ発行する。Cookie の属性には意味がある（[httpapi/cookie.go](../../httpapi/cookie.go)）。

- 名前の `__Host-` 接頭辞 — `Secure`、`Path=/`、`Domain` なしを強制する。サブドメインから上書きされない
- `HttpOnly` — スクリプトから読めない
- `SameSite=Lax` — Resume は Interaction App からのトップレベルの GET 遷移なので、Lax なら送られる。Strict にすると別サイトからの遷移で送られず、正規のフローが壊れる
- 1 ブラウザに 1 つで使い回す。同じブラウザで複数の Transaction を並行させてもよい

`Service.Begin` は `parseRequest`（Day 2）を通った要求を、`pending` の Transaction として保存する。Interaction URL に載せるのは Transaction ID だけで、scope や `client_id` は載せない。Interaction App はバックチャネルの `GET /transactions/{id}` で要求内容を取りに来る。URL の改ざんで同意画面の表示を偽れないようにするためである。

`GET /transactions/{id}` の応答（`transactionView`）には `state`、`nonce`、`code_challenge` を**含めない**。これらは Client とエンジンの間の値で、Interaction App が知る必要がない。知る必要のないものは渡さない。

### 4. Complete / Reject: 信頼するが契約は確かめる

`Service.Complete` は Interaction App の結果（`Outcome`）を次の観点で検証する。違反は `ErrInvalidOutcome`（HTTP 400）になる。

| 検証 | 理由 |
| --- | --- |
| `Subject` が空でない | 誰の認可かわからない Grant を作らない |
| `AuthenticatedAt` がゼロでない | ID Token の `auth_time` と `max_age` 検証に要る |
| `GrantedScopes` が空でない | 何も許さないなら Reject を使う、という契約 |
| `GrantedScopes ⊆ Request.Scopes` | 同意画面は scope を**減らす**ことしかできない |
| `max_age` が要求されていれば `now - AuthenticatedAt <= MaxAge` | OIDC Core §3.1.2.1。古いログインセッションのまま通すのを防ぐ |

エンジンはユーザーを認証できないので、`Subject` が本物かどうかは確かめられない。それでも、**プロトコルとして矛盾する結果**はエンジン側で拒否する。Interaction App の実装ミスがそのまま認可の欠陥にならないようにするためである。

検証を通ったら Resume Token を生成し、`TransitionTransaction(pending → completed, Patch{Outcome, ResumeTokenHash})` で保存する。CAS に負けた（同時に別の Complete / Reject が勝った）ら `ErrTransactionNotPending`（HTTP 409）になる。

`Reject` も同じ形で、`error` は `access_denied` `login_required` `consent_required` `interaction_required` `server_error` に限られる（`rejectionCodes`）。拒否の場合も Resume Token を返し、ブラウザは Resume を通って Client にエラーを持ち帰る。こうすると成功時と拒否時でブラウザの経路が同じになり、Client へのリダイレクトはどちらもエンジンが行う。

### 5. Resume: 2 つの秘密が揃ったときだけ Code を作る

Resume が要求するのは 2 つの値である。

- **Resume Token** — Complete の応答に含まれる。Interaction App → ブラウザ → エンジンと渡る
- **ブラウザ結合 Cookie** — /authorize でそのブラウザに発行したもの

Resume Token だけでは足りない理由は、次の攻撃を考えるとわかる。攻撃者が自分のブラウザで /authorize を開始し、得た Interaction URL（`?txn=...`）を被害者に踏ませる。被害者は何も知らずにログインし、同意する。Resume Token は被害者のブラウザに渡るが、もし Resume Token が攻撃者に漏れたら（リファラ、ログ、共有 URL など）、攻撃者は自分のブラウザで Resume して、**被害者の権限の Code を自分の Client セッションで受け取れてしまう**。結合 Cookie は「Transaction を始めたブラウザと、Resume するブラウザが同じ」ことを要求し、この経路を塞ぐ（ADR-0003「ブラウザ結合」）。

```go
// 定数時間比較。両方を評価してから判定する（早期 return で情報を漏らさない）。
tokenOK := rand.HashEqual(txn.ResumeTokenHash, resumeToken)
bindOK := rand.HashEqual(txn.BrowserBindingHash, browserBinding)
if !tokenOK || !bindOK {
	return "", ErrResumeDenied
}
```

失敗の理由（Token 違い、Cookie 違い、未完了、再利用）は `ErrResumeDenied` 1 つにまとめ、エラーページを描いて Client へはリダイレクトしない。攻撃者にどちらが外れたかを教えないためである。

**書き込みの順序**が、この関数でいちばん大事な部分である。

1. `TransitionTransaction(completed または rejected → consumed)` — CAS。同時に 2 回 Resume されても 1 回しか通らない
2. rejected なら、エラー応答の URL を返して終わり（これは正常な戻り値で、`err` は nil）
3. completed なら `issueCode`: Grant を upsert し、Code を作って保存する

| どこで失敗したか | 残る状態 | 結果 |
| --- | --- | --- |
| 1 の CAS に負けた | 別の要求が consumed にした | `ErrResumeDenied` |
| 2〜3 の途中（Grant や Code の保存失敗） | Transaction は consumed、Code はない | 500。同じ Resume を再試行しても通らない。ユーザーは認可をやり直す |

「先に消費してから作る」ので、どの時点で失敗しても**同じ Transaction から Code が 2 つできる**ことはない。代償として、障害時はユーザーが最初からやり直すことになる。これが CLAUDE.md の不変条件「Resume は CAS で `consumed` にしてから Code を作る」である。

### 6. issueCode: Code に何を写すか

`AuthorizationCode` には、トークンエンドポイントが Transaction を読み直さずに済むだけの情報を写す。

- 誰に: `ClientID`、`RedirectURI`、`RedirectURIExplicit`（RFC 6749 §4.1.3 の照合に使う）
- 何を: `Scopes`（Complete で絞った後の scope）、`Resource`
- どう証明するか: `CodeChallenge`
- ID Token の材料: `Subject`、`AuthenticatedAt`、`AMR`、`ACR`、`Nonce`、`Claims`
- 後で失効させる単位: `GrantID` と、**この時点で決めておく** `FamilyID`

`FamilyID` を Code 発行時に決めておくのは、Code の再利用を検知したとき「この Code から作られた Family」を特定するためである（Day 4）。

成功応答の URL には `code` と `state` に加えて `iss`（RFC 9207）を付ける。Client は `iss` を見て、どの認可サーバーからの応答かを確かめられる（Mix-Up 攻撃の対策）。`appendQuery` は登録済み redirect URI の既存クエリ（`?env=prod` など）を保ったまま足す。

### 7. Grant: client_id × subject の認可の記録

`issueCode` は `Grants.UpsertGrant` を呼ぶ。Grant は client_id × subject につき 1 つで、Adapter は既存があれば `grant.Merge(existing, candidate)` の結果で更新する。

| 既存の状態 | scope | Claims | Status |
| --- | --- | --- | --- |
| active | 既存と今回の**和集合** | 今回の値で**置き換え** | active |
| revoked | 今回の値**だけ**（失効前の scope は引き継がない） | 今回の値 | active に戻る |

和集合にするのは、同意を段階的に足していける（step-up）ようにするためである。ただし、Grant の scope が増えても、すでに発行済みの Token Family の scope は増えない（architecture.md §6）。失効済みからの復活で古い scope を引き継がないのは、「連携を解除したのに、再接続したら以前の権限が全部戻っていた」を防ぐためである。

`grant.Service` は Interaction App 向けに 3 つの操作を持つ。

- `Find(clientID, subject)` — 同意スキップの判断用。Interaction API の `GET /grants?subject=...&client_id=...`
- `List(subject)` — 「連携済みアプリ一覧」用
- `Revoke(clientID, subject)` — 連携解除。Grant と配下の全 Family・全トークンを失効させる。**HTTP のルートはなく Go API だけ**（architecture.md §4）

## 手を動かす

### 1. 状態遷移と Resume のテスト

```bash
go test -run 'TestStatusTransitions|TestCompleteThenResume|TestRejectThenResume|TestResumeDenied|TestCompleteValidation' -v ./authorization/
```

E2E は別 Module にある。

```bash
(cd tests && go test -run 'TestResumeFromAnotherBrowserIsDenied|TestUserDenies|TestExpiredTransaction' -v .)
```

`TestResumeFromAnotherBrowserIsDenied` を読み、「別のブラウザ」をテストがどう表現しているか（Cookie Jar の分け方）を確かめる。

### 2. 壊して確かめる

| 変更 | 落ちるテスト |
| --- | --- |
| `Resume` の判定を `if !tokenOK {` にする（Cookie を見ない） | `authorization` の `TestResumeDenied`、`httpapi` の `TestResumeErrors`、`tests` の `TestResumeFromAnotherBrowserIsDenied` |
| `Complete` の `max_age` 検証を無効にする（`if false && txn.Request.HasMaxAge ...`） | `authorization` の `TestCompleteValidation/older_than_max_age` だけ。**`tests` の `TestMaxAgeReauthentication` は通る** |
| `grant.Merge` で active のときも `out.Scopes = slices.Clone(candidate.Scopes)` にする | `grant` の `TestMerge`、`storage/memory` の `TestContract/Grant`。**`authorization` の `TestResumeMergesGrantAcrossTransactions` は通る** |

「通る」と書いた 2 つについて考える。

- `TestMaxAgeReauthentication` が通るのは、デモの loginapp 自身が `max_age` を解釈して再認証させているからである。E2E では「正しい Interaction App」が前提になっているため、エンジン側の検証は**誤った Interaction App に対する防御**として、ユニットテストだけが守っている
- `TestResumeMergesGrantAcrossTransactions` は `{openid}` の後に `{openid, profile}` を同意させている。2 回目が 1 回目を包含しているので、置き換えでも和集合でも結果が同じになる。和集合であることを確かめるには、どんな順序で同意させればよいか

### 3. デモで二段階を観察する

`-auto-approve` を付けずに起動し、ログイン画面を経由するフローを流す。`start` は起動済みのサーバーのモードを切り替えないので、Day 1 の自動承認モードが残っていれば先に止める。

```bash
.claude/skills/run-demo/scripts/demo.sh stop
```

```bash
.claude/skills/run-demo/scripts/demo.sh start
```

```bash
.claude/skills/run-demo/scripts/demo.sh flow
```

表示された URL をブラウザで開き、開発者ツールの Network タブで次を確かめる。

- `/authorize` の応答で `ae_bind`（開発用に `InsecureCookies` で `__Host-` を外した名前）が Set-Cookie される
- ログイン画面の URL には `txn` しかない
- 承認後、`/authorize/resume?txn=...&token=rs_...` を経て `http://127.0.0.1:<port>/callback?code=...&state=...&iss=...` に戻る

承認したら、結果を表示する。

```bash
.claude/skills/run-demo/scripts/demo.sh flow-wait
```

Interaction API は外から届かないことも確かめる（デモの API トークンはプロセス内の乱数で、外には出ない）。

```bash
curl -i http://127.0.0.1:8081/transactions/x
```

401 と `WWW-Authenticate: Bearer realm="interaction"` が返る。

## 確認問題

1. `CanTransitionTo` があるのに、Store の `TransitionTransaction` が `from` を引数に取るのはなぜか。`from` を取らずに「現在の状態から `to` へ」とするとどんな競合で壊れるか。
2. Complete の応答で Code そのものを返さず `resume_url` を返す設計の利点を 2 つ挙げよ。
3. Resume で `tokenOK` と `bindOK` を両方計算してから判定しているのはなぜか。
4. Resume の途中で Code の保存に失敗した。ユーザーがブラウザの「再読み込み」で同じ Resume URL を開き直したら何が起きるか。それは望ましいか。
5. あるユーザーが Client A に `openid profile` を許可し、後日 `openid email` を追加で許可した。その後 Grant を `Grants.Revoke` で失効させ、再び `openid` だけを許可した。Grant の scope はそれぞれの時点でどうなっているか。

<details>
<summary>解答</summary>

1. 「読んでから書く」の間に別の要求が状態を変えうるからである。たとえば同じ Transaction に Complete と Reject が同時に届くと、両方が `pending` を読み、両方が書き込む。後勝ちになり、片方の Interaction App は成功したつもりなのに結果が上書きされる。`from` を条件にした CAS なら、2 つ目は `ErrStateConflict` で失敗し、遷移は 1 回だけになる。
2. (a) Interaction App が Code に触れないので、Interaction App が侵害されたり、ログに URL を残したりしても Code やトークンが漏れない。(b) Code の発行をブラウザ結合 Cookie の確認と同じ地点（Resume）に集められるので、「Transaction を始めたブラウザにだけ Code を渡す」ことを 1 か所で保証できる。ほかに、Code の期限（60 秒）が Interaction App の処理時間に食われない、という利点もある。
3. 片方が外れた時点で返すと、処理時間の差からどちらが合っていたかを推測される余地が生まれる。また、失敗の理由を `ErrResumeDenied` 1 つにまとめて、攻撃者に区別を与えないという方針の一部である。
4. Transaction はすでに `consumed` なので、2 回目の Resume は `ErrResumeDenied`（HTTP 400）になり、Code は発行されない。ユーザーは認可を最初からやり直す必要がある。可用性より「同じ Transaction から 2 つ目の Code を作らない」安全性を優先した fail-closed の設計で、意図した挙動である。
5. 1 回目の後は `openid profile`、2 回目の後は和集合の `openid profile email`（Claims は 2 回目の値に置き換わる）。失効すると Status が revoked になる（scope の値は残っている）。再許可すると、失効前の scope は引き継がず `openid` だけで active に戻る。
</details>
