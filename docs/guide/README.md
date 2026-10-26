# auth-engine 実装解説書（7 日間）

auth-engine の実装を、数日かけてコードと一緒に読み進めるための解説書である。[Architecture](../architecture.md) を**地図**として使い、この解説書はその各区画を**コードの水準まで降りて**読む。設計の理由は [ADR](../README.md)、組み込み手順は [組み込みガイド](../embedding.md) にあり、ここではそれらを引用しながら「この判断がコードのどこに、どういう形で現れているか」を追う。

- **対象**: ブランチ `feat/client-update-delete`（コミット `a978b38`、2026-10-25 時点）。M1〜M3 の実装に、issue #1 の `UpdateClient` / `DeleteClient`（main には未マージ）を加えた状態
- **前提知識**: Go の読み書き。OAuth 2.0 の Authorization Code フローを一度は使ったことがあること（RFC を読み込んでいる必要はない。必要な節は各日に示す）
- **所要時間**: 1 日あたり 1.5〜3 時間。読む時間と手を動かす時間が半々くらい

## 日程

| 日 | テーマ | architecture.md の対応節 | 中心になるコード |
| --- | --- | --- | --- |
| [Day 1](day1-overview.md) | 全体像と組み立て | §1〜§4 | `engine.go` `store.go` `httpapi/server.go` |
| [Day 2](day2-client-and-request.md) | Client Profile と認可要求の検証 | §2、§5 前半、§7 の Profile 表 | `client/` `authorization/request.go` `authorization/pkce.go` |
| [Day 3](day3-transaction.md) | Transaction と Interaction 契約、Code 発行まで | §5、§6 | `authorization/service.go` `httpapi/authorize.go` `httpapi/interaction.go` `grant/` |
| [Day 4](day4-code-exchange.md) | Code 交換、Access Token、ID Token、鍵 | §5 後半、§7 | `token/service.go` `token/issuer.go` `oidc/` `keys/` |
| [Day 5](day5-token-lifecycle.md) | Refresh Rotation、M2M、失効、検査、UserInfo | §7 | `token/refresh.go` `token/revoke.go` `token/introspect.go` `oidc/userinfo.go` |
| [Day 6](day6-storage.md) | 永続化と並行処理 | §9 | `storage/` `adapters/sqlite` `adapters/postgres` |
| [Day 7](day7-mcp.md) | MCP 連携と Resource Server、総まとめ | §8、§10、§11 | `resource/` `cimd/` `resourceserver/` |
| [付録](appendix-invariants.md) | 不変条件とコードの対応表 | — | CLAUDE.md の「守るべき不変条件」全項目 |

順番には理由がある。Day 1〜3 で「認可コードができるまで」、Day 4〜5 で「トークンが生まれて死ぬまで」、Day 6 で「それを支える Store の保証」、Day 7 で「MCP のための拡張」を読む。Day 6 を後ろに置くのは、Store の各メソッドが**なぜその粒度なのか**が、使う側（Day 3〜5）を読んだ後でないと見えないからである。

## 各日の構成

1. **目標** — その日に説明できるようになること
2. **この日の用語** — その日に初めて出てくる、または意味を押さえておくべき用語の表。読み始める前に一度目を通す
3. **読む順** — architecture.md の節 → ADR → コード。この順で読む
4. **解説** — コードを関数単位で追い、「なぜこう書いてあるか」を説明する
5. **手を動かす** — テストの実行、デモ、**壊して確かめる**（下記）
6. **確認問題** — 解答は折りたたんである。先に自分で答えを書いてから開くこと

### 「壊して確かめる」について

いくつかの日に「この 1 行を消すと、どのテストが落ちるか」という演習がある。挙げたテスト名は、このブランチで実際に変更を入れて確かめたものである。自分で試すときは、作業ツリーを汚さないよう別の worktree で行うとよい。

```bash
git worktree add --detach ../auth-engine-lab HEAD
```

終わったら次で片付ける。

```bash
git worktree remove --force ../auth-engine-lab
```

テストが 1 本も落ちない変更もある。それは「テストの穴」か「別の層が同じことを守っている」かのどちらかで、どちらなのかを考えること自体が演習になる。

## コードの参照の仕方

この解説書は行番号を書かない（コードが変わるとずれるため）。代わりに**関数名・型名**で示すので、エディタのシンボル検索か `grep -n` で引くこと。

```bash
grep -n 'func (s \*Service) Resume' authorization/service.go
```

## 共通の準備

```bash
make vet test          # 全モジュールの go vet と go test -race。最初に一度通しておく
go test -run Example ./...   # コア Module の実行可能な使用例だけを流す
```

デモサーバーを動かす演習では、リポジトリ同梱のスクリプトを使う（中身は `.claude/skills/run-demo/SKILL.md`）。

```bash
.claude/skills/run-demo/scripts/demo.sh start -auto-approve
```

`start` はすでに起動しているサーバーをそのまま使い、モード（`-auto-approve` の有無）を切り替えない。モードを変えるときは先に止める。止めるときは次のコマンドを使う。

```bash
.claude/skills/run-demo/scripts/demo.sh stop
```

## 用語集

7 日間を通して使う中心の語だけをここに置く。各日に出てくる細かい用語は、その日の「この日の用語」にある。

この実装を読むときに混乱しやすい語を先に定義しておく。RFC の用語と実装の用語が**同じ綴りで別の意味**を持つものがあるので注意する。

| 用語 | この実装での意味 | 定義している場所 |
| --- | --- | --- |
| Protocol Engine | auth-engine 本体。プロトコル処理と状態管理だけを担い、UI とユーザー管理を持たない（ヘッドレス） | [ADR-0001](../adr/0001-scope-and-principles.md) |
| Interaction App | ログイン・同意画面を持つ外部アプリ。エンジンとは Interaction API（バックチャネル）とブラウザのリダイレクトだけでつながる | [ADR-0003](../adr/0003-interaction-contract.md)、[interaction-api.md](../interaction-api.md) |
| Client Profile | Web / Native / Machine / MCP の 4 種。grant_type、PKCE、認証方式、redirect URI の照合規則を一括で決める。個別のフラグは開放しない | `client.Profile`、[ADR-0004](../adr/0004-client-profiles.md) |
| Transaction | 1 回の `/authorize` 要求から Code 発行（または失敗）までの記録。`pending → completed / rejected → consumed` の状態機械 | `authorization.Transaction` |
| Outcome / Rejection | Interaction App が Complete / Reject で伝える結果。誰が認証され、どの scope に同意したか（または拒否の理由） | `authorization.Outcome` `authorization.Rejection` |
| Resume Token | Complete / Reject の応答で発行する単回使用の秘密値。ブラウザが `/authorize/resume` に持って戻る | `authorization.ResumeTokenPrefix`（`rs_`） |
| Browser Binding | `/authorize` でブラウザに発行する Cookie（`__Host-ae_bind`）。Resume が同じブラウザから来たことを確かめる | `httpapi/cookie.go` |
| Authorization Code | Resume で発行する単回使用の Code。平文は応答にだけ載り、保存は SHA-256 のみ | `authorization.AuthorizationCode` |
| **Grant** | **client_id × subject に対する永続的な認可の記録**（付与済み scope の和集合と Claims）。RFC 6749 §1.3 の "authorization grant"（Code などの資格情報）とは**別物**で、FAPI の Grant Management と同じ意味で使っている | `grant.Grant`、`grant/doc.go` |
| Token Family | 1 回の Code 交換（または 1 回の client_credentials 要求）から派生するトークンの集まり。Refresh Rotation はこの中で連鎖し、失効の単位にもなる | `token.Family` |
| Rotation | Refresh Token を 1 回使うごとに後継と交換すること。古いものは `rotated` になり、再提示されると Family ごと失効する | `token.Service.refresh`、RFC 9700 §4.14.2 |
| Resource | RFC 8707 の resource indicator で指す Resource Server。`Config.Resources` に静的に登録したものだけを受理する | `resource.Resource` `resource.Set` |
| Audience | Access Token が向けられる Resource の一覧。Code → Family → Access Token と、上限を引き継ぎながら狭めていく | `token.Family.Audience` `token.AccessToken.Audience` |
| CIMD | Client ID Metadata Document。`client_id` を HTTPS の URL にし、その URL の JSON 文書から Client を組み立てる。事前登録なしの MCP クライアント向け。DCR（動的登録）ではない | `cimd.Resolver`、`client.NewMCP` |
| Store / Port / Adapter | Store は永続化の口（Port）。各文脈パッケージがインターフェースを定義し、ルートの `authengine.Store` が合成する。Adapter は Memory / SQLite / PostgreSQL の実装 | `store.go`、[ADR-0005](../adr/0005-storage-port.md) |
| fail-closed | 途中で失敗したとき「やり直しが必要になる」側に倒す書き方。たとえば先に消費してから検証し、検証に失敗しても未消費に戻さない | Day 3、Day 4 |

## 読み終えたら

付録の [不変条件とコードの対応表](appendix-invariants.md) を、何も見ずに埋められるか試すとよい。埋められれば、この実装に変更を入れるときに「どの不変条件に触れるか」を自分で判断できる状態になっている。
