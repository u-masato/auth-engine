# Day 6 永続化と並行処理

[← Day 5](day5-token-lifecycle.md) ｜ [索引](README.md) ｜ [Day 7 →](day7-mcp.md)

## 目標

- Store Port に `BeginTx` がない理由と、代わりに何を契約にしているかを説明できる
- 主要な Store 操作ごとに、Memory / SQLite / PostgreSQL がどう原子性を実現しているかを対応づけられる
- 失効の連鎖（Grant → Family → トークン）と、発行との競合をどう解いているかを説明できる
- 契約テスト `storagetest.Run` の役割と、並行テストの限界を説明できる

## この日の用語

| 用語 | 意味 | 出てくる場所 |
| --- | --- | --- |
| Store Port | エンジンと永続化の境界。トランザクションを公開せず、各メソッドが単体で原子的であることを契約にする | ADR-0005 |
| 単体で原子的 | 1 回のメソッド呼び出しが、途中の状態を外から見せずに全部成功するか全部失敗するかのどちらかになること | `storage/doc.go` |
| 意図を表すメソッド | 競合が問題になる複合操作を 1 つにまとめた Store のメソッド（`RotateRefreshToken` など） | `token/store.go` |
| 条件付き UPDATE | `UPDATE ... WHERE status = 'active'` のように前提を条件に含め、更新行数で成否を判定する CAS の実装 | `TransitionTransaction` の各 Adapter |
| 行ロック（`SELECT ... FOR UPDATE`） | 読んだ行を、トランザクションが終わるまで他の書き込みから守る PostgreSQL の仕組み | `adapters/postgres` |
| READ COMMITTED | PostgreSQL の既定の分離レベル。確定済みのデータだけが見えるが、読んでから書くまでの間に他が割り込みうる | `postgres.go` のパッケージコメント |
| `BEGIN IMMEDIATE` | SQLite で、開始時点で書き込みロックを取るトランザクション。DSN の `_txlock=immediate` で指定する | `sqlite.Open` |
| WAL | SQLite のジャーナル方式。読み取りが書き込みと並行できる | `sqlite.Open` |
| `busy_timeout` | SQLite がロックの解放を待つ時間。プロセス間の書き込みを待ち合わせる | `sqlite.Open` |
| `writeMu` | SQLite Adapter のプロセス内の書き込み Mutex。`SQLITE_BUSY` のリトライの代わりに Go 側で待つ | `sqlite.Store` |
| `ON CONFLICT DO NOTHING` | 主キーの重複時に何もしない INSERT。更新行数 0 で重複を検出する | `insertOnce` |
| 一意制約違反のやり直し | 同時の初回 upsert で両方が INSERT したとき、負けた方をやり直して Merge に進ませること | PostgreSQL の `UpsertGrant` |
| 失効の連鎖 | Grant → Family → Access / Refresh Token と、配下をまとめて失効させること | `revokeFamiliesWhere` |
| Purge | 期限切れの Transaction、Code、トークンの行を削除する。正しさではなく容量の問題を扱う | `Store.Purge` |
| 契約テスト | 全 Adapter が通すべき共通のテスト。新しい Adapter が契約を満たすことの定義になる | `storagetest.Run` |
| マイグレーション | スキーマの段階的な変更。SQL を埋め込み、goose をライブラリとして呼ぶ | `Migrate` |
| Testcontainers | テストから Docker で PostgreSQL を起動する仕組み。Docker がなければ Skip する | `adapters/postgres/postgres_test.go` |
| 深いコピー | Memory Adapter が保存・取得のたびに値を複製すること。DB の直列化の境界を模倣する | `clone` |

## 読む順

1. [architecture.md §9 永続化と並行処理](../architecture.md#storage)
2. [ADR-0005 Storage Port](../adr/0005-storage-port.md)（全体）
3. [storage/doc.go](../../storage/doc.go)（Adapter 実装者への契約。このブランチで追加した `UpdateClient` / `DeleteClient` の契約もここにある）
4. コード
   - 各文脈の Store: [client/store.go](../../client/store.go)、[authorization/store.go](../../authorization/store.go)、[grant/store.go](../../grant/store.go)、[token/store.go](../../token/store.go)
   - [storage/memory/memory.go](../../storage/memory/memory.go)
   - [adapters/sqlite/sqlite.go](../../adapters/sqlite/sqlite.go)、[adapters/sqlite/tokens.go](../../adapters/sqlite/tokens.go)、[adapters/sqlite/transactions.go](../../adapters/sqlite/transactions.go)
   - [adapters/postgres/postgres.go](../../adapters/postgres/postgres.go)、[adapters/postgres/tokens.go](../../adapters/postgres/tokens.go)、[adapters/postgres/grants.go](../../adapters/postgres/grants.go)
   - [adapters/sqlite/migrations/00001_init.sql](../../adapters/sqlite/migrations/00001_init.sql)
   - [storage/storagetest/storagetest.go](../../storage/storagetest/storagetest.go)

## 解説

### 1. トランザクションを Port に出さない

Store Port には `BeginTx` / `Commit` がない。代わりに、**各メソッドが単体で原子的であること**を契約にしている（ADR-0005 §1）。

もし Port に `BeginTx` があれば、Service 側は「Code を読む → 検証する → 消費済みにする → Family を作る」を 1 つのトランザクションで書けそうに見える。しかしそうすると、

- 原子性の正しさが、Service のコードの書き方（どこで Begin し、どこで Commit するか）に依存する
- Adapter ごとに分離レベルやロックの挙動が違い、同じ Service のコードが Adapter によって正しかったり間違っていたりする
- Memory のテスト用 Store で「トランザクション」を正しく模倣するのが難しい

そこで、競合が問題になる操作を**意図を表す 1 メソッド**にまとめた。Day 3〜5 で見てきた次のメソッドがそれである。

| メソッド | 1 操作で行うこと | 使う側 |
| --- | --- | --- |
| `TransitionTransaction` | Status が `from` なら `to` にし、Patch を書く（CAS） | Complete / Reject / Resume |
| `ConsumeAuthorizationCode` | 未消費・未期限なら消費済みにして返す。消費済みなら記録と `ErrCodeAlreadyUsed` | Code 交換 |
| `IssueTokens` | Grant が active か確かめ、Family と最初のトークンを保存 | Code 交換、client_credentials |
| `RotateRefreshToken` | 旧トークンが active なら rotated にし、後継と Access Token を保存 | Refresh |
| `RevokeTokenFamily` | Family と配下の全トークンを失効 | 再利用検知、Revocation |
| `RevokeGrant` | Grant と全 Family・全トークンを失効 | `Grants.Revoke` |
| `DeleteClient` | Client を削除し、全 Grant の失効（連鎖つき）と Code の削除を行う | このブランチで追加 |

Service はこれらの戻り値（センチネルエラー）で分岐するだけである。**複数メソッドの呼び出しをまたいだ一貫性は期待しない**。たとえば Day 4 の「Code を消費 → Family を作成」は 2 つの操作に分かれているので、間に障害が起きると「Code は消費済みだが Family はない」状態が残る。これは fail-closed の側に倒れているので許容し、競合の窓は `revokeFamilyOnReuse` のコメントに明記してある。

全 Port メソッドの第一引数は `context.Context` で、`ctx` に値を載せて挙動を変えることはしない（CLAUDE.md）。挙動を変える値はすべて引数として見えるようにする、という規律である。

### 2. 3 つの Adapter の原子性

architecture.md §9 の表を、操作ごとに分解したのが次の表である。

| 操作 | Memory | SQLite | PostgreSQL |
| --- | --- | --- | --- |
| 共通の土台 | 全操作を 1 つの `sync.Mutex` で直列化 | 書き込みは `writeMu`（プロセス内 Mutex）+ `BEGIN IMMEDIATE`（`_txlock=immediate`）。プロセス間は SQLite のファイルロックと `busy_timeout` | `READ COMMITTED` の DB トランザクション + `SELECT ... FOR UPDATE`。プロセス内の Mutex はない |
| `TransitionTransaction` | 状態を比べて書き換え | `UPDATE ... WHERE id = ? AND status = ?` の更新行数。0 なら `exists` で「ない」と「状態違い」を区別 | 同じ形の条件付き UPDATE |
| `ConsumeAuthorizationCode` | `ConsumedAt` を見て書き換え | `UPDATE ... SET consumed_at WHERE hash = ? AND consumed_at IS NULL AND expires_at > ? RETURNING ...`。返らなければ SELECT で理由を調べる | 同じ UPDATE ... RETURNING を**トランザクションなしの 1 文**で実行。行ロックで直列化され、2 番目は WHERE を再評価して 0 行になる |
| `IssueTokens` | Grant を見て挿入 | `writeMu` の中で Grant を確かめて挿入 | `SELECT status FROM grants WHERE id = $1 FOR UPDATE` で Grant 行をロックしてから挿入 |
| `RotateRefreshToken` | 状態を見て書き換え | `writeMu` の中で状態を確かめ、`UPDATE ... AND status = 'active'` | 旧 Refresh Token 行と Family 行を `FOR UPDATE` でロックし、さらに `UPDATE ... AND status = $5` の更新行数で確かめる |
| `RevokeGrant` | Grant と配下を書き換え | `UPDATE grants ... AND status = 'active'` の後、`revokeFamiliesWhere` で Access → Refresh → Family の順に失効 | 同じ。Grant 行の UPDATE が行ロックを取るので、同じ Grant への `IssueTokens`（`FOR UPDATE`）と直列になる |

いくつか補足する。

- **Memory は JSON で深いコピーをとる**（`clone`）。DB Adapter の「直列化して保存し、復元して返す」境界を模倣し、呼び出し側が受け取った値を書き換えても保存内容が変わらないことを保証する（`TestContract/ValuesAreCopied`）。本番では使わない
- **SQLite は `:memory:` を受け付けない**。接続ごとに別の DB になり、並行テストの前提が崩れるからである。契約テストもファイル DB で回す（ADR-0005 §6）
- **SQLite の `writeMu`** は、SQLite が同時に 1 つの書き込みしか受け付けないことを、`SQLITE_BUSY` のリトライではなく Go 側の待ち合わせで扱うためのもの。読み取りは WAL で書き込みと並行できる
- **重複の検出は `INSERT ... ON CONFLICT (主キー) DO NOTHING` の更新行数**で行う（`insertOnce`）。`INSERT OR IGNORE` は他の制約違反まで黙って捨てるので使わない
- **PostgreSQL の `UpsertGrant`** は、同じ client_id × subject の最初の upsert が同時に走ると、両方が「既存なし」と判断して INSERT し、片方が一意制約違反になる。これを `isUniqueViolation` で検知して最大 3 回やり直す。2 回目には既存行が見えるので、Merge の側に進む

### 3. 失効と発行の競合

`RevokeGrant` と `IssueTokens` が同時に走ったとき、何が保証されるべきか。契約テスト `testRevokeGrantVersusIssue` が答えを書いている。

> 発行が成功したなら、そのトークンは失効済みでなければならない。

つまり「失効の後に発行が成功して、生きたトークンが残る」ことだけは許さない。PostgreSQL では、`IssueTokens` が Grant 行を `FOR UPDATE` でロックし、`RevokeGrant` の UPDATE も同じ行のロックを取るので、両者は必ずどちらかが先になる。

- 失効が先: 発行側は失効済みの Grant を読んで `ErrGrantRevoked`
- 発行が先: 失効側は、発行されたばかりの Family も `revokeFamiliesWhere` で失効させる

`DeleteClient` も、Grant の UPDATE で同じ行ロックを取るので、同じ形で直列になる（`testClientDeleteVersusIssue`）。

### 4. スキーマの読み方

[00001_init.sql](../../adapters/sqlite/migrations/00001_init.sql) を開くと、ここまでの設計がそのまま列に現れている。

- 秘密値の表（`authorization_codes` `access_tokens` `refresh_tokens`）の主キーは `hash`。平文の列はない
- `authorization_codes.consumed_at` — NULL なら未消費。再利用を検知するため、期限まで行を残す
- `grants` の `UNIQUE (client_id, subject)` — Grant は client_id × subject に 1 つ
- `refresh_tokens.replaced_by_hash` — Rotation の鎖
- 時刻は UTC の Unix ナノ秒、配列やマップは JSON（PostgreSQL は JSONB）

マイグレーションは `//go:embed migrations/*.sql` で埋め込み、goose をライブラリとして `Migrate` から呼ぶ（goose CLI は不要）。SQLite と PostgreSQL で番号が 1 つずれているのは、SQLite の `00002_family_auth.sql`（Family に認証情報の写しを足す。M2 タスク 4）が PostgreSQL Adapter（M2 タスク 7）より前に入り、PostgreSQL ではその列が最初から `00001_init.sql` に含まれているためである。列の意味は揃えてある。「両者を読み比べると方言の差だけが見える」（[postgres.go](../../adapters/postgres/postgres.go) のパッケージコメント）ように書かれている。

### 5. Client の更新と削除（このブランチ）

`UpdateClient` は保存済みの Profile との照合と更新を 1 操作で行う。Profile が違えば `ErrStateConflict` で、何も変えない。`ID` `Profile` `CreatedAt` は書き換えない。

`DeleteClient` は Client の削除と同じ操作で次を行う（[storage/doc.go](../../storage/doc.go)）。

- その Client の全 Grant を失効させ、配下の全 Family・全トークンも失効させる（`RevokeGrant` と同じ連鎖）。Grant の行は失効済みとして残す
- その Client の Authorization Code を、消費済みも含めて削除する

Code を削除する理由は少し込み入っている。同じ client_id で Client を作り直して再同意すると、`UpsertGrant` が同じ Grant を active に戻す（Day 3 の `grant.Merge`）。そのとき削除前に発行した未使用の Code が残っていると、作り直した Client で交換できてしまう。

一方、進行中の Transaction には触れない。削除前に同意が済んだ Transaction を削除後に Resume すると、Grant が active に戻り、新しい Code が発行される（その Code の交換は Client 認証で失敗する）。そのため「同じ client_id での作り直しは Transaction の期限が過ぎてから」という運用上の前提が、契約のコメントに書かれている。**契約で守り切れない部分を、運用の前提として明文化している**例である。

### 6. Purge

`Store.Purge(now)` は期限切れの Transaction、Code、Access Token、Refresh Token を削除する。消費済みの Code もここで消える（期限が過ぎれば再利用の検知は要らない）。Grant と Family は削除しない。呼び出す頻度はホストのスケジューラに任せる（architecture.md §10）。

期限の判定はすべて `Expired(now)` で行っているので、Purge を呼ばなくても**正しさ**は変わらない。Purge は容量の問題を扱うだけである。

### 7. 契約テスト

`storagetest.Run(t, open)` は、`open` が返す空の Store に対して 18 個のサブテストを実行する。各 Adapter のテストは 1 行で済む。

```go
func TestContract(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) authengine.Store { return openTemp(t) })
}
```

CRUD に加え、`concurrency = 16` の goroutine で次の競合を起こす。

- `TransactionConcurrentComplete` — 同じ Transaction への同時 Complete。成功は 1 つ
- `AuthorizationCodeConcurrentConsume` — 同じ Code の同時消費。成功は 1 つ、残りは `ErrCodeAlreadyUsed`
- `RotateConcurrent` — 同じ Refresh Token の同時 Rotation。成功は 1 つ、後継は 1 本
- `RevokeGrantVersusIssue` / `ClientDeleteVersusIssue` — 失効と発行の競合

新しい Adapter（たとえば MySQL）を書く人は、このテストを通すことが「Port の契約を満たした」ことの定義になる（CLAUDE.md「全 Adapter は `storage/storagetest` を通す」）。

## 手を動かす

### 1. 各 Adapter で契約テストを回す

```bash
go test -race -run TestContract -v ./storage/memory/
```

```bash
(cd adapters/sqlite && go test -race -count=1 ./...)
```

PostgreSQL は Docker が必要（なければ Skip される）。

```bash
(cd adapters/postgres && go test -race -count=1 ./...)
```

### 2. 壊して確かめる（SQLite）

| 変更 | 結果 |
| --- | --- |
| `transactions.go` の `TransitionTransaction` の `WHERE id = ? AND status = ?` から status の条件を外す | `TestContract/Transaction`、`TestContract/TransactionConcurrentComplete` が落ちる |
| `tokens.go` の `RotateRefreshToken` の `UPDATE ... WHERE hash = ? AND status = ?` から status の条件を外す | **落ちない** |

2 つ目が落ちないのはなぜか。同じ関数の中で、旧トークンの状態をどこで確かめているか、その確認と UPDATE の間に別の書き込みが割り込めるかを考える（ヒント: `write` と `writeMu`）。そのうえで、この条件は消してよいかどうかも考える。別のプロセスが同じ DB ファイルを開いていても、SELECT は `BEGIN IMMEDIATE` で始めたトランザクションの中にあるので、間に書き込みは入らない。条件が効いてくるのは、利用者が `_txlock=immediate` を含まない DSN で開いた `*sql.DB` を `sqlite.New(db)` に渡した場合である（`New` のコメントは推奨にとどめている）。そのとき何が起こりうるかを考えること。

### 3. 並行テストが本当に競合を起こしているか（PostgreSQL）

`adapters/postgres/tokens.go` の `RotateRefreshToken` で、次の 3 つを**すべて**外す。

- 旧 Refresh Token の SELECT の `FOR UPDATE`
- Family の SELECT の `FOR UPDATE OF f`
- UPDATE の `AND status = $5`

これで同時 Rotation を防ぐものは何もなくなる。ところが、このブランチで試したところ、`TestContract/RotateConcurrent` は `-count=20` で 20 回とも**通った**。旧トークンの SELECT の直後に `time.Sleep(20 * time.Millisecond)` を挟むと、毎回「16 succeeded, 0 reused」で落ちる。同じ Sleep を入れても、元のロックがあれば通る。

```bash
(cd adapters/postgres && go test -count=20 -run 'TestContract/RotateConcurrent' ./...)
```

ここから言えるのは、**並行テストが通ることは、競合を正しく扱っている証拠として弱い**ということである。各 goroutine の処理が速すぎて、実際には重ならずに順番に実行されている可能性がある（テストごとに新しい schema と接続プールを作るので、接続の確立に時間がかかり、実行が自然にずれることなどが考えられる）。

- 競合の窓を確実に開くには、テストにどんな仕掛けが要るか（全 goroutine を同じ地点で待たせる、Adapter にフックを入れる、など）
- その仕掛けを入れると、Port や Adapter の設計にどんな影響があるか

を考えてみること。正解は 1 つではない。

## 確認問題

1. Store Port に `BeginTx` を置かないことで、Service のコードから消えたものと、Adapter に移った責任をそれぞれ挙げよ。
2. PostgreSQL の `ConsumeAuthorizationCode` がトランザクションを使わずに原子的なのはなぜか。
3. `RevokeGrant` と `IssueTokens` が同時に走ったとき、契約上許されない結果は何か。PostgreSQL ではそれをどう防いでいるか。
4. `Purge` を一度も呼ばなかったら、正しさと運用のそれぞれに何が起きるか。
5. `DeleteClient` が進行中の Transaction を削除しないことで起こりうることと、それを運用でどう避けるかを説明せよ。

<details>
<summary>解答</summary>

1. 消えたもの: トランザクションの開始・確定・ロールバックの制御と、分離レベルやロックを意識したコード。Service は「意図を表すメソッドを呼び、戻り値のセンチネルエラーで分岐する」だけになる。Adapter に移った責任: 各メソッドを単体で原子的に実装すること（DB トランザクション、行ロック、条件付き UPDATE、プロセス内 Mutex など手段は Adapter が選ぶ）と、契約テストを通すこと。
2. 「未消費・未期限なら消費済みにする」を `UPDATE ... WHERE consumed_at IS NULL AND expires_at > $1 RETURNING` の 1 文で行っているからである。PostgreSQL は 1 文の UPDATE を原子的に実行し、同じ行への同時 UPDATE は行ロックで直列化され、後の文は WHERE を再評価して 0 行になる。続く SELECT は、0 行だった理由（消費済みか、期限切れか、存在しないか）を調べるためだけのもので、判定の原子性には関わらない。
3. 「失効が終わった後に発行が成功し、active なトークンが残る」こと。`IssueTokens` は Grant 行を `SELECT ... FOR UPDATE` でロックしてから status を確かめ、`RevokeGrant` は同じ行を UPDATE する。行ロックで必ずどちらかが先になり、失効が先なら発行は `ErrGrantRevoked`、発行が先なら失効がその Family も連鎖で失効させる。
4. 正しさは変わらない。期限の判定はすべて `Expired(now)` で行うので、期限切れの行が残っていても有効とは判定されない。運用面では、Transaction、Code、トークンの行が溜まり続け、DB の容量と索引の効率が悪化する。
5. 削除前に同意が済んだ Transaction を削除後に Resume すると、`UpsertGrant` が Grant を active に戻し、新しい Code が発行される（交換は Client 認証で失敗するので、トークンは出ない）。同じ client_id で Client を作り直すと、この Grant と Code が新しい Client に引き継がれうる。だから作り直しは、Transaction の最大寿命（`TransactionTTL`、上限 1 時間）が過ぎてから行う。
</details>
