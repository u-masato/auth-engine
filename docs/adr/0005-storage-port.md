# ADR-0005: Storage Port と不変条件の保証

- 状態: 採用（2026-10-24 合意）。2026-11-11 更新: §2〜§4 と §6 のメソッドの形・エラー・実現方法の記述を実装に合わせた。決定（操作単位の原子性、Port にトランザクション抽象を置かない）は変えていない。計画からの差分は末尾の「実装結果」
- 日付: 2026-10-24（2026-11-11 更新）

## 文脈

技術スタック案は「DB Adapter が Code の原子的消費、Refresh Token Rotation、Grant 失効の整合性を保証する」とする。これを SQLite と PostgreSQL の両方で成立させるための Port の粒度を決める。

論点は 2 つある。

1. Port を CRUD（`Get/Save/Delete`）にして原子性をエンジン側で組み立てるか、意図を表す操作（`ConsumeCode`）にして原子性を Adapter に閉じ込めるか。
2. Port に `BeginTx` のようなトランザクション抽象を露出するか。

## 決定

### 1. 「操作単位の原子性」を採る。Port にトランザクション抽象を置かない

- Port の各メソッドは **それ単体で原子的** であることを契約とする。エンジンは複数のメソッド呼び出しをまたいで一貫性を期待しない。
- `BeginTx` / `Tx` を Port に露出しない。理由: DB の意味論がエンジンに漏れ、Adapter の実装自由度（将来の非 SQL ストア）を失い、エンジン側のコードで「どこまでが 1 トランザクションか」が読みにくくなる。
- 結果として、競合が問題になる操作は **CRUD ではなく意図を表す 1 メソッド** になる。

### 2. 不変条件を担う複合操作

| 操作 | 契約 | SQLite / PostgreSQL での実現 |
| --- | --- | --- |
| `TransitionTransaction(ctx, id, from, to, patch)` | 状態が `from` のときだけ `to` に更新し、`patch`（Outcome / Rejection / Resume Token のハッシュ）を同時に書く。違えば `ErrStateConflict`、なければ `ErrNotFound` | `UPDATE ... WHERE id=? AND status=?` の rows affected = 1 を確認。0 行なら存在を調べて `ErrNotFound` と `ErrStateConflict` を分ける |
| `ConsumeAuthorizationCode(ctx, codeHash, now)` | 未消費かつ未期限なら消費済みにして内容を返す。既消費なら `ErrCodeAlreadyUsed` **と消費済みの Code 本体** を返す（Code が持つ Family ID で再利用検知→Token Family 失効）。不明・期限切れなら `ErrNotFound`。消費済みで期限も過ぎた Code は、`Purge` されるまで `ErrCodeAlreadyUsed` | `UPDATE authorization_codes SET consumed_at=? WHERE hash=? AND consumed_at IS NULL AND expires_at>? RETURNING ...`。0 行なら `SELECT` で既消費か不明かを判別。消費済み行は Code 期限まで残す |
| `IssueTokens(ctx, family, access, refresh)` | 新しい Token Family と、それに属する最初の Access Token・Refresh Token（`refresh` は nil でよい）を保存する。Family の Grant が `active` のときだけ挿入し、違えば `ErrGrantRevoked` で何も保存しない | 1 トランザクションで Grant 行を読み（PostgreSQL は `FOR UPDATE`、SQLite は書き込みが直列）→ `INSERT` |
| `RotateRefreshToken(ctx, oldHash, next, access, now)` | 旧トークンが `active` かつ未期限のときだけ `rotated` にし、後継の Refresh Token と新しい Access Token を同じ Token Family に保存する。旧が `rotated` なら `ErrTokenReused`（呼び出し側が Family を失効させる）、旧か Family が `revoked` なら `ErrFamilyRevoked`、Grant が `revoked` なら `ErrGrantRevoked`、不明・期限切れなら `ErrNotFound`。旧トークンの状態を先に見るので、`RevokeGrant` でトークンまで失効している場合は `ErrFamilyRevoked` になる | 1 つの DB トランザクションで `UPDATE ... WHERE hash=? AND status='active'`（rows=1 確認）→ `INSERT`。PostgreSQL は Grant → Token Family → 旧トークンの順に `FOR UPDATE` でロックしてから判定する（2026-11-10 修正。旧トークンだけをロックすると、同時に走る `RevokeGrant` / `DeleteClient` の `UPDATE` が後継を見落とし、Family を先にロックする `RevokeTokenFamily` とはデッドロックする。契約テスト `RotateVersusRevoke`） |
| `RevokeGrant(ctx, grantID, now)` | Grant と、それに属する全 Token Family・全トークンを失効。既に失効済みなら何もせず成功、なければ `ErrNotFound` | 1 トランザクションで `UPDATE grants ... WHERE status='active'`（0 行なら存在を調べる）→ `UPDATE access_tokens` → `UPDATE refresh_tokens` → `UPDATE token_families` |
| `RevokeTokenFamily(ctx, familyID, now)` | Family と配下の全トークンを失効。既に失効済みでも成功、なければ `ErrNotFound` | 1 トランザクションで Family の存在を確認（PostgreSQL は `FOR UPDATE`）→ `UPDATE access_tokens` → `UPDATE refresh_tokens` → `UPDATE token_families` |
| `RevokeAccessToken(ctx, hash, now)` | Access Token 1 つを失効。既に失効済みでも成功、なければ `ErrNotFound`。同じ Family の Refresh Token には触れない | `UPDATE access_tokens ... WHERE hash=? AND status='active'`。0 行なら存在を調べる |
| `UpsertGrant(ctx, candidate)` | `client_id` × `subject` の Grant を作成または更新し、保存後の Grant を返す。既存が `active` なら scope を和集合にし、`revoked` なら候補の内容で `active` に戻す（`grant.Merge`） | 1 トランザクションで既存行を読み（PostgreSQL は `FOR UPDATE`）→ `UPDATE` か `INSERT`。PostgreSQL は同時の初回作成が一意制約に当たったらやり直す |
| `UpdateClient(ctx, client)`（2026-10-25 追加） | 保存済みの Profile が一致するときだけ開放項目を置き換える。違えば `ErrStateConflict`、なければ `ErrNotFound`。ID・Profile・作成日時は変えない（ADR-0004 §4） | `UPDATE clients SET ... WHERE id=? AND profile=?` の rows affected = 1 を確認。0 行なら存在を調べて `ErrNotFound` と `ErrStateConflict` を分ける |
| `DeleteClient(ctx, clientID, now)`（2026-10-25 追加） | Client を削除し、その Client の全 Grant と配下の全 Token Family・全トークンを失効、Authorization Code を削除。なければ `ErrNotFound` で何もしない。Grant の行は失効済みとして残す。進行中の Txn には触れないので、削除後の Resume で Grant が active に戻りうる。同じ ID の作り直しは Txn の有効期限後に行う | 1 トランザクションで `DELETE FROM clients`（rows=1 確認）→ `UPDATE grants` → `UPDATE access_tokens` / `refresh_tokens` / `token_families` → `DELETE FROM authorization_codes`。PostgreSQL では Grant の行ロックで `IssueTokens` / `RotateRefreshToken`（`FOR UPDATE`）と直列になる |

SQLite 側の前提:

- 接続文字列で `_pragma=journal_mode(WAL)`, `_pragma=busy_timeout(5000)`, `_pragma=foreign_keys(1)` を Adapter が固定する。
- 書き込みは `BEGIN IMMEDIATE`（`_txlock=immediate`）で開始し、プロセス内の書き込みトランザクションを Adapter の Mutex で直列化する。SQLite は同時に 1 つの書き込みしか受け付けないので、`SQLITE_BUSY` のリトライより単純で速い。複数プロセスから同じ DB に書く構成では `busy_timeout` だけが待ち合わせになる。
- `*sql.DB` の `SetMaxOpenConns` は利用者任せにせず、Adapter の `Open` が設定する（読み取りの並行度の分として 4）。利用者が用意した `*sql.DB` を渡す `New` では、同じ pragma と `_txlock=immediate` を DSN に含めることを推奨する。
- 並行テストは `:memory:` ではなくファイル DB（WAL）で行う。`:memory:` は接続ごとに別 DB になり、ロック意味論が本番と異なる。

### 3. 単純な作成と読み取りの Port

| 操作 | 備考 |
| --- | --- |
| `CreateClient(ctx, client)` | 同じ ID があれば `ErrAlreadyExists` |
| `GetClient(ctx, clientID)` | `client.Resolver` の 1 実装。M3 で `client.ChainResolver{Store, cimd.Resolver}` に合成し、Store にない URL 形式の `client_id` は CIMD で解決する（ADR-0008 §5） |
| `ListClients(ctx, after, limit)`（2026-11-10 追加） | 登録済みの Client を ID の昇順（バイト列としての比較）で最大 `limit` 件返す。`after` が空でなければ ID がそれより大きいものだけ（キーセットページング）。運用者向けの管理操作で、プロトコル処理からは呼ばない。CIMD で解決した Client は含まない。`SELECT ... WHERE id > ? ORDER BY id LIMIT ?` で実現し、PostgreSQL は既定の照合順序がロケール依存なので `COLLATE "C"` で固定する |
| `CreateTransaction(ctx, txn)` / `GetTransaction(ctx, id)` | Txn 本体。同じ ID があれば `ErrAlreadyExists` |
| `CreateAuthorizationCode(ctx, code)` | Resume 時。同じ Hash があれば `ErrAlreadyExists` |
| `GetGrant(ctx, id)` | Refresh Token の Introspection が Grant の失効を確かめるのに使う |
| `FindGrant(ctx, clientID, subject)` | 同意スキップ判断と連携解除用。失効済みも返す（active かどうかは `grant.Service` が見る） |
| `ListGrantsBySubject(ctx, subject)` | 連携済みアプリ一覧用。失効済みも含め、作成日時の昇順 |
| `LookupAccessToken(ctx, hash)` | Access Token と、それが属する Grant を併せて返す（失効チェックの二重化） |
| `LookupRefreshToken(ctx, hash)` | Refresh Token だけを返す。Client・subject・scope は Family を介して結びつくので、呼び出し側が `GetTokenFamily` で引く |
| `GetTokenFamily(ctx, id)` | Refresh Token の所有者の確認、Refresh 応答の ID Token に載せる元の認証情報（`auth_time` / `amr` / `acr`）の取得 |
| `Purge(ctx, now)` | 期限切れの Txn・Code（消費済みを含む）・Access Token・Refresh Token の削除。Grant・Token Family・Client は削除しない。呼び出しは利用者のスケジューラに委ねる |

### 4. インターフェースの形

- **全メソッドの第一引数は `context.Context`** とする（上表では `ctx` と略記）。HTTP リクエストのキャンセル・タイムアウトを DB 呼び出しまで伝搬し、`database/sql` の `*Context` 系メソッドに渡す。Adapter は `ctx` にトレース情報が載っていればそのまま利用できる（OpenTelemetry 対応をコアに入れずに済む根拠でもある、ADR-0002）。
- `ctx` に値（Txn ID やテナント等）を載せて Port の挙動を変えることは禁止する。引数で渡す。

```go
// 各文脈パッケージが、自分に必要なメソッドだけを定義する（例: authorization/store.go）
type Store interface { /* CreateTransaction, GetTransaction, TransitionTransaction, ... */ }

// ルートパッケージ authengine（store.go）が合成する。Adapter はこれを実装する
type Store interface {
    client.Store
    authorization.Store
    grant.Store
    token.Store
    Purge(ctx context.Context, now time.Time) error
}
```

- インターフェースは **使う側（文脈パッケージ）で定義** し、ルートで合成する。Adapter は合成 `Store` を全て実装する。エンジン内部の各 Service は自分の文脈の `Store` だけを引数に取る（テストの差し替えが容易）。置き場所と依存方向の詳細は ADR-0007 §2。
- `storage` パッケージはセンチネルエラーだけを持つ葉パッケージであり、インターフェースや型は置かない。
- メソッド数は 20 前後に収める。これを超える場合は Port が CRUD 化している兆候として見直す（2026-11-11 時点で 23: client 5、authorization 4、grant 5、token 8、`Purge`）。
- エラーは `storage.ErrNotFound`, `ErrAlreadyExists`, `ErrStateConflict`, `ErrCodeAlreadyUsed`, `ErrTokenReused`, `ErrGrantRevoked`, `ErrFamilyRevoked` のセンチネルで返し、エンジンは `errors.Is` で判別する。Adapter 固有のエラー（接続断など）はセンチネルに写さず、そのまま（文脈を付けてもよい）返す。エンジンは内部障害として扱う。

### 5. 秘密値の保存

- Code、Access Token、Refresh Token、ResumeToken、Client Secret は **SHA-256 ハッシュのみ** を保存する。元値は 256 bit 乱数なのでソルトは不要（辞書攻撃の対象にならない）。
- 平文を保存しないことで DB 読み出し権限だけではトークンを偽造できない。

### 6. 契約テスト（Adapter 共通）

`storage/storagetest` パッケージに、`func Run(t *testing.T, open func(t *testing.T) authengine.Store)` を提供する。全 Adapter はこれを通すことを CI の必須条件とする。内容:

- 各複合操作の正常系・状態違反系
- **並行テスト**: 同一 Code の同時消費（成功は 1 つ、他は `ErrCodeAlreadyUsed`）、同一 Refresh Token の同時 Rotation（成功は 1 つ）、Grant 失効と `IssueTokens` の競合（失効後の発行は必ず失敗）、Txn の同時 Complete（成功は 1 つ）、Client の削除と `IssueTokens` の競合、Rotation と失効（Grant・Token Family・Client の削除）の競合（後継のトークンが有効なまま残らない）
- `go test -race` 下で実行

In-Memory Store（`storage/memory`）はエンジンの単体テスト専用とし、同じ契約テストを通すが、**安全性の根拠は SQLite / PostgreSQL のテスト結果に置く**。

## 却下した代替案

- **Repository + Unit of Work（`BeginTx` を Port に置く）**: エンジン側で「`GetCode` → 検査 → `MarkConsumed`」と書けて読みやすいが、Adapter ごとの分離レベルの差（SQLite は直列、PostgreSQL は READ COMMITTED）が競合の正しさに影響し、エンジンの読者が DB の意味論を知らないと正しさを判断できない。
- **Code の消費を `DELETE ... RETURNING` で行う**: 1 文で済むが、消費済み Code の再提示を「不明」と区別できず、RFC 6749 §4.1.2 の「再利用検知時に当該 Code 由来のトークンを失効」が実装できない。

## 影響

- Adapter 実装者向けに「各メソッドが満たすべき原子性」を `storage/doc.go` に明記する。
- PostgreSQL Adapter（P2）は同じ契約テストを Testcontainers で実行する。

## 実装結果（2026-11-11）

2026-10-24 の決定時の記述と、実装した Port の差分。決定そのもの（§1）は変わっていない。上の表は実装の形に直してあり、ここには何が変わったかを残す。

| 項目 | 決定時の記述 | 実装 |
| --- | --- | --- |
| `IssueTokens` | `(ctx, grantID, tokens)` | `(ctx, family, access, refresh)`。Token Family を引数に取り、Family の作成と最初のトークンの保存を 1 つの操作にした。Grant は `family.GrantID` で引く |
| `RotateRefreshToken` | `(ctx, oldHash, next, now)`。`ErrTokenReused` と Family ID を返す | `(ctx, oldHash, next, access, now)`。新しい Access Token も同じ操作で保存する。Family ID は返さない（呼び出し側は Rotation の前に `LookupRefreshToken` で Family を知っている）。`ErrFamilyRevoked` と `ErrGrantRevoked` を足した |
| `UpsertGrant` | `(ctx, clientID, subject, scopes, claims)` | `(ctx, candidate)`。候補の Grant を渡し、既存との統合は `grant.Merge` に置いた（Adapter が共通で使う）。失効済みの Grant は候補の内容で active に戻す |
| `LookupRefreshToken` | Grant の状態も併せて返す | Refresh Token だけを返す。Family は `GetTokenFamily`、Grant は `GetGrant` で引く。Rotation の判定は `RotateRefreshToken` の中で Family と Grant の状態を見るので、二重化はそこで行う |
| 表になかったメソッド | — | `GetGrant`、`RevokeAccessToken`（M1 タスク 3）、`GetTokenFamily`（M2 タスク 4・5）、`ListGrantsBySubject`（M2 タスク 6）、`UpdateClient`、`DeleteClient`（2026-10-25）、`ListClients`（2026-11-10） |
| センチネル | 5 種を列挙 | 7 種。`ErrAlreadyExists`（作成の重複）と `ErrFamilyRevoked`（失効済みの Family への操作）は M1 からあったが、列挙に載っていなかった |
| SQLite の書き込み | `SQLITE_BUSY` 時のリトライ | プロセス内の Mutex で直列化（リトライは実装していない） |
| 失効の `UPDATE` の順 | `grants` → `refresh_tokens` → `access_tokens` | `grants` → `access_tokens` → `refresh_tokens` → `token_families`（Family にも状態を持たせたため） |
| 契約テストの入口 | `open func(t) storage.Store` | `open func(t) authengine.Store`（合成 Store はルートパッケージにある。ADR-0007 §2） |

未解決の点（決定が要るもの。ここでは方針を変えていない）:

- `Purge` は Token Family と失効済みの Grant を削除しない。Family は Code 交換のたびに 1 行増える。
- Adapter 固有のエラーに文脈（接頭辞）を付けるかどうかは Adapter の中でも揃っていない（トランザクションの開始・コミットには付け、個々の文には付けていない）。
