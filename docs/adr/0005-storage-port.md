# ADR-0005: Storage Port と不変条件の保証

- 状態: 採用（2026-10-24 合意）
- 日付: 2026-10-24

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
| `TransitionTransaction(ctx, id, from, to, patch)` | 状態が `from` のときだけ `to` に更新。違えば `ErrStateConflict` | `UPDATE ... WHERE id=? AND status=?` の rows affected = 1 を確認 |
| `ConsumeAuthorizationCode(ctx, codeHash, now)` | 未消費かつ未期限なら消費済みにして内容を返す。既消費なら `ErrCodeAlreadyUsed` **と消費済みの Code 本体** を返す（Code が持つ Family ID で再利用検知→Token Family 失効）。不明・期限切れなら `ErrNotFound` | `UPDATE codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL RETURNING ...`。0 行なら `SELECT` で既消費か不明かを判別。消費済み行は Code 期限まで残す |
| `RotateRefreshToken(ctx, oldHash, next RefreshToken, now)` | 旧トークンが `active` のときだけ `rotated` にし、新トークンを同じ Token Family に挿入。旧が `rotated` なら `ErrTokenReused` と Family ID を返す | 1 つの DB トランザクションで `UPDATE ... WHERE hash=? AND status='active'`（rows=1 確認）→ `INSERT` |
| `IssueTokens(ctx, grantID, tokens)` | Grant が `active` のときだけ挿入。違えば `ErrGrantRevoked` | 1 トランザクションで Grant 行を読み（PostgreSQL は `FOR UPDATE`、SQLite は書込トランザクション自体が直列）→ `INSERT` |
| `RevokeGrant(ctx, grantID, now)` | Grant と、それに属する全 Token Family・全トークンを失効 | 1 トランザクションで `UPDATE grants` → `UPDATE refresh_tokens` → `UPDATE access_tokens` |
| `RevokeTokenFamily(ctx, familyID, now)` | Family 内の全トークンを失効 | 同上 |

SQLite 側の前提:

- 接続文字列で `_pragma=journal_mode(WAL)`, `_pragma=busy_timeout(5000)`, `_pragma=foreign_keys(1)` を Adapter が固定する。
- 書き込みは `BEGIN IMMEDIATE` で開始し、`SQLITE_BUSY` 時のリトライを Adapter 内で行う。
- `*sql.DB` の `SetMaxOpenConns` は利用者任せにせず、Adapter の `Open` が妥当値を設定する。
- 並行テストは `:memory:` ではなくファイル DB（WAL）で行う。`:memory:` は接続ごとに別 DB になり、ロック意味論が本番と異なる。

### 3. 読み取り系の Port

| 操作 | 備考 |
| --- | --- |
| `GetClient(ctx, clientID)` | P1 で `ClientResolver` の 1 実装になる |
| `CreateTransaction(ctx, txn)` / `GetTransaction(ctx, id)` | Txn 本体 |
| `CreateAuthorizationCode(ctx, code)` | Resume 時 |
| `UpsertGrant(ctx, clientID, subject, scopes, claims)` | 同意結果の保存。既存 Grant があれば scope を和集合で更新 |
| `FindGrant(ctx, clientID, subject)` | 同意スキップ判断用 |
| `LookupAccessToken(ctx, hash)` | Grant の状態も併せて返す（失効チェックの二重化） |
| `LookupRefreshToken(ctx, hash)` | 同上 |
| `Purge(ctx, now)` | 期限切れ Txn・Code・トークンの削除。呼び出しは利用者のスケジューラに委ねる |

### 4. インターフェースの形

- **全メソッドの第一引数は `context.Context`** とする（上表では `ctx` と略記）。HTTP リクエストのキャンセル・タイムアウトを DB 呼び出しまで伝搬し、`database/sql` の `*Context` 系メソッドに渡す。Adapter は `ctx` にトレース情報が載っていればそのまま利用できる（OpenTelemetry 対応をコアに入れずに済む根拠でもある、ADR-0002）。
- `ctx` に値（Txn ID やテナント等）を載せて Port の挙動を変えることは禁止する。引数で渡す。

```go
// 各文脈パッケージが、自分に必要なメソッドだけを定義する（例: authorization/store.go）
type Store interface { /* CreateTransaction, GetTransaction, TransitionTransaction, ... */ }

// ルートパッケージ authengine（engine.go）が合成する。Adapter はこれを実装する
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
- メソッド数は 20 前後に収める。これを超える場合は Port が CRUD 化している兆候として見直す。
- エラーは `storage.ErrNotFound`, `ErrStateConflict`, `ErrCodeAlreadyUsed`, `ErrTokenReused`, `ErrGrantRevoked` のセンチネルで返し、エンジンは `errors.Is` で判別する。Adapter 固有のエラーはラップして返す。

### 5. 秘密値の保存

- Code、Access Token、Refresh Token、ResumeToken、Client Secret は **SHA-256 ハッシュのみ** を保存する。元値は 256 bit 乱数なのでソルトは不要（辞書攻撃の対象にならない）。
- 平文を保存しないことで DB 読み出し権限だけではトークンを偽造できない。

### 6. 契約テスト（Adapter 共通）

`storage/storagetest` パッケージに、`func Run(t *testing.T, open func(t *testing.T) storage.Store)` を提供する。全 Adapter はこれを通すことを CI の必須条件とする。内容:

- 各複合操作の正常系・状態違反系
- **並行テスト**: 同一 Code の同時消費（成功は 1 つ、他は `ErrCodeAlreadyUsed`）、同一 Refresh Token の同時 Rotation（成功は 1 つ）、Grant 失効と `IssueTokens` の競合（失効後の発行は必ず失敗）、Txn の同時 Complete（成功は 1 つ）
- `go test -race` 下で実行

In-Memory Store（`storage/memory`）はエンジンの単体テスト専用とし、同じ契約テストを通すが、**安全性の根拠は SQLite / PostgreSQL のテスト結果に置く**。

## 却下した代替案

- **Repository + Unit of Work（`BeginTx` を Port に置く）**: エンジン側で「`GetCode` → 検査 → `MarkConsumed`」と書けて読みやすいが、Adapter ごとの分離レベルの差（SQLite は直列、PostgreSQL は READ COMMITTED）が競合の正しさに影響し、エンジンの読者が DB の意味論を知らないと正しさを判断できない。
- **Code の消費を `DELETE ... RETURNING` で行う**: 1 文で済むが、消費済み Code の再提示を「不明」と区別できず、RFC 6749 §4.1.2 の「再利用検知時に当該 Code 由来のトークンを失効」が実装できない。

## 影響

- Adapter 実装者向けに「各メソッドが満たすべき原子性」を `storage/doc.go` に明記する。
- PostgreSQL Adapter（P2）は同じ契約テストを Testcontainers で実行する。
