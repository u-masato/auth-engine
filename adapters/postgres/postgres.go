// Package postgres は authengine.Store の PostgreSQL Adapter である。
//
// pgx/v5 の database/sql ドライバー（stdlib）を使い、スキーマは埋め込んだ SQL マイグレーションを
// goose ライブラリで適用する。goose CLI は不要。
//
// 原子性の保証（docs/adr/0005-storage-port.md）:
//   - 複合操作は 1 つの DB トランザクション（READ COMMITTED）で行い、前提となる行を
//     SELECT ... FOR UPDATE でロックしてから検査・更新する。SQLite Adapter と違いプロセス内の
//     Mutex は使わず、複数プロセス・複数接続の競合も DB の行ロックで直列化する。
//   - 状態遷移は UPDATE ... WHERE status = <from> の更新行数で判定する（CAS）。
//   - 単一行の作成は INSERT ... ON CONFLICT DO NOTHING の更新行数で重複を判定する。
//
// 時刻は UTC の Unix ナノ秒（BIGINT）で保存し、配列・マップは JSONB で保存する。
// SQLite Adapter と列の意味を揃えてあるので、両者を読み比べると方言の差だけが見える。
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql ドライバー "pgx"
	"github.com/pressly/goose/v3"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/storage"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store は PostgreSQL 上の authengine.Store 実装。
type Store struct {
	db *sql.DB
}

var _ authengine.Store = (*Store)(nil)

// Open は DSN（postgres://user:pass@host/db?sslmode=... または key=value 形式）で接続し、
// マイグレーションを適用して Store を返す。
func Open(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("postgres: dsn is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return New(db), nil
}

// New は利用者が用意した *sql.DB から Store を作る。スキーマは Migrate で適用済みであること。
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Migrate は埋め込んだマイグレーションを適用する。何度呼んでも安全。
func Migrate(ctx context.Context, db *sql.DB) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: migrations fs: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return fmt.Errorf("postgres: migration provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	return nil
}

// Close は DB を閉じる。
func (s *Store) Close() error { return s.db.Close() }

// DB は内部の *sql.DB を返す（テストや運用ツール向け）。
func (s *Store) DB() *sql.DB { return s.db }

// write は 1 つのトランザクションで fn を実行する。fn が error を返せばロールバックする。
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// insertOnce は ON CONFLICT DO NOTHING 付きの INSERT を実行し、挿入されなければ ErrAlreadyExists。
func insertOnce(ctx context.Context, ex execer, query string, args ...any) error {
	res, err := ex.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return storage.ErrAlreadyExists
	}
	return nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type rowScanner interface {
	Scan(dest ...any) error
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// exists は query（SELECT EXISTS (...)）の結果を返す。
// 条件付き UPDATE が 0 行だったとき、「存在しない」と「状態が違う」を区別するのに使う。
func exists(ctx context.Context, q queryRower, query string, arg any) (bool, error) {
	var ok bool
	if err := q.QueryRowContext(ctx, query, arg).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

// isUniqueViolation は PostgreSQL の unique_violation（23505）かを返す。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// --- 値の変換 ---

// nanos は time.Time を Unix ナノ秒に変換する。ゼロ値は NULL。
func nanos(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

// mustNanos は NOT NULL 列向け。ゼロ値も 0 として保存する。
func mustNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromNanos(n sql.NullInt64) time.Time {
	if !n.Valid || n.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(0, n.Int64).UTC()
}

// toJSON は NULL 許容列向け。nil（型付き nil ポインタや nil マップを含む）は NULL にする。
func toJSON(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("postgres: marshal: %w", err)
	}
	if string(b) == "null" {
		return nil, nil
	}
	return string(b), nil
}

// mustJSON は NOT NULL 列向け。nil のスライスは "[]" になる。
func mustJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("postgres: marshal: %w", err)
	}
	if string(b) == "null" {
		return "[]", nil
	}
	return string(b), nil
}

func fromJSON(s sql.NullString, v any) error {
	if !s.Valid || s.String == "" || s.String == "null" {
		return nil
	}
	if err := json.Unmarshal([]byte(s.String), v); err != nil {
		return fmt.Errorf("postgres: unmarshal: %w", err)
	}
	return nil
}
