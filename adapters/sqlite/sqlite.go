// Package sqlite は authengine.Store の SQLite Adapter である。
//
// modernc.org/sqlite（CGO 不要）を使い、スキーマは埋め込んだ SQL マイグレーションを
// goose ライブラリで適用する。goose CLI は不要。
//
// 原子性の保証（docs/adr/0005-storage-port.md）:
//   - 書き込みは 1 つの DB トランザクションで行い、プロセス内では Mutex で直列化する。
//     BEGIN IMMEDIATE（_txlock=immediate）で開始するので、複数プロセスからの書き込みは
//     SQLite のロックと busy_timeout で直列化される。
//   - 読み取りは WAL により書き込みと並行できる。
//
// 時刻は UTC の Unix ナノ秒で保存し、配列・マップは JSON で保存する。
// `:memory:` は接続ごとに別 DB になるので対応しない。ファイル DB を使うこと。
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sync"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // database/sql ドライバー "sqlite"

	authengine "github.com/u-masato/auth-engine"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store は SQLite 上の authengine.Store 実装。
type Store struct {
	db *sql.DB
	// writeMu はプロセス内の書き込みトランザクションを直列化する。
	// SQLite は同時に 1 つの書き込みしか受け付けないため、Go 側で待ち合わせた方が
	// SQLITE_BUSY のリトライより単純で速い。
	writeMu sync.Mutex
}

var _ authengine.Store = (*Store)(nil)

// Open はファイル DB を開き、マイグレーションを適用して Store を返す。
//
// DSN には次を固定する: journal_mode=WAL、busy_timeout=5000ms、foreign_keys=ON、
// 書き込みトランザクションは BEGIN IMMEDIATE。
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("sqlite: a file path is required (:memory: is not supported)")
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	// 書き込みは Mutex で直列化するので、接続は読み取りの並行度の分だけあればよい。
	db.SetMaxOpenConns(4)
	db.SetConnMaxLifetime(0)
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return New(db), nil
}

// New は利用者が用意した *sql.DB から Store を作る。スキーマは Migrate で適用済みであること。
// DSN に Open と同じ pragma と _txlock=immediate を含めることを推奨する。
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Migrate は埋め込んだマイグレーションを適用する。何度呼んでも安全。
func Migrate(ctx context.Context, db *sql.DB) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: migrations fs: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, fsys)
	if err != nil {
		return fmt.Errorf("sqlite: migration provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	return nil
}

// Close は DB を閉じる。
func (s *Store) Close() error { return s.db.Close() }

// DB は内部の *sql.DB を返す（テストや運用ツール向け）。
func (s *Store) DB() *sql.DB { return s.db }

// write は書き込みトランザクションを直列化して実行する。fn が error を返せばロールバックする。
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	return nil
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
		return nil, fmt.Errorf("sqlite: marshal: %w", err)
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
		return "", fmt.Errorf("sqlite: marshal: %w", err)
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
		return fmt.Errorf("sqlite: unmarshal: %w", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
