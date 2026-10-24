package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/storage/storagetest"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestContract は全 Adapter 共通の契約テスト（並行テスト含む）をファイル DB で実行する。
func TestContract(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) authengine.Store { return openTemp(t) })
}

func TestOpenSettings(t *testing.T) {
	s := openTemp(t)
	var journal string
	if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if journal != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journal)
	}
	var fk int
	if err := s.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatal("foreign_keys must be on")
	}
	// マイグレーションは冪等
	if err := Migrate(context.Background(), s.DB()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if _, err := Open(context.Background(), ":memory:"); err == nil {
		t.Fatal(":memory: must be rejected")
	}
}
