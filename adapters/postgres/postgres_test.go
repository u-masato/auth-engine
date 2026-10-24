package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/storage/storagetest"
)

// 接続先の決め方:
//   - 環境変数 AUTH_ENGINE_POSTGRES_DSN（URL 形式）があればそれを使う（CI でサービスコンテナを使う場合など）。
//   - なければ Testcontainers で postgres:16 を起動する。Docker がなければ Skip。
//
// テストごとに新しいスキーマを作り、search_path をそのスキーマにした接続で Store を開く。
// 契約テストは open のたびに空の Store を要求するため。
var (
	baseDSN   string
	schemaSeq atomic.Int64
)

func TestMain(m *testing.M) {
	code := func() int {
		if dsn := os.Getenv("AUTH_ENGINE_POSTGRES_DSN"); dsn != "" {
			baseDSN = dsn
			return m.Run()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		ctr, err := tcpostgres.Run(ctx, "postgres:16",
			tcpostgres.WithDatabase("authengine"), tcpostgres.WithUsername("test"), tcpostgres.WithPassword("test"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2*time.Minute)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "postgres: skipping: cannot start container (is Docker running?): %v\n", err)
			return 0 // Skip 扱い
		}
		defer func() { _ = testcontainers.TerminateContainer(ctr) }()
		baseDSN, err = ctr.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			fmt.Fprintf(os.Stderr, "postgres: connection string: %v\n", err)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	if baseDSN == "" {
		t.Skip("no PostgreSQL available")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("t%d_%d", time.Now().UnixNano()%1_000_000, schemaSeq.Add(1))
	admin, err := sql.Open("pgx", baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	// pgx は URL の未知のクエリパラメータを実行時パラメータとして送るので、search_path で
	// スキーマを切り替えられる。
	sep := "?"
	if strings.Contains(baseDSN, "?") {
		sep = "&"
	}
	s, err := Open(ctx, baseDSN+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestContract は全 Adapter 共通の契約テスト（並行テスト含む）を実行する。
func TestContract(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) authengine.Store { return openTemp(t) })
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := openTemp(t)
	if err := Migrate(context.Background(), s.DB()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if _, err := Open(context.Background(), ""); err == nil {
		t.Fatal("empty dsn must be rejected")
	}
}
