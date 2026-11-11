package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/storage/storagetest"
	"github.com/u-masato/auth-engine/token"
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

// TestRotateAfterPurgeRemovedFamily は、RotateRefreshToken がロックする行を読んだ後で Purge が
// 旧トークンごと Token Family を消した場合に、ErrNotFound になることを確かめる（ADR-0005 §7）。
//
// 契約テストの PurgeVersusRotate はこの順序をほとんど踏まないので、Grant の行ロックで Rotation を
// 止めて順序を固定する。
func TestRotateAfterPurgeRemovedFamily(t *testing.T) {
	s := openTemp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	g, err := s.UpsertGrant(ctx, &grant.Grant{ID: "g1", ClientID: "c1", Subject: "alice", Scopes: []string{"openid"},
		Status: grant.StatusActive, CreatedAt: base, UpdatedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	family := &token.Family{ID: "f1", GrantID: g.ID, ClientID: "c1", Subject: "alice", Scopes: []string{"openid"},
		Status: token.FamilyActive, CreatedAt: base, ExpiresAt: base.Add(time.Hour)}
	access := func(hash string, expires time.Time) *token.AccessToken {
		return &token.AccessToken{Hash: hash, FamilyID: family.ID, GrantID: g.ID, ClientID: "c1", Subject: "alice",
			Scopes: []string{"openid"}, Status: token.AccessActive, IssuedAt: base, ExpiresAt: expires}
	}
	refresh := func(hash string, expires time.Time) *token.RefreshToken {
		return &token.RefreshToken{Hash: hash, FamilyID: family.ID, Status: token.RefreshActive, IssuedAt: base, ExpiresAt: expires}
	}
	if err := s.IssueTokens(ctx, family, access("at1", base.Add(time.Minute)), refresh("rt1", base.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}

	// Grant の行をロックして、Rotation を「ロックする行を読んだ後、Grant のロック待ち」で止める
	blocker, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	if _, err := blocker.ExecContext(ctx, `SELECT 1 FROM grants WHERE id = $1 FOR UPDATE`, g.ID); err != nil {
		t.Fatal(err)
	}
	rotated := make(chan error, 1)
	go func() {
		rotated <- s.RotateRefreshToken(ctx, "rt1", refresh("rt2", base.Add(time.Hour)), access("at2", base.Add(time.Hour)), base)
	}()
	for {
		var waiting int
		if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE pid <> pg_backend_pid() AND datname = current_database() AND wait_event_type = 'Lock'
			  AND query LIKE '%FROM grants WHERE id =%FOR UPDATE%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case err := <-rotated:
			t.Fatalf("rotation finished before it was blocked: %v", err)
		case <-ctx.Done():
			t.Fatal("rotation never blocked on the grant row")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// 旧トークンは Purge の時刻では期限切れ。Family ごと消える
	if err := s.Purge(ctx, base.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetTokenFamily(ctx, family.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("family must be purged: %v", err)
	}
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-rotated; !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("rotation after the purge: got %v, want ErrNotFound", err)
	}
	if _, err := s.LookupRefreshToken(ctx, "rt2"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("successor must not exist: %v", err)
	}
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
