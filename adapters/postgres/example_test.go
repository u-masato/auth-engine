package postgres_test

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql の "pgx" ドライバー

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/adapters/postgres"
)

// ExampleOpen は DSN から接続し、マイグレーションを適用した Store を作る。
// 複数プロセスで同じ DB を共有してよい（競合は行ロックで直列化する）。
func ExampleOpen() {
	ctx := context.Background()
	store, err := postgres.Open(ctx, os.Getenv("DATABASE_URL")) // 例: postgres://auth:secret@db:5432/auth?sslmode=verify-full
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	var _ authengine.Store = store // Config.Store にそのまま渡せる
}

// ExampleNew は接続プールの設定を利用者が持つ場合に、用意した *sql.DB から Store を作る。
// New はマイグレーションを適用しないので、先に Migrate を呼ぶ（デプロイ時のジョブで 1 度だけ流してもよい）。
func ExampleNew() {
	ctx := context.Background()
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(20)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err := postgres.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	store := postgres.New(db)
	var _ authengine.Store = store
}
