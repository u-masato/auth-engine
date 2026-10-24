package sqlite_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/adapters/sqlite"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/keys"
)

// ExampleOpen はファイル DB を開いて Engine に渡す。Open はマイグレーションを適用してから返すので、
// goose CLI などで事前にスキーマを作る必要はない。`:memory:` は使えない（接続ごとに別 DB になる）。
// 再び開いても登録済みの Client は残る。
func ExampleOpen() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "auth-engine-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "auth.db")

	store, err := sqlite.Open(ctx, path)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.NewNative(client.NativeParams{ID: "cli", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/callback"}, Scopes: []string{"openid"}}, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := store.CreateClient(ctx, c); err != nil {
		log.Fatal(err)
	}
	if err := store.Close(); err != nil {
		log.Fatal(err)
	}

	// プロセスの再起動に相当する。
	store, err = sqlite.Open(ctx, path)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		log.Fatal(err)
	}
	engine, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: store, Keys: ks})
	if err != nil {
		log.Fatal(err)
	}
	got, err := engine.Store.GetClient(ctx, "cli")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(got.ID, got.Profile)

	// 期限切れの Transaction・Code・トークンの削除はエンジンが自動では行わない。利用者のスケジューラから呼ぶ。
	if err := engine.Store.Purge(ctx, time.Now()); err != nil {
		log.Fatal(err)
	}

	// Output:
	// cli native
}
