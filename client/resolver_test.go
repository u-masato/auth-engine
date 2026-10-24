package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/storage/memory"
)

// fakeResolver は受け取った id を記録し、固定の結果を返す。
type fakeResolver struct {
	calls []string
	c     *client.Client
	err   error
}

func (f *fakeResolver) GetClient(_ context.Context, id string) (*client.Client, error) {
	f.calls = append(f.calls, id)
	return f.c, f.err
}

func TestChainResolver(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	store := memory.New()
	registered, err := client.NewNative(client.NativeParams{ID: "cli", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateClient(ctx, registered); err != nil {
		t.Fatal(err)
	}
	fromCIMD, err := client.NewMCP(client.MetadataDocument{ClientID: "https://c.example/client", ClientName: "C", RedirectURIs: []string{"http://localhost:3000/cb"}}, "https://c.example/client", now)
	if err != nil {
		t.Fatal(err)
	}

	// Store にあれば後続は呼ばれない
	second := &fakeResolver{c: fromCIMD}
	chain := client.ChainResolver{store, second}
	if c, err := chain.GetClient(ctx, "cli"); err != nil || c.ID != "cli" {
		t.Fatalf("store hit: %v %v", c, err)
	}
	if len(second.calls) != 0 {
		t.Fatalf("second resolver must not be called on a store hit: %v", second.calls)
	}

	// Store に無ければ次へ
	if c, err := chain.GetClient(ctx, "https://c.example/client"); err != nil || c.ID != "https://c.example/client" {
		t.Fatalf("fallthrough: %v %v", c, err)
	}

	// ErrNotFound 以外のエラーはそのまま返す（後続を試さない）
	failing := &fakeResolver{err: errors.New("boom")}
	third := &fakeResolver{c: fromCIMD}
	if _, err := (client.ChainResolver{store, failing, third}).GetClient(ctx, "x"); err == nil || err.Error() != "boom" || len(third.calls) != 0 {
		t.Fatalf("non-NotFound error must stop the chain: %v, third calls %v", err, third.calls)
	}
	unresolvable := &fakeResolver{err: client.ErrUnresolvable}
	if _, err := (client.ChainResolver{store, unresolvable}).GetClient(ctx, "https://c.example/client"); !errors.Is(err, client.ErrUnresolvable) {
		t.Fatalf("want ErrUnresolvable, got %v", err)
	}

	// 全部 ErrNotFound なら ErrNotFound。空の Chain も同じ
	notFound := &fakeResolver{err: storage.ErrNotFound}
	if _, err := (client.ChainResolver{store, notFound}).GetClient(ctx, "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := (client.ChainResolver{}).GetClient(ctx, "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("empty chain: want ErrNotFound, got %v", err)
	}
}
