package grant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

func TestService(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	store := memory.New()
	svc := &grant.Service{Store: store, Clock: clock.NewFixed(now)}

	for _, g := range []*grant.Grant{
		{ID: "g1", ClientID: "app1", Subject: "alice", Scopes: []string{"openid"}, Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now},
		{ID: "g2", ClientID: "app2", Subject: "alice", Scopes: []string{"openid", "email"}, Status: grant.StatusActive, CreatedAt: now.Add(time.Second), UpdatedAt: now},
		{ID: "g3", ClientID: "app1", Subject: "bob", Scopes: []string{"openid"}, Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := store.UpsertGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	fam := &token.Family{ID: "f1", GrantID: "g1", ClientID: "app1", Subject: "alice", Scopes: []string{"openid"}, Status: token.FamilyActive, CreatedAt: now}
	at := &token.AccessToken{Hash: "h1", FamilyID: "f1", GrantID: "g1", ClientID: "app1", Subject: "alice", Scopes: []string{"openid"}, Status: token.AccessActive, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.IssueTokens(ctx, fam, at, nil); err != nil {
		t.Fatal(err)
	}

	g, err := svc.Find(ctx, "app1", "alice")
	if err != nil || g.ID != "g1" {
		t.Fatalf("find: %+v %v", g, err)
	}
	if _, err := svc.Find(ctx, "app9", "alice"); !errors.Is(err, grant.ErrNotFound) {
		t.Fatalf("find unknown: %v", err)
	}
	list, err := svc.List(ctx, "alice")
	if err != nil || len(list) != 2 || list[0].ID != "g1" || list[1].ID != "g2" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := svc.List(ctx, ""); err == nil {
		t.Fatal("empty subject must be rejected")
	}

	// 連携解除: Grant と配下のトークンが失効し、一覧・検索から消える
	if err := svc.Revoke(ctx, "app1", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Find(ctx, "app1", "alice"); !errors.Is(err, grant.ErrNotFound) {
		t.Fatalf("find after revoke: %v", err)
	}
	list, _ = svc.List(ctx, "alice")
	if len(list) != 1 || list[0].ID != "g2" {
		t.Fatalf("list after revoke: %+v", list)
	}
	tok, _, _ := store.LookupAccessToken(ctx, "h1")
	if tok.Status != token.AccessRevoked {
		t.Fatal("tokens must be revoked with the grant")
	}
	// 冪等。未登録は ErrNotFound
	if err := svc.Revoke(ctx, "app1", "alice"); err != nil {
		t.Fatalf("revoke twice: %v", err)
	}
	if err := svc.Revoke(ctx, "app9", "alice"); !errors.Is(err, grant.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
}
