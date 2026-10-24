package oidc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/oidc"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

func TestUserInfo(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	store := memory.New()
	clk := clock.NewFixed(now)
	svc := &oidc.UserInfoService{Tokens: store, Clock: clk}

	g, err := store.UpsertGrant(ctx, &grant.Grant{ID: "g1", ClientID: "web", Subject: "alice", Scopes: []string{"openid", "profile", "email"},
		Claims: map[string]any{"name": "Alice", "email": "a@example.com", "phone_number": "+81", "sub": "spoof"},
		Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(hash string, scopes []string, audience ...string) {
		fam := &token.Family{ID: "f-" + hash, GrantID: g.ID, ClientID: "web", Subject: "alice", Scopes: scopes, Audience: audience, Status: token.FamilyActive, CreatedAt: now}
		at := &token.AccessToken{Hash: rand.Hash(hash), FamilyID: fam.ID, GrantID: g.ID, ClientID: "web", Subject: "alice", Scopes: scopes, Audience: audience,
			Status: token.AccessActive, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := store.IssueTokens(ctx, fam, at, nil); err != nil {
			t.Fatal(err)
		}
	}
	issue("at-email", []string{"openid", "email"})
	issue("at-noopenid", []string{"profile"})
	issue("at-all", []string{"openid", "profile", "email"})
	issue("at-aud", []string{"openid", "email"}, "https://mcp.example.com")

	// email scope だけのトークン: name と phone_number は返らない、sub は Access Token の subject
	claims, err := svc.UserInfo(ctx, "at-email")
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "alice" || claims["email"] != "a@example.com" {
		t.Fatalf("claims: %v", claims)
	}
	if _, has := claims["name"]; has {
		t.Fatalf("name must be filtered: %v", claims)
	}
	if _, has := claims["phone_number"]; has {
		t.Fatalf("phone_number must be filtered: %v", claims)
	}
	claims, _ = svc.UserInfo(ctx, "at-all")
	if claims["name"] != "Alice" || claims["email"] != "a@example.com" || claims["sub"] != "alice" {
		t.Fatalf("all: %v", claims)
	}
	// Audience が別の Resource Server でも、openid があれば UserInfo は受理する（UserInfo は AS 自身のリソース。ADR-0008 §3）
	claims, err = svc.UserInfo(ctx, "at-aud")
	if err != nil || claims["sub"] != "alice" || claims["email"] != "a@example.com" {
		t.Fatalf("audience-bound token: %v, %v", claims, err)
	}

	if _, err := svc.UserInfo(ctx, "at-noopenid"); !errors.Is(err, oidc.ErrInsufficientScope) {
		t.Fatalf("no openid: %v", err)
	}
	if _, err := svc.UserInfo(ctx, "unknown"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := svc.UserInfo(ctx, ""); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("empty: %v", err)
	}
	// 失効
	if err := store.RevokeAccessToken(ctx, rand.Hash("at-email"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UserInfo(ctx, "at-email"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("revoked: %v", err)
	}
	// 期限切れ
	clk.Advance(2 * time.Hour)
	if _, err := svc.UserInfo(ctx, "at-all"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("expired: %v", err)
	}
	clk.Set(now)
	// Grant 失効（連鎖でトークンも失効する）
	if err := store.RevokeGrant(ctx, g.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UserInfo(ctx, "at-all"); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("grant revoked: %v", err)
	}
}
