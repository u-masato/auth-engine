package oidc

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/token"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func TestAccessTokenHashVector(t *testing.T) {
	// OIDC Core §3.1.3.6 の例: access_token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" の
	// SHA-256 左半分の base64url は "77QmUPtjPfzWtF2AnpK9RQ"
	got, err := AccessTokenHash(keys.AlgRS256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
	if err != nil {
		t.Fatal(err)
	}
	if got != "77QmUPtjPfzWtF2AnpK9RQ" {
		t.Fatalf("at_hash = %q", got)
	}
	if raw, _ := base64.RawURLEncoding.DecodeString(got); len(raw) != 16 {
		t.Fatalf("at_hash must be 128 bits, got %d bytes", len(raw))
	}
	if _, err := AccessTokenHash("HS256", "x"); err == nil {
		t.Fatal("unsupported alg must fail")
	}
}

func TestIssueIDToken(t *testing.T) {
	set := keys.NewSet()
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		k, _ := keys.Generate(alg, now)
		_ = set.AddSigning(k)
	}
	iss := &IDTokenIssuer{Issuer: "https://as.example.com", Keys: set, Clock: clock.NewFixed(now)}

	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			c, _, err := client.NewWeb(client.WebParams{ID: "web", Name: "W", RedirectURIs: []string{"https://a.example/cb"}, Scopes: []string{"openid"}, IDTokenAlg: alg}, now)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := iss.IssueIDToken(context.Background(), c, token.IDTokenInput{
				Subject: "alice", AuthenticatedAt: now.Add(-5 * time.Minute), Nonce: "n1", AMR: []string{"pwd"}, ACR: "acr1", AccessToken: "at_x",
			})
			if err != nil {
				t.Fatal(err)
			}
			var got idTokenClaims
			h, err := set.Verify(tok, &got)
			if err != nil {
				t.Fatal(err)
			}
			wantHash, _ := AccessTokenHash(alg, "at_x")
			if h.Alg != alg || got.Issuer != "https://as.example.com" || got.Subject != "alice" || len(got.Audience) != 1 || got.Audience[0] != "web" ||
				got.ExpiresAt != now.Add(time.Hour).Unix() || got.IssuedAt != now.Unix() || got.AuthTime != now.Add(-5*time.Minute).Unix() ||
				got.Nonce != "n1" || got.ATHash != wantHash || len(got.AMR) != 1 || got.ACR != "acr1" {
				t.Fatalf("claims: %+v", got)
			}
		})
	}

	// nonce と access token がなければ省略される
	c, _, _ := client.NewWeb(client.WebParams{ID: "web2", Name: "W", RedirectURIs: []string{"https://a.example/cb"}, Scopes: []string{"openid"}}, now)
	iss.TTL = 5 * time.Minute
	tok, err := iss.IssueIDToken(context.Background(), c, token.IDTokenInput{Subject: "bob", AuthenticatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if _, err := set.Verify(tok, &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m["nonce"]; has {
		t.Fatal("nonce must be omitted")
	}
	if _, has := m["at_hash"]; has {
		t.Fatal("at_hash must be omitted")
	}
	if m["exp"] != float64(now.Add(5*time.Minute).Unix()) {
		t.Fatalf("custom ttl: %v", m["exp"])
	}

	// Machine Profile と空 subject は拒否
	m2m, _, _ := client.NewMachine(client.MachineParams{ID: "svc", Name: "S", Scopes: []string{"api"}}, now)
	if _, err := iss.IssueIDToken(context.Background(), m2m, token.IDTokenInput{Subject: "x", AuthenticatedAt: now}); err == nil {
		t.Fatal("machine client must not get id tokens")
	}
	if _, err := iss.IssueIDToken(context.Background(), c, token.IDTokenInput{AuthenticatedAt: now}); err == nil {
		t.Fatal("empty subject must fail")
	}
}

func TestFilterClaims(t *testing.T) {
	claims := map[string]any{
		"name": "Alice", "email": "a@example.com", "email_verified": true, "phone_number": "+81",
		"address": map[string]any{"country": "JP"}, "custom_role": "admin",
		"sub": "evil", "iss": "evil", "exp": 1,
	}
	got := FilterClaims(claims, []string{"openid", "email"})
	if got["email"] != "a@example.com" || got["email_verified"] != true {
		t.Fatalf("email scope claims missing: %v", got)
	}
	for _, denied := range []string{"name", "phone_number", "address", "sub", "iss", "exp"} {
		if _, has := got[denied]; has {
			t.Fatalf("%s must be filtered: %v", denied, got)
		}
	}
	if got["custom_role"] != "admin" {
		t.Fatal("non-standard claims pass through")
	}
	all := FilterClaims(claims, []string{"openid", "profile", "email", "address", "phone"})
	if len(all) != 6 {
		t.Fatalf("all scopes: %v", all)
	}
	if len(FilterClaims(nil, nil)) != 0 {
		t.Fatal("nil claims")
	}
	if len(ClaimsSupported()) < 20 || len(StandardScopes) != 5 {
		t.Fatal("discovery lists")
	}
}
