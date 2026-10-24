package grant

import (
	"slices"
	"testing"
	"time"
)

func TestMerge(t *testing.T) {
	base := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	existing := &Grant{ID: "g1", ClientID: "c", Subject: "s", Scopes: []string{"openid", "profile"},
		Claims: map[string]any{"name": "A"}, Status: StatusActive, CreatedAt: base, UpdatedAt: base}
	cand := &Grant{ID: "other", ClientID: "c", Subject: "s", Scopes: []string{"email", "openid"},
		Claims: map[string]any{"name": "B"}, Status: StatusActive, CreatedAt: base.Add(time.Hour), UpdatedAt: base.Add(time.Hour)}

	got := Merge(existing, cand)
	if got.ID != "g1" || !got.CreatedAt.Equal(base) || !got.UpdatedAt.Equal(base.Add(time.Hour)) {
		t.Fatalf("identity fields: %+v", got)
	}
	if !slices.Equal(got.Scopes, []string{"openid", "profile", "email"}) {
		t.Fatalf("active merge must union scopes in order: %v", got.Scopes)
	}
	if got.Claims["name"] != "B" {
		t.Fatalf("claims must be replaced: %v", got.Claims)
	}
	cand.Claims["name"] = "mutated"
	if got.Claims["name"] != "B" {
		t.Fatal("claims must be cloned")
	}

	revoked := *existing
	revoked.Status = StatusRevoked
	revoked.RevokedAt = base
	got = Merge(&revoked, cand)
	if !got.Active() || !got.RevokedAt.IsZero() || !slices.Equal(got.Scopes, []string{"email", "openid"}) {
		t.Fatalf("revived grant must take candidate scopes only: %+v", got)
	}
}
