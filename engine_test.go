package authengine_test

import (
	"testing"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/storage/memory"
)

func testKeys(t *testing.T, algs ...string) *keys.Set {
	t.Helper()
	set := keys.NewSet()
	for _, alg := range algs {
		k, err := keys.Generate(alg, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := set.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

func TestNew(t *testing.T) {
	ks := testKeys(t, keys.AlgRS256)
	e, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks})
	if err != nil {
		t.Fatal(err)
	}
	if e.Authorization == nil || e.Token == nil || e.Authorization.Issuer != "https://as.example.com" || e.Clock == nil || e.IDTokens == nil ||
		e.Token.IDTokens == nil || e.Token.Grants == nil || e.Grants == nil || e.Token.RefreshTokenTTL != 30*24*time.Hour || e.Token.RefreshTokenIdleTTL != 14*24*time.Hour {
		t.Fatalf("engine not wired: %+v", e)
	}
	if time.Since(e.Clock.Now()) > time.Minute {
		t.Fatal("default clock must be real time")
	}

	bad := []authengine.Config{
		{Issuer: "", Store: memory.New(), Keys: ks},
		{Issuer: "as.example.com", Store: memory.New(), Keys: ks},
		{Issuer: "http://as.example.com", Store: memory.New(), Keys: ks},
		{Issuer: "https://as.example.com/path", Store: memory.New(), Keys: ks},
		{Issuer: "https://as.example.com?x=1", Store: memory.New(), Keys: ks},
		{Issuer: "https://as.example.com", Keys: ks},
		{Issuer: "https://as.example.com", Store: memory.New()},                                   // Keys なし
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: testKeys(t, keys.AlgES256)}, // RS256 なし
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, TransactionTTL: 2 * time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, CodeTTL: time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, IDTokenTTL: 48 * time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, RefreshTokenTTL: -time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, RefreshTokenTTL: 24 * time.Hour}, // 既定のスライド期限 14 日を下回る
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, RefreshTokenTTL: 48 * time.Hour, RefreshTokenIdleTTL: 72 * time.Hour},
	}
	for i, cfg := range bad {
		if _, err := authengine.New(cfg); err == nil {
			t.Errorf("config %d must be rejected: %+v", i, cfg)
		}
	}
	for _, iss := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "https://as.example.com/"} {
		if _, err := authengine.New(authengine.Config{Issuer: iss, Store: memory.New(), Keys: ks}); err != nil {
			t.Errorf("%s must be accepted: %v", iss, err)
		}
	}
}
