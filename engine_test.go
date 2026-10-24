package authengine_test

import (
	"testing"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/storage/memory"
)

func TestNew(t *testing.T) {
	e, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: memory.New()})
	if err != nil {
		t.Fatal(err)
	}
	if e.Authorization == nil || e.Token == nil || e.Authorization.Issuer != "https://as.example.com" || e.Clock == nil {
		t.Fatalf("engine not wired: %+v", e)
	}
	if time.Since(e.Clock.Now()) > time.Minute {
		t.Fatal("default clock must be real time")
	}

	bad := []authengine.Config{
		{Issuer: "", Store: memory.New()},
		{Issuer: "as.example.com", Store: memory.New()},
		{Issuer: "http://as.example.com", Store: memory.New()},
		{Issuer: "https://as.example.com/path", Store: memory.New()},
		{Issuer: "https://as.example.com?x=1", Store: memory.New()},
		{Issuer: "https://as.example.com"},
		{Issuer: "https://as.example.com", Store: memory.New(), TransactionTTL: 2 * time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), CodeTTL: time.Hour},
	}
	for i, cfg := range bad {
		if _, err := authengine.New(cfg); err == nil {
			t.Errorf("config %d must be rejected: %+v", i, cfg)
		}
	}
	for _, iss := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "https://as.example.com/"} {
		if _, err := authengine.New(authengine.Config{Issuer: iss, Store: memory.New()}); err != nil {
			t.Errorf("%s must be accepted: %v", iss, err)
		}
	}
}
