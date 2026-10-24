package client

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewWebGeneratesIDAndSecret(t *testing.T) {
	c, secret, err := NewWeb(WebParams{Name: "web", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid", "profile"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == "" || len(c.ID) != 43 {
		t.Errorf("generated id = %q", c.ID)
	}
	if secret == "" {
		t.Fatal("secret must be returned once")
	}
	if strings.Contains(c.SecretHash, string(secret)) {
		t.Fatal("plaintext secret must not be stored")
	}
	if !c.VerifySecret(string(secret)) {
		t.Error("VerifySecret must accept the generated secret")
	}
	if c.VerifySecret(string(secret)+"x") || c.VerifySecret("") {
		t.Error("VerifySecret must reject wrong or empty secrets")
	}
	if c.IDTokenAlg != AlgRS256 {
		t.Errorf("default alg = %q, want RS256", c.IDTokenAlg)
	}
	if c.EffectiveAccessTokenTTL() != DefaultAccessTokenTTL {
		t.Errorf("default ttl = %s", c.EffectiveAccessTokenTTL())
	}
	if !c.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v", c.CreatedAt)
	}
}

func TestNewNativeHasNoSecret(t *testing.T) {
	c, err := NewNative(NativeParams{ID: "cli-1", Name: "cli", RedirectURIs: []string{"http://127.0.0.1/cb", "com.example.app:/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "cli-1" {
		t.Errorf("explicit id not kept: %q", c.ID)
	}
	if c.SecretHash != "" || c.VerifySecret("anything") {
		t.Error("public client must not have a secret")
	}
}

func TestNewMachine(t *testing.T) {
	c, secret, err := NewMachine(MachineParams{Name: "svc", Scopes: []string{"api:read"}, AccessTokenTTL: 5 * time.Minute}, now)
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || !c.VerifySecret(string(secret)) {
		t.Error("machine client must have a verifiable secret")
	}
	if c.IDTokenAlg != "" {
		t.Errorf("machine must not set id token alg, got %q", c.IDTokenAlg)
	}
	if c.EffectiveAccessTokenTTL() != 5*time.Minute {
		t.Errorf("ttl = %s", c.EffectiveAccessTokenTTL())
	}
}

func TestValidationErrors(t *testing.T) {
	validRedirect := []string{"https://app.example.com/cb"}
	tests := []struct {
		name string
		make func() error
	}{
		{"web: no name", func() error {
			_, _, err := NewWeb(WebParams{RedirectURIs: validRedirect, Scopes: []string{"openid"}}, now)
			return err
		}},
		{"web: no scopes", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect}, now)
			return err
		}},
		{"web: no redirect", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"}}, now)
			return err
		}},
		{"web: bad alg", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}, IDTokenAlg: "HS256"}, now)
			return err
		}},
		{"web: ttl too short", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}, AccessTokenTTL: time.Second}, now)
			return err
		}},
		{"web: ttl too long", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}, AccessTokenTTL: 48 * time.Hour}, now)
			return err
		}},
		{"web: id with space", func() error {
			_, _, err := NewWeb(WebParams{ID: "my client", Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}}, now)
			return err
		}},
		{"web: id too long", func() error {
			_, _, err := NewWeb(WebParams{ID: strings.Repeat("a", 256), Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}}, now)
			return err
		}},
		{"machine: redirect given", func() error {
			c, _, err := NewMachine(MachineParams{Name: "m", Scopes: []string{"a"}}, now)
			if err != nil {
				return err
			}
			c.RedirectURIs = validRedirect
			return c.Validate()
		}},
		{"machine: alg given", func() error {
			c, _, err := NewMachine(MachineParams{Name: "m", Scopes: []string{"a"}}, now)
			if err != nil {
				return err
			}
			c.IDTokenAlg = AlgRS256
			return c.Validate()
		}},
		{"restored: unknown profile", func() error {
			return (&Client{ID: "x", Profile: "custom", Name: "n", Scopes: []string{"a"}}).Validate()
		}},
		{"restored: public with secret", func() error {
			c, err := NewNative(NativeParams{Name: "n", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"a"}}, now)
			if err != nil {
				return err
			}
			c.SecretHash = "abc"
			return c.Validate()
		}},
		{"restored: confidential without secret", func() error {
			c, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}}, now)
			if err != nil {
				return err
			}
			c.SecretHash = ""
			return c.Validate()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.make()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}
