package client

import (
	"errors"
	"slices"
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
		{"web: relative resource", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}, Resources: []string{"api.example.com"}}, now)
			return err
		}},
		{"web: resource with fragment", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}, Resources: []string{"https://api.example.com#x"}}, now)
			return err
		}},
		{"web: duplicate resource after normalization", func() error {
			_, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: validRedirect, Scopes: []string{"openid"}, Resources: []string{"https://api.example.com", "https://API.example.com"}}, now)
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

func TestResources(t *testing.T) {
	// 空なら全 resource を許可する
	open, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(open.Resources) != 0 || !open.AllowsResource("https://anything.example.com") {
		t.Fatalf("unrestricted client must allow any resource: %+v", open.Resources)
	}

	// 指定があれば正規形で保持し、照合も正規化して行う
	in := []string{"https://API.example.com", "urn:example:billing"}
	limited, _, err := NewMachine(MachineParams{Name: "m", Scopes: []string{"api"}, Resources: in}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(limited.Resources, []string{"https://api.example.com", "urn:example:billing"}) {
		t.Fatalf("resources must be normalized: %v", limited.Resources)
	}
	if in[0] != "https://API.example.com" {
		t.Fatal("constructor must not modify the caller's slice")
	}
	tests := map[string]bool{
		"https://api.example.com":  true,
		"HTTPS://api.EXAMPLE.com":  true,
		"urn:example:billing":      true,
		"https://api.example.com/": false, // 末尾スラッシュは別の resource
		"https://mcp.example.com":  false,
		"api.example.com":          false,
		"":                         false,
	}
	for uri, want := range tests {
		if got := limited.AllowsResource(uri); got != want {
			t.Errorf("AllowsResource(%q) = %v, want %v", uri, got, want)
		}
	}
	// Adapter から復元した値も Validate で検証される
	limited.Resources = []string{"https://api.example.com", "https://api.example.com"}
	if err := limited.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate resources must fail validation: %v", err)
	}
}

func TestPresentedSecret(t *testing.T) {
	const presented = "conformance-client-secret-0123456789abcdef"
	c, secret, err := NewWeb(WebParams{Name: "web", Secret: presented, RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != presented || !c.VerifySecret(presented) {
		t.Fatal("presented secret must be used as is")
	}
	// 短すぎるシークレットは拒否
	if _, _, err := NewWeb(WebParams{Name: "web", Secret: "short", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"}}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short secret: %v", err)
	}
	if _, _, err := NewMachine(MachineParams{Name: "svc", Secret: presented, Scopes: []string{"api"}}, now); err != nil {
		t.Fatalf("machine with presented secret: %v", err)
	}
}
