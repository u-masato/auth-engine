package client

import (
	"errors"
	"slices"
	"testing"
)

func TestRotateSecretReplacesOnlyTheSecret(t *testing.T) {
	c, oldSecret, err := NewWeb(WebParams{ID: "web-1", Name: "web", RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes: []string{"openid", "profile"}, Resources: []string{"https://api.example.com"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	next, newSecret, err := c.RotateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if newSecret == "" || newSecret == oldSecret {
		t.Fatalf("a new secret must be generated: %q", newSecret)
	}
	if !next.VerifySecret(string(newSecret)) || next.VerifySecret(string(oldSecret)) {
		t.Fatal("only the new secret must verify against the rotated client")
	}
	// 元の値は変わらない（保存するまでは旧シークレットが有効）
	if !c.VerifySecret(string(oldSecret)) || c.VerifySecret(string(newSecret)) {
		t.Fatal("RotateSecret must not modify the receiver")
	}
	if next.ID != c.ID || next.Profile != c.Profile || next.Name != c.Name || !next.CreatedAt.Equal(c.CreatedAt) ||
		!slices.Equal(next.RedirectURIs, c.RedirectURIs) || !slices.Equal(next.Scopes, c.Scopes) || !slices.Equal(next.Resources, c.Resources) ||
		next.IDTokenAlg != c.IDTokenAlg || next.AccessTokenTTL != c.AccessTokenTTL {
		t.Fatalf("everything but the secret must be kept:\n got %+v\nwant %+v", next, c)
	}
	// スライスは共有しない
	next.RedirectURIs[0] = "https://evil.example.com/cb"
	if c.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatal("RotateSecret must not share slices with the receiver")
	}
}

func TestRotateSecretIsGeneratedEachTime(t *testing.T) {
	c, _, err := NewMachine(MachineParams{ID: "m-1", Name: "machine", Scopes: []string{"jobs:run"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, s1, err := c.RotateSecret()
	if err != nil {
		t.Fatal(err)
	}
	_, s2, err := c.RotateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 || len(s1) < MinSecretLength {
		t.Fatalf("secrets must be random and long enough: %q %q", s1, s2)
	}
}

func TestRotateSecretRejectsPublicClients(t *testing.T) {
	native, err := NewNative(NativeParams{ID: "n-1", Name: "native", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, secret, err := native.RotateSecret(); !errors.Is(err, ErrInvalid) || secret != "" {
		t.Fatalf("public client must be rejected: %q, %v", secret, err)
	}
}
