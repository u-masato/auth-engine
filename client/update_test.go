package client

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestUpdateReplacesOpenFieldsOnly(t *testing.T) {
	c, secret, err := NewWeb(WebParams{ID: "web-1", Name: "web", RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes: []string{"openid", "profile"}, IDTokenAlg: AlgES256}, now)
	if err != nil {
		t.Fatal(err)
	}
	p := c.UpdateParams()
	p.Name = "renamed"
	p.RedirectURIs = []string{"https://app.example.com/cb2"}
	p.Resources = []string{"HTTPS://API.example.com"}
	p.IDTokenAlg = "" // 空なら既定値に戻る
	next, err := c.Update(p)
	if err != nil {
		t.Fatal(err)
	}

	if next.ID != c.ID || next.Profile != c.Profile || !next.CreatedAt.Equal(c.CreatedAt) || !next.VerifySecret(string(secret)) {
		t.Fatalf("immutable fields must be kept: %+v", next)
	}
	if next.Name != "renamed" || !slices.Equal(next.RedirectURIs, []string{"https://app.example.com/cb2"}) {
		t.Fatalf("open fields must be replaced: %+v", next)
	}
	if !slices.Equal(next.Resources, []string{"https://api.example.com"}) {
		t.Errorf("resources must be normalized like the constructor: %v", next.Resources)
	}
	if next.IDTokenAlg != AlgRS256 {
		t.Errorf("empty alg must default to RS256, got %q", next.IDTokenAlg)
	}
	// 元の値は変わらない
	if c.Name != "web" || c.IDTokenAlg != AlgES256 || !slices.Equal(c.RedirectURIs, []string{"https://app.example.com/cb"}) {
		t.Fatalf("Update must not modify the receiver: %+v", c)
	}
}

func TestUpdateParamsIsACopy(t *testing.T) {
	c, err := NewNative(NativeParams{ID: "cli", Name: "cli", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	p := c.UpdateParams()
	p.RedirectURIs[0] = "http://127.0.0.1/other"
	if c.RedirectURIs[0] != "http://127.0.0.1/cb" {
		t.Fatal("UpdateParams must not share slices with the client")
	}
}

func TestUpdateValidatesAgainstProfile(t *testing.T) {
	web, _, err := NewWeb(WebParams{Name: "web", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	machine, _, err := NewMachine(MachineParams{Name: "svc", Scopes: []string{"api:read"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		c      *Client
		modify func(*UpdateParams)
	}{
		{"web http redirect", web, func(p *UpdateParams) { p.RedirectURIs = []string{"http://app.example.com/cb"} }},
		{"web no scopes", web, func(p *UpdateParams) { p.Scopes = nil }},
		{"empty name", web, func(p *UpdateParams) { p.Name = "" }},
		{"ttl too long", web, func(p *UpdateParams) { p.AccessTokenTTL = 48 * time.Hour }},
		{"machine redirect", machine, func(p *UpdateParams) { p.RedirectURIs = []string{"https://app.example.com/cb"} }},
		{"machine id token alg", machine, func(p *UpdateParams) { p.IDTokenAlg = AlgRS256 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.c.UpdateParams()
			tt.modify(&p)
			if _, err := tt.c.Update(p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}
