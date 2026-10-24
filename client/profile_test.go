package client

import (
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

// ADR-0004 §1 の表を、Client の問い合わせメソッド経由で検証する。
func TestProfileTable(t *testing.T) {
	web, _, err := NewWeb(WebParams{Name: "web", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	native, err := NewNative(NativeParams{Name: "cli", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	machine, _, err := NewMachine(MachineParams{Name: "svc", Scopes: []string{"api:read"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	mcp, err := NewMCP(MetadataDocument{ClientID: "https://mcp-client.example/oauth/client.json", ClientName: "MCP", RedirectURIs: []string{"http://localhost:3000/callback"}},
		"https://mcp-client.example/oauth/client.json", now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		c            *Client
		public       bool
		grants       []GrantType
		auth         []AuthMethod
		pkce         bool
		refresh      bool
		idToken      bool
		hasRedirects bool
		resource     bool
	}{
		{"web", web, false, []GrantType{GrantAuthorizationCode, GrantRefreshToken}, []AuthMethod{AuthClientSecretBasic, AuthClientSecretPost}, true, true, true, true, false},
		{"native", native, true, []GrantType{GrantAuthorizationCode, GrantRefreshToken}, []AuthMethod{AuthNone}, true, true, true, true, false},
		{"machine", machine, false, []GrantType{GrantClientCredentials}, []AuthMethod{AuthClientSecretBasic, AuthClientSecretPost}, false, false, false, false, false},
		{"mcp", mcp, true, []GrantType{GrantAuthorizationCode, GrantRefreshToken}, []AuthMethod{AuthNone}, true, true, true, true, true},
	}
	allGrants := []GrantType{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials}
	allAuth := []AuthMethod{AuthClientSecretBasic, AuthClientSecretPost, AuthNone}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.c.IsPublic() != tt.public {
				t.Errorf("IsPublic = %v, want %v", tt.c.IsPublic(), tt.public)
			}
			for _, g := range allGrants {
				if got, want := tt.c.Allows(g), slices.Contains(tt.grants, g); got != want {
					t.Errorf("Allows(%s) = %v, want %v", g, got, want)
				}
			}
			for _, a := range allAuth {
				if got, want := tt.c.AcceptsAuthMethod(a), slices.Contains(tt.auth, a); got != want {
					t.Errorf("AcceptsAuthMethod(%s) = %v, want %v", a, got, want)
				}
			}
			if tt.c.RequiresPKCE() != tt.pkce {
				t.Errorf("RequiresPKCE = %v, want %v", tt.c.RequiresPKCE(), tt.pkce)
			}
			if tt.c.IssuesRefreshToken() != tt.refresh {
				t.Errorf("IssuesRefreshToken = %v, want %v", tt.c.IssuesRefreshToken(), tt.refresh)
			}
			if tt.c.IssuesIDToken() != tt.idToken {
				t.Errorf("IssuesIDToken = %v, want %v", tt.c.IssuesIDToken(), tt.idToken)
			}
			if tt.c.RequiresResource() != tt.resource {
				t.Errorf("RequiresResource = %v, want %v", tt.c.RequiresResource(), tt.resource)
			}
			if (len(tt.c.RedirectURIs) > 0) != tt.hasRedirects {
				t.Errorf("redirect URIs present = %v, want %v", len(tt.c.RedirectURIs) > 0, tt.hasRedirects)
			}
			if (tt.c.SecretHash != "") != !tt.public {
				t.Errorf("secret presence = %v, want %v", tt.c.SecretHash != "", !tt.public)
			}
		})
	}
}

func TestProfileValid(t *testing.T) {
	for _, p := range []Profile{ProfileWeb, ProfileNative, ProfileMachine, ProfileMCP} {
		if !p.Valid() {
			t.Errorf("%q should be valid", p)
		}
	}
	if Profile("custom").Valid() {
		t.Error("unknown profile must be invalid")
	}
}
