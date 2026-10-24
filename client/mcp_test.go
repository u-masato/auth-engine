package client

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

const docURL = "https://mcp-client.example/oauth/client.json"

func validDoc() MetadataDocument {
	return MetadataDocument{
		ClientID:     docURL,
		ClientName:   "Example MCP Client",
		ClientURI:    "https://mcp-client.example",
		LogoURI:      "https://mcp-client.example/logo.png",
		RedirectURIs: []string{"http://localhost:3000/callback", "https://mcp-client.example/callback"},
		Scope:        "files:read files:write",
	}
}

func TestParseClientIDURL(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"https://mcp-client.example/oauth/client.json", true},
		{"https://mcp-client.example:8443/client", true}, // ポートは任意（CIMD §3）
		{"https://mcp-client.example/", true},            // ルートパスは NOT RECOMMENDED だが受理
		{"https://mcp-client.example/client?v=1", true},  // query は SHOULD NOT だが受理
		{"https://mcp-client.example", false},            // path なし
		{"http://mcp-client.example/client", false},      // https のみ
		{"https://user@mcp-client.example/client", false},
		{"https://user:pw@mcp-client.example/client", false},
		{"https://mcp-client.example/client#frag", false},
		{"https://mcp-client.example/client#", false},
		{"https://mcp-client.example/a/./client", false},
		{"https://mcp-client.example/a/../client", false},
		{"https:///client", false}, // host なし
		{"web-app", false},         // Store の client_id
		{"", false},
		{"HTTPS://mcp-client.example/client", false}, // 文書の client_id と単純比較するので小文字のみ
	}
	for _, tt := range tests {
		u, err := ParseClientIDURL(tt.id)
		if (err == nil) != tt.ok {
			t.Errorf("%q: ok=%v, err=%v", tt.id, tt.ok, err)
		}
		if err != nil && !errors.Is(err, ErrNotMetadataURL) {
			t.Errorf("%q: want ErrNotMetadataURL, got %v", tt.id, err)
		}
		if err == nil && u.String() != tt.id {
			t.Errorf("%q: parsed back to %q", tt.id, u)
		}
	}
}

func TestNewMCP(t *testing.T) {
	c, err := NewMCP(validDoc(), docURL, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != docURL || c.Profile != ProfileMCP || c.Name != "Example MCP Client" || c.ClientURI != "https://mcp-client.example" ||
		c.LogoURI != "https://mcp-client.example/logo.png" || !slices.Equal(c.Scopes, []string{"files:read", "files:write"}) ||
		c.SecretHash != "" || c.IDTokenAlg != AlgRS256 || !c.CreatedAt.Equal(now) || len(c.RedirectURIs) != 2 {
		t.Fatalf("unexpected client: %+v", c)
	}
	if !c.IsPublic() || !c.RequiresResource() || !c.AcceptsAuthMethod(AuthNone) || c.AcceptsAuthMethod(AuthClientSecretBasic) {
		t.Fatalf("mcp profile rules not applied: %+v", c)
	}
	if dis := c.DisallowedScopes([]string{"files:read", "openid"}); !slices.Equal(dis, []string{"openid"}) {
		t.Errorf("scope from the document must bound requests: %v", dis)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("restored client must validate: %v", err)
	}
}

// 文書に scope がなければ Client は scope の上限を持たない（resource ごとの上限だけが効く）。
func TestNewMCPWithoutScope(t *testing.T) {
	doc := validDoc()
	doc.Scope = ""
	c, err := NewMCP(doc, docURL, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Scopes) != 0 {
		t.Fatalf("scopes = %v", c.Scopes)
	}
	if dis := c.DisallowedScopes([]string{"openid", "files:read"}); dis != nil {
		t.Errorf("client without scope must not restrict: %v", dis)
	}
	// 他の Profile では空の Scopes は不正のまま
	if _, _, err := NewWeb(WebParams{Name: "w", RedirectURIs: []string{"https://app.example.com/cb"}}, now); !errors.Is(err, ErrInvalid) {
		t.Errorf("web without scopes must be rejected: %v", err)
	}
}

func TestNewMCPRejects(t *testing.T) {
	tests := []struct {
		name string
		mod  func(d *MetadataDocument)
		url  string
	}{
		{"client_id mismatch (document url)", func(d *MetadataDocument) {}, "https://mcp-client.example/other.json"},
		{"client_id mismatch (case)", func(d *MetadataDocument) { d.ClientID = "https://MCP-client.example/oauth/client.json" }, docURL},
		{"client_id not https", func(d *MetadataDocument) { d.ClientID = "http://mcp-client.example/oauth/client.json" }, "http://mcp-client.example/oauth/client.json"},
		{"client_id without path", func(d *MetadataDocument) { d.ClientID = "https://mcp-client.example" }, "https://mcp-client.example"},
		{"client_id with fragment", func(d *MetadataDocument) { d.ClientID = docURL + "#x" }, docURL + "#x"},
		{"client_id with dot segment", func(d *MetadataDocument) { d.ClientID = "https://mcp-client.example/../client.json" }, "https://mcp-client.example/../client.json"},
		{"missing client_name", func(d *MetadataDocument) { d.ClientName = "" }, docURL},
		{"missing redirect_uris", func(d *MetadataDocument) { d.RedirectURIs = nil }, docURL},
		{"duplicate redirect_uris", func(d *MetadataDocument) { d.RedirectURIs = []string{"https://a.example/cb", "https://a.example/cb"} }, docURL},
		{"redirect http non-localhost", func(d *MetadataDocument) { d.RedirectURIs = []string{"http://mcp-client.example/cb"} }, docURL},
		{"redirect custom scheme", func(d *MetadataDocument) { d.RedirectURIs = []string{"com.example.app:/cb"} }, docURL},
		{"redirect with fragment", func(d *MetadataDocument) { d.RedirectURIs = []string{"https://a.example/cb#x"} }, docURL},
		{"redirect javascript", func(d *MetadataDocument) { d.RedirectURIs = []string{"javascript:alert(1)"} }, docURL},
		{"client_secret_basic", func(d *MetadataDocument) { d.TokenEndpointAuthMethod = "client_secret_basic" }, docURL},
		{"client_secret_post", func(d *MetadataDocument) { d.TokenEndpointAuthMethod = "client_secret_post" }, docURL},
		{"private_key_jwt (M4)", func(d *MetadataDocument) { d.TokenEndpointAuthMethod = "private_key_jwt" }, docURL},
		{"client_secret present", func(d *MetadataDocument) { d.ClientSecret = "s3cret" }, docURL},
		{"client_secret_expires_at present", func(d *MetadataDocument) { d.ClientSecretExpiresAt = json.RawMessage("0") }, docURL},
		{"grant_types with client_credentials", func(d *MetadataDocument) { d.GrantTypes = []string{"authorization_code", "client_credentials"} }, docURL},
		{"grant_types implicit", func(d *MetadataDocument) { d.GrantTypes = []string{"implicit"} }, docURL},
		{"response_types token", func(d *MetadataDocument) { d.ResponseTypes = []string{"code", "token"} }, docURL},
		{"malformed scope token", func(d *MetadataDocument) { d.Scope = `files:read "quoted"` }, docURL},
		{"client_uri relative", func(d *MetadataDocument) { d.ClientURI = "mcp-client.example" }, docURL},
		{"client_id too long", func(d *MetadataDocument) {
			d.ClientID = "https://mcp-client.example/" + strings.Repeat("a", 240)
		}, "https://mcp-client.example/" + strings.Repeat("a", 240)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDoc()
			tt.mod(&doc)
			_, err := NewMCP(doc, tt.url, now)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("want ErrInvalid, got %v", err)
			}
		})
	}
}

// Profile の固定値と矛盾しない grant_types / response_types / token_endpoint_auth_method は受理し、Profile は変わらない。
func TestNewMCPAcceptsConsistentMetadata(t *testing.T) {
	doc := validDoc()
	doc.GrantTypes = []string{"authorization_code"} // refresh_token を書かなくても Profile は Refresh Token を発行する
	doc.ResponseTypes = []string{"code"}
	doc.TokenEndpointAuthMethod = "none"
	c, err := NewMCP(doc, docURL, now)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IssuesRefreshToken() || !c.Allows(GrantRefreshToken) {
		t.Error("profile must stay fixed regardless of grant_types")
	}
}

func TestMCPRedirectRegistration(t *testing.T) {
	tests := []struct {
		uri string
		ok  bool
	}{
		{"https://mcp-client.example/callback", true},
		{"http://localhost:3000/callback", true}, // MCP 仕様が localhost を明示的に許す（Native と異なる）
		{"http://localhost/callback", true},
		{"http://LOCALHOST:3000/callback", true},
		{"http://127.0.0.1:3000/callback", true},
		{"http://[::1]:3000/callback", true},
		{"http://mcp-client.example/callback", false},
		{"http://192.168.1.10/callback", false},
		{"https://mcp-client.example/callback#x", false},
		{"com.example.app:/callback", false},
		{"callback", false},
	}
	for _, tt := range tests {
		doc := validDoc()
		doc.RedirectURIs = []string{tt.uri}
		_, err := NewMCP(doc, docURL, now)
		if (err == nil) != tt.ok {
			t.Errorf("mcp %q: ok=%v, err=%v", tt.uri, tt.ok, err)
		}
	}
}

func TestResolveRedirectURIMCP(t *testing.T) {
	doc := validDoc()
	doc.RedirectURIs = []string{"http://localhost:3000/callback", "http://127.0.0.1/callback", "https://mcp-client.example/callback"}
	c, err := NewMCP(doc, docURL, now)
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{
		"http://localhost:3000/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:51004/callback", // loopback IP はポートを無視（RFC 8252 §7.3）
		"https://mcp-client.example/callback",
	}
	for _, u := range ok {
		if got, err := c.ResolveRedirectURI(u); err != nil || got != u {
			t.Errorf("%q: got %q, %v", u, got, err)
		}
	}
	bad := []string{
		"http://localhost:3001/callback", // localhost は完全一致（ポートを含む）
		"http://localhost/callback",
		"http://[::1]/callback", // 登録と異なる loopback アドレス
		"https://mcp-client.example/callback/",
		"http://127.0.0.1/other",
		"",
	}
	for _, u := range bad {
		if _, err := c.ResolveRedirectURI(u); err == nil {
			t.Errorf("%q: must not match", u)
		}
	}
}
