package oauthclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	ch := ParseChallenge([]string{
		`Basic realm="x"`,
		`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", error="invalid_token", error_description="say \"hi\"", scope="mcp:read mcp:write"`,
	})
	if ch.ResourceMetadata != "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" || ch.Scope != "mcp:read mcp:write" || ch.Error != "invalid_token" {
		t.Fatalf("challenge: %+v", ch)
	}
	if ch := ParseChallenge([]string{`Bearer scope=mcp:read, resource_metadata=https://a/b`}); ch.Scope != "mcp:read" || ch.ResourceMetadata != "https://a/b" {
		t.Fatalf("token68 values: %+v", ch)
	}
}

func TestWellKnownResourceMetadata(t *testing.T) {
	tests := map[string]string{
		"https://mcp.example.com":      "https://mcp.example.com/.well-known/oauth-protected-resource",
		"https://mcp.example.com/mcp":  "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
		"https://mcp.example.com/mcp/": "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
	}
	for in, want := range tests {
		got, err := wellKnownResourceMetadata(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	if _, err := wellKnownResourceMetadata("urn:example:mcp"); err == nil {
		t.Error("urn must be rejected")
	}
}

func TestDiscoverResource(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srv.URL+`/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL + "/mcp", "authorization_servers": []string{"https://as.example.com"}, "scopes_supported": []string{"mcp:read", "mcp:write"}})
	})
	// WWW-Authenticate なしの Resource Server: well-known の既定パスから組む
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	mux.HandleFunc("/.well-known/oauth-protected-resource/plain", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL + "/other", "authorization_servers": []string{"https://as.example.com"}})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	d, err := DiscoverResource(context.Background(), srv.Client(), srv.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if d.Metadata.Resource != srv.URL+"/mcp" || d.Metadata.AuthorizationServers[0] != "https://as.example.com" || d.Challenge.Scope != "mcp:read" {
		t.Fatalf("discovery: %+v %+v", d.Metadata, d.Challenge)
	}
	// resource の不一致は拒否（RFC 9728 §3.3）
	if _, err := DiscoverResource(context.Background(), srv.Client(), srv.URL+"/plain"); err == nil {
		t.Fatal("resource mismatch must be rejected")
	}
	// 401 を返さない URL は Resource Server として扱わない
	if _, err := DiscoverResource(context.Background(), srv.Client(), srv.URL+"/.well-known/oauth-protected-resource/mcp"); err == nil {
		t.Fatal("non-401 must be rejected")
	}
}
