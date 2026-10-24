package resourceserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/resourceserver"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// stubVerifier はトークン文字列をキーに固定の結果を返す。
type stubVerifier map[string]*resourceserver.Principal

func (s stubVerifier) Verify(_ context.Context, token string) (*resourceserver.Principal, error) {
	switch token {
	case "boom":
		return nil, errors.New("introspection endpoint unreachable")
	}
	if p, ok := s[token]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("%w: unknown token", resourceserver.ErrInvalidToken)
}

func newProtector(t *testing.T, v resourceserver.TokenVerifier) *resourceserver.Protector {
	t.Helper()
	p, err := resourceserver.New(resourceserver.Config{
		Resource:             "https://MCP.example.com/api/",
		Name:                 "Example MCP Server",
		AuthorizationServers: []string{"https://as.example.com"},
		Scopes:               []string{"files:read", "files:write"},
		Documentation:        "https://mcp.example.com/docs",
		Verifier:             v,
		Now:                  func() time.Time { return now },
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func echoPrincipal(w http.ResponseWriter, r *http.Request) {
	p, ok := resourceserver.FromContext(r.Context())
	if !ok {
		http.Error(w, "no principal", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(p)
}

func TestMetadata(t *testing.T) {
	p := newProtector(t, stubVerifier{})
	// RFC 9728 §3: path を持つ resource は well-known の後ろに path を付ける。末尾スラッシュは落とす
	if p.MetadataPath() != "/.well-known/oauth-protected-resource/api" || p.MetadataURL() != "https://mcp.example.com/.well-known/oauth-protected-resource/api" {
		t.Fatalf("metadata path %q url %q", p.MetadataPath(), p.MetadataURL())
	}
	if p.Resource() != "https://mcp.example.com/api/" {
		t.Fatalf("resource must be normalized (lowercase host, path kept): %q", p.Resource())
	}
	rec := httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p.MetadataPath(), nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || rec.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("metadata: %d %v", rec.Code, rec.Header())
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if m["resource"] != "https://mcp.example.com/api/" || m["resource_name"] != "Example MCP Server" || m["resource_documentation"] != "https://mcp.example.com/docs" {
		t.Fatalf("metadata body: %s", rec.Body)
	}
	if as := m["authorization_servers"].([]any); len(as) != 1 || as[0] != "https://as.example.com" {
		t.Fatalf("authorization_servers: %v", as)
	}
	if sc := m["scopes_supported"].([]any); len(sc) != 2 || sc[0] != "files:read" {
		t.Fatalf("scopes_supported: %v", sc)
	}
	if bm := m["bearer_methods_supported"].([]any); len(bm) != 1 || bm[0] != "header" {
		t.Fatalf("bearer_methods_supported: %v", bm)
	}
	rec = httptest.NewRecorder()
	p.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p.MetadataPath(), nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST metadata: %d", rec.Code)
	}

	// path なしの resource
	root, err := resourceserver.New(resourceserver.Config{Resource: "https://mcp.example.com", AuthorizationServers: []string{"https://as.example.com"}, Verifier: stubVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	if root.MetadataPath() != "/.well-known/oauth-protected-resource" {
		t.Fatalf("root metadata path: %q", root.MetadataPath())
	}
}

func TestRequire(t *testing.T) {
	good := &resourceserver.Principal{Subject: "alice", ClientID: "mcp-client", Scopes: []string{"files:read"},
		Audience: []string{"https://mcp.example.com/api/"}, ExpiresAt: now.Add(time.Hour)}
	p := newProtector(t, stubVerifier{
		"good":    good,
		"other":   {Subject: "alice", ClientID: "c", Scopes: []string{"files:read"}, Audience: []string{"https://other.example.com"}, ExpiresAt: now.Add(time.Hour)},
		"noaud":   {Subject: "alice", ClientID: "c", Scopes: []string{"files:read"}, ExpiresAt: now.Add(time.Hour)},
		"expired": {Subject: "alice", ClientID: "c", Scopes: []string{"files:read"}, Audience: []string{"https://mcp.example.com/api/"}, ExpiresAt: now.Add(-time.Second)},
		"caseaud": {Subject: "alice", ClientID: "c", Scopes: []string{"files:read", "files:write"}, Audience: []string{"https://x.example", "HTTPS://MCP.EXAMPLE.COM/api/"}},
	})
	read := p.Require("files:read")(http.HandlerFunc(echoPrincipal))
	write := p.Protect(http.HandlerFunc(echoPrincipal), "files:read", "files:write")
	any := p.Require()(http.HandlerFunc(echoPrincipal))

	call := func(h http.Handler, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	const meta = `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/api"`

	// トークンなし: 401、error なし、resource_metadata と必要 scope（RFC 9728 §5.1、RFC 6750 §3.1）
	rec := call(read, "")
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer `+meta+`, scope="files:read"` || rec.Body.Len() != 0 {
		t.Fatalf("no token: %d %q %s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("challenges must be no-store")
	}
	// scope を要求しないルートでは scope パラメータなし
	if rec := call(any, ""); rec.Header().Get("WWW-Authenticate") != `Bearer `+meta {
		t.Fatalf("no scope: %q", rec.Header().Get("WWW-Authenticate"))
	}
	// 壊れたヘッダ: 400 invalid_request
	if rec := call(read, "Basic abc"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_request"`) {
		t.Fatalf("malformed: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// 不明なトークン: 401 invalid_token
	rec = call(read, "Bearer nope")
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer `+meta+`, error="invalid_token", error_description="invalid token: unknown token", scope="files:read"` {
		t.Fatalf("invalid: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_token"`) {
		t.Fatalf("invalid body: %s", rec.Body)
	}
	// 他の resource 向け、aud なし: 401 invalid_token（MCP「Token Handling」）
	for _, tok := range []string{"other", "noaud"} {
		rec := call(read, "Bearer "+tok)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token", error_description="token is not intended for this resource"`) {
			t.Fatalf("%s: %d %q", tok, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
	// 期限切れ
	if rec := call(read, "Bearer expired"); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "expired") {
		t.Fatalf("expired: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// scope 不足: 403 insufficient_scope と必要 scope（MCP「Runtime Insufficient Scope Errors」）
	rec = call(write, "Bearer good")
	if rec.Code != http.StatusForbidden || rec.Header().Get("WWW-Authenticate") != `Bearer `+meta+`, error="insufficient_scope", error_description="the request requires higher privileges than provided by the access token", scope="files:read files:write"` {
		t.Fatalf("insufficient: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// 成功: Principal が context に載る
	rec = call(read, "Bearer good")
	if rec.Code != http.StatusOK {
		t.Fatalf("good: %d %s", rec.Code, rec.Body)
	}
	var got resourceserver.Principal
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Subject != "alice" || got.ClientID != "mcp-client" || !got.HasScope("files:read") || got.HasScope("files:write") {
		t.Fatalf("principal: %+v", got)
	}
	// aud は正規形で比較する（大文字のホスト、複数 aud）。exp 不明（ゼロ）は検証方式に委ねる
	if rec := call(write, "Bearer caseaud"); rec.Code != http.StatusOK {
		t.Fatalf("caseaud: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	// 検証方式の障害: 503、WWW-Authenticate なし
	rec = call(read, "Bearer boom")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("WWW-Authenticate") != "" || !strings.Contains(rec.Body.String(), "temporarily_unavailable") {
		t.Fatalf("verifier error: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	// Require を通らないハンドラには Principal がない
	if _, ok := resourceserver.FromContext(context.Background()); ok {
		t.Fatal("FromContext without Require must be false")
	}
}

func TestNewValidation(t *testing.T) {
	v := stubVerifier{}
	bad := []resourceserver.Config{
		{AuthorizationServers: []string{"https://as.example.com"}, Verifier: v},                                          // Resource なし
		{Resource: "mcp.example.com", AuthorizationServers: []string{"https://as.example.com"}, Verifier: v},             // 相対
		{Resource: "urn:example:mcp", AuthorizationServers: []string{"https://as.example.com"}, Verifier: v},             // http(s) 以外は well-known を組めない
		{Resource: "https://mcp.example.com?x=1", AuthorizationServers: []string{"https://as.example.com"}, Verifier: v}, // query
		{Resource: "https://mcp.example.com#f", AuthorizationServers: []string{"https://as.example.com"}, Verifier: v},   // fragment
		{Resource: "https://mcp.example.com", Verifier: v},                                                               // AS なし
		{Resource: "https://mcp.example.com", AuthorizationServers: []string{"as.example.com"}, Verifier: v},             // AS が相対
		{Resource: "https://mcp.example.com", AuthorizationServers: []string{"https://as.example.com"}},                  // Verifier なし
	}
	for i, cfg := range bad {
		if _, err := resourceserver.New(cfg); err == nil {
			t.Errorf("config %d must be rejected: %+v", i, cfg)
		}
	}
}
