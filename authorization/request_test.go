package authorization

import (
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/storage"
)

type fakeResolver map[string]*client.Client

func (f fakeResolver) GetClient(_ context.Context, id string) (*client.Client, error) {
	if c, ok := f[id]; ok {
		return c, nil
	}
	return nil, storage.ErrNotFound
}

var testNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func testClients(t *testing.T) fakeResolver {
	t.Helper()
	web, _, err := client.NewWeb(client.WebParams{ID: "web", Name: "Web",
		RedirectURIs: []string{"https://app.example.com/cb?env=prod", "https://app.example.com/cb2"},
		Scopes:       []string{"openid", "profile", "email"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	native, err := client.NewNative(client.NativeParams{ID: "cli", Name: "CLI",
		RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	m2m, _, err := client.NewMachine(client.MachineParams{ID: "svc", Name: "Svc", Scopes: []string{"api"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return fakeResolver{"web": web, "cli": native, "svc": m2m}
}

func baseParams() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"web"},
		"redirect_uri":          {"https://app.example.com/cb?env=prod"},
		"scope":                 {"openid profile"},
		"state":                 {"xyz"},
		"code_challenge":        {rfcChallenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {"n-0S6_WzA2Mj"},
	}
}

func TestParseRequestSuccess(t *testing.T) {
	p := baseParams()
	p.Set("prompt", "login consent")
	p.Set("max_age", "300")
	p.Set("login_hint", "alice@example.com")
	p.Add("resource", "https://api.example.com")
	p.Add("resource", "https://mcp.example.com")
	req, c, perr := parseRequest(context.Background(), testClients(t), p)
	if perr != nil {
		t.Fatal(perr)
	}
	if c.ID != "web" || req.ClientID != "web" || req.RedirectURI != "https://app.example.com/cb?env=prod" || !req.RedirectURIExplicit {
		t.Fatalf("client/redirect: %+v", req)
	}
	if !slices.Equal(req.Scopes, []string{"openid", "profile"}) || req.State != "xyz" || req.Nonce != "n-0S6_WzA2Mj" {
		t.Fatalf("scope/state/nonce: %+v", req)
	}
	if req.CodeChallenge != rfcChallenge || req.CodeChallengeMethod != "S256" {
		t.Fatalf("pkce: %+v", req)
	}
	if !slices.Equal(req.Prompt, []string{"login", "consent"}) || !req.HasMaxAge || req.MaxAge != 300*time.Second || req.LoginHint != "alice@example.com" {
		t.Fatalf("hints: %+v", req)
	}
	if !slices.Equal(req.Resource, []string{"https://api.example.com", "https://mcp.example.com"}) {
		t.Fatalf("resource: %+v", req.Resource)
	}
}

func TestParseRequestDefaultRedirectAndDedupScopes(t *testing.T) {
	p := baseParams()
	p.Set("client_id", "cli")
	p.Del("redirect_uri")
	p.Set("scope", "openid  openid")
	// OIDC（openid あり）では redirect_uri を省略できない。リダイレクト先が確定しないのでエラーページ
	_, _, perr := parseRequest(context.Background(), testClients(t), p)
	if perr == nil || perr.Code != CodeInvalidRequest || perr.Redirectable() {
		t.Fatalf("openid without redirect_uri must be a non-redirectable invalid_request: %v", perr)
	}
	// OAuth 2.0 だけの要求なら、登録 URI が 1 つの public クライアントは省略できる（RFC 6749 §3.1.2.3）
	plain, err := client.NewNative(client.NativeParams{ID: "plain", Name: "Plain", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"read", "openid"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	clients := testClients(t)
	clients["plain"] = plain
	p.Set("client_id", "plain")
	p.Set("scope", "read  read")
	req, _, perr := parseRequest(context.Background(), clients, p)
	if perr != nil {
		t.Fatal(perr)
	}
	if req.RedirectURI != "http://127.0.0.1/cb" || req.RedirectURIExplicit {
		t.Fatalf("default redirect: %+v", req)
	}
	if !slices.Equal(req.Scopes, []string{"read"}) {
		t.Fatalf("scopes must be deduplicated: %v", req.Scopes)
	}
}

func TestParseRequestNonRedirectableErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(url.Values)
	}{
		{"missing client_id", func(v url.Values) { v.Del("client_id") }},
		{"duplicate client_id", func(v url.Values) { v.Add("client_id", "web") }},
		{"unknown client", func(v url.Values) { v.Set("client_id", "nope") }},
		{"unregistered redirect", func(v url.Values) { v.Set("redirect_uri", "https://evil.example.com/cb") }},
		{"duplicate redirect", func(v url.Values) { v.Add("redirect_uri", "https://app.example.com/cb2") }},
		{"missing redirect with 2 registered", func(v url.Values) { v.Del("redirect_uri") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := baseParams()
			tt.mod(p)
			_, _, perr := parseRequest(context.Background(), testClients(t), p)
			if perr == nil {
				t.Fatal("want error")
			}
			if perr.Redirectable() || perr.RedirectURL("https://as.example.com") != "" {
				t.Fatalf("must not be redirectable: %+v", perr)
			}
			if perr.Code != CodeInvalidRequest {
				t.Fatalf("code = %s", perr.Code)
			}
		})
	}
}

func TestParseRequestRedirectableErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(url.Values)
		code string
	}{
		{"missing response_type", func(v url.Values) { v.Del("response_type") }, CodeInvalidRequest},
		{"implicit", func(v url.Values) { v.Set("response_type", "token") }, CodeUnsupportedResponseType},
		{"hybrid", func(v url.Values) { v.Set("response_type", "code id_token") }, CodeUnsupportedResponseType},
		{"duplicate scope param", func(v url.Values) { v.Add("scope", "openid") }, CodeInvalidRequest},
		{"request object", func(v url.Values) { v.Set("request", "eyJ...") }, CodeRequestNotSupported},
		{"request_uri", func(v url.Values) { v.Set("request_uri", "https://x") }, CodeRequestURINotSupported},
		{"fragment response_mode", func(v url.Values) { v.Set("response_mode", "fragment") }, CodeInvalidRequest},
		{"missing scope", func(v url.Values) { v.Del("scope") }, CodeInvalidScope},
		{"malformed scope", func(v url.Values) { v.Set("scope", "openid bad\"scope") }, CodeInvalidScope},
		{"scope not allowed", func(v url.Values) { v.Set("scope", "openid admin") }, CodeInvalidScope},
		{"missing code_challenge", func(v url.Values) { v.Del("code_challenge") }, CodeInvalidRequest},
		{"plain method", func(v url.Values) { v.Set("code_challenge_method", "plain") }, CodeInvalidRequest},
		{"missing method", func(v url.Values) { v.Del("code_challenge_method") }, CodeInvalidRequest},
		{"short challenge", func(v url.Values) { v.Set("code_challenge", "short") }, CodeInvalidRequest},
		{"unknown prompt", func(v url.Values) { v.Set("prompt", "banana") }, CodeInvalidRequest},
		{"prompt none with login", func(v url.Values) { v.Set("prompt", "none login") }, CodeInvalidRequest},
		{"negative max_age", func(v url.Values) { v.Set("max_age", "-1") }, CodeInvalidRequest},
		{"non-numeric max_age", func(v url.Values) { v.Set("max_age", "soon") }, CodeInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := baseParams()
			tt.mod(p)
			_, _, perr := parseRequest(context.Background(), testClients(t), p)
			if perr == nil {
				t.Fatal("want error")
			}
			if perr.Code != tt.code {
				t.Fatalf("code = %s (%s), want %s", perr.Code, perr.Description, tt.code)
			}
			if !perr.Redirectable() || perr.State != "xyz" {
				t.Fatalf("must be redirectable with state: %+v", perr)
			}
			u, err := url.Parse(perr.RedirectURL("https://as.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if q.Get("error") != tt.code || q.Get("state") != "xyz" || q.Get("iss") != "https://as.example.com" || q.Get("env") != "prod" {
				t.Fatalf("redirect URL must carry error, state, iss and keep the original query: %s", u)
			}
			if u.Fragment != "" {
				t.Fatalf("no fragment: %s", u)
			}
		})
	}
}

func TestParseRequestMachineClientCannotAuthorize(t *testing.T) {
	// Machine Profile は redirect URI を持たないので redirect_uri 検証で止まる（リダイレクト不可）。
	p := baseParams()
	p.Set("client_id", "svc")
	p.Set("scope", "api")
	_, _, perr := parseRequest(context.Background(), testClients(t), p)
	if perr == nil || perr.Redirectable() {
		t.Fatalf("machine client must fail without redirect: %+v", perr)
	}
}

func TestParseRequestOpenIDRequiresIDTokenProfile(t *testing.T) {
	// Native は ID Token を発行できるので openid 可。否定ケースは Profile 上存在しないため、
	// scope の許可範囲外として弾かれることを確認する。
	p := baseParams()
	p.Set("client_id", "cli")
	p.Set("redirect_uri", "http://127.0.0.1:9999/cb")
	p.Set("scope", "openid profile")
	_, _, perr := parseRequest(context.Background(), testClients(t), p)
	if perr == nil || perr.Code != CodeInvalidScope {
		t.Fatalf("want invalid_scope, got %+v", perr)
	}
	// loopback のポート違いは許される
	p.Set("scope", "openid")
	req, _, perr := parseRequest(context.Background(), testClients(t), p)
	if perr != nil || req.RedirectURI != "http://127.0.0.1:9999/cb" {
		t.Fatalf("loopback port: %+v %v", req, perr)
	}
}
