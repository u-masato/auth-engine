package authorization

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/storage"
)

type fakeResolver map[string]*client.Client

func (f fakeResolver) GetClient(_ context.Context, id string) (*client.Client, error) {
	if c, ok := f[id]; ok {
		return c, nil
	}
	return nil, storage.ErrNotFound
}

var testNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func testClients(t testing.TB) fakeResolver {
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
	// limited は resource の許可範囲を api.example.com に絞った Web Client
	limited, _, err := client.NewWeb(client.WebParams{ID: "limited", Name: "Limited",
		RedirectURIs: []string{"https://app.example.com/cb?env=prod"},
		Scopes:       []string{"openid", "profile"}, Resources: []string{"https://api.example.com"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	// files は files.example.com 向けの scope を持つ Web Client（resource ごとの scope 上限の検証用）
	files, _, err := client.NewWeb(client.WebParams{ID: "files", Name: "Files",
		RedirectURIs: []string{"https://app.example.com/cb?env=prod"},
		Scopes:       []string{"openid", "files:read", "files:write"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return fakeResolver{"web": web, "cli": native, "svc": m2m, "limited": limited, "files": files}
}

// testResources は Opaque 2 件と JWT 1 件の Resource Server 設定。
func testResources(t testing.TB) *resource.Set {
	t.Helper()
	set, err := resource.NewSet([]resource.Resource{
		{URI: "https://api.example.com"},
		{URI: "https://mcp.example.com", Name: "MCP"},
		{URI: "https://jwt.example.com", AccessTokenFormat: resource.FormatJWT},
		{URI: "https://files.example.com", Scopes: []string{"files:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func parse(t *testing.T, clients fakeResolver, p url.Values) (*Request, *Error) {
	t.Helper()
	return parseRequest(context.Background(), clients, testResources(t), p)
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
	p.Add("resource", "https://API.example.com")
	p.Add("resource", "https://mcp.example.com")
	p.Add("resource", "https://api.example.com") // 正規形で重複
	p.Add("resource", "")                        // 値なしは省略扱い（RFC 6749 §3.1）
	req, perr := parse(t, testClients(t), p)
	if perr != nil {
		t.Fatal(perr)
	}
	if req.ClientID != "web" || req.RedirectURI != "https://app.example.com/cb?env=prod" || !req.RedirectURIExplicit {
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
		t.Fatalf("resource must be normalized and deduplicated: %+v", req.Resource)
	}
}

func TestParseRequestWithoutResource(t *testing.T) {
	// resource なしの要求は従来どおり受理し、Resource は空（ADR-0008 §2）。設定が空でも同じ。
	for _, set := range []*resource.Set{testResources(t), nil} {
		req, perr := parseRequest(context.Background(), testClients(t), set, baseParams())
		if perr != nil || len(req.Resource) != 0 {
			t.Fatalf("resource-less request: %+v %v", req, perr)
		}
	}
}

func TestParseRequestResourceErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(url.Values)
		set  *resource.Set
		desc string
	}{
		{"unknown", func(v url.Values) { v.Set("resource", "https://other.example.com") }, nil, "unknown resource"},
		{"trailing slash differs", func(v url.Values) { v.Set("resource", "https://api.example.com/") }, nil, "unknown resource"},
		{"relative", func(v url.Values) { v.Set("resource", "api.example.com") }, nil, "invalid resource indicator"},
		{"fragment", func(v url.Values) { v.Set("resource", "https://api.example.com#x") }, nil, "invalid resource indicator"},
		{"mixed formats", func(v url.Values) {
			v.Add("resource", "https://api.example.com")
			v.Add("resource", "https://jwt.example.com")
		}, nil, "different access token formats"},
		{"client restriction", func(v url.Values) { v.Set("client_id", "limited"); v.Set("resource", "https://mcp.example.com") }, nil, "not allowed for this client"},
		{"one allowed one not", func(v url.Values) {
			v.Set("client_id", "limited")
			v.Add("resource", "https://api.example.com")
			v.Add("resource", "https://mcp.example.com")
		}, nil, "not allowed for this client"},
		{"no resources configured", func(v url.Values) { v.Set("resource", "https://api.example.com") }, &resource.Set{}, "unknown resource"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := baseParams()
			tt.mod(p)
			set := tt.set
			if set == nil {
				set = testResources(t)
			}
			_, perr := parseRequest(context.Background(), testClients(t), set, p)
			if perr == nil {
				t.Fatal("want error")
			}
			if perr.Code != CodeInvalidTarget || !strings.Contains(perr.Description, tt.desc) {
				t.Fatalf("got %s (%s), want invalid_target with %q", perr.Code, perr.Description, tt.desc)
			}
			// Client と redirect_uri は確定しているので、リダイレクトして返す（ADR-0008 §1）
			if !perr.Redirectable() || perr.State != "xyz" {
				t.Fatalf("invalid_target must be redirectable with state: %+v", perr)
			}
		})
	}
	// 許可範囲内なら limited でも通る。JWT の resource だけなら形式は揃っている
	p := baseParams()
	p.Set("client_id", "limited")
	p.Set("resource", "https://api.example.com")
	if _, perr := parse(t, testClients(t), p); perr != nil {
		t.Fatalf("allowed resource: %v", perr)
	}
	p = baseParams()
	p.Set("resource", "https://jwt.example.com")
	if _, perr := parse(t, testClients(t), p); perr != nil {
		t.Fatalf("single jwt resource: %v", perr)
	}
}

func TestParseRequestResourceScopeLimit(t *testing.T) {
	// files.example.com は files:read だけを許す。openid は OIDC の標準 scope なので制限を受けない
	p := baseParams()
	p.Set("client_id", "files")
	p.Set("resource", "https://files.example.com")
	p.Set("scope", "openid files:read")
	if _, perr := parse(t, testClients(t), p); perr != nil {
		t.Fatalf("allowed scope: %v", perr)
	}
	p.Set("scope", "openid files:write")
	_, perr := parse(t, testClients(t), p)
	if perr == nil || perr.Code != CodeInvalidScope || !strings.Contains(perr.Description, "files:write") || !perr.Redirectable() {
		t.Fatalf("scope outside the resource limit must be a redirectable invalid_scope: %+v", perr)
	}
	// resource なしなら resource の scope 上限は関係ない
	p.Del("resource")
	if _, perr := parse(t, testClients(t), p); perr != nil {
		t.Fatalf("without resource: %v", perr)
	}
	// 上限のない resource と組み合わせれば、どちらかが許すので通る
	p.Add("resource", "https://files.example.com")
	p.Add("resource", "https://api.example.com")
	if _, perr := parse(t, testClients(t), p); perr != nil {
		t.Fatalf("another resource without limit allows the scope: %v", perr)
	}
}

func TestParseRequestDefaultRedirectAndDedupScopes(t *testing.T) {
	p := baseParams()
	p.Set("client_id", "cli")
	p.Del("redirect_uri")
	p.Set("scope", "openid  openid")
	// OIDC（openid あり）では redirect_uri を省略できない。リダイレクト先が確定しないのでエラーページ
	_, perr := parse(t, testClients(t), p)
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
	req, perr := parse(t, clients, p)
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
			_, perr := parse(t, testClients(t), p)
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
			_, perr := parse(t, testClients(t), p)
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
	_, perr := parse(t, testClients(t), p)
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
	_, perr := parse(t, testClients(t), p)
	if perr == nil || perr.Code != CodeInvalidScope {
		t.Fatalf("want invalid_scope, got %+v", perr)
	}
	// loopback のポート違いは許される
	p.Set("scope", "openid")
	req, perr := parse(t, testClients(t), p)
	if perr != nil || req.RedirectURI != "http://127.0.0.1:9999/cb" {
		t.Fatalf("loopback port: %+v %v", req, perr)
	}
}
