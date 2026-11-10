package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"slices"
	"testing"

	"github.com/u-masato/auth-engine/client"
)

// FuzzParseRequest は任意の /authorize クエリについて、次の不変条件を確かめる。
//
//   - Client へリダイレクトするエラーと成功の redirect_uri は、Client の登録情報と照合済みのものに限る
//     （RFC 6749 §4.1.2.1、RFC 9700 §4.1.3）。照合前のエラーをリダイレクトするとオープンリダイレクトになる。
//   - 成功した要求は S256 の PKCE を持ち、scope は構文どおりで Client の許可範囲内、resource は
//     設定済みで Client に許されたもの（RFC 7636、RFC 6749 §3.3、RFC 8707 §2、ADR-0008 §1）。
func FuzzParseRequest(f *testing.F) {
	clients := testClients(f)
	resources := testResources(f)

	f.Add(baseParams().Encode())
	for _, mod := range []func(url.Values){
		func(p url.Values) { p.Set("client_id", "cli"); p.Set("redirect_uri", "http://127.0.0.1:51004/cb") },
		func(p url.Values) { p.Set("redirect_uri", "https://evil.example/cb"); p.Del("code_challenge") },
		func(p url.Values) { p.Del("redirect_uri"); p.Set("scope", "profile") },
		func(p url.Values) {
			p.Add("resource", "https://API.example.com")
			p.Add("resource", "https://jwt.example.com")
		},
		func(p url.Values) { p.Set("client_id", "limited"); p.Add("resource", "https://mcp.example.com") },
		func(p url.Values) {
			p.Set("client_id", "files")
			p.Set("scope", "files:write")
			p.Add("resource", "https://files.example.com")
		},
		func(p url.Values) { p.Set("code_challenge_method", "plain") },
		func(p url.Values) { p.Set("prompt", "none login"); p.Set("max_age", "-1") },
		func(p url.Values) { p.Add("state", "again") },
		func(p url.Values) { p.Set("client_id", "svc") },
	} {
		p := baseParams()
		mod(p)
		f.Add(p.Encode())
	}

	f.Fuzz(func(t *testing.T, query string) {
		// 解析に失敗した組も、取り出せた分は渡す（net/http の Request.URL.Query と同じ振る舞い）
		values, _ := url.ParseQuery(query)
		req, perr := parseRequest(context.Background(), clients, resources, values)

		var c *client.Client
		if ids := values["client_id"]; len(ids) == 1 {
			c = clients[ids[0]]
		}
		// 照合済みの redirect_uri。照合できない要求では空。
		var resolved string
		if c != nil && len(values["redirect_uri"]) <= 1 {
			resolved, _ = c.ResolveRedirectURI(values.Get("redirect_uri"))
		}

		if perr != nil {
			if req != nil {
				t.Fatalf("both request and error returned: %+v / %v", req, perr)
			}
			if perr.Redirectable() && (resolved == "" || perr.RedirectURI != resolved) {
				t.Fatalf("error redirects to %q, but the verified redirect_uri is %q (query %q)", perr.RedirectURI, resolved, query)
			}
			return
		}
		if c == nil || req.ClientID != c.ID || resolved == "" || req.RedirectURI != resolved {
			t.Fatalf("accepted request has an unverified client or redirect_uri: %+v (query %q)", req, query)
		}
		if req.CodeChallengeMethod != CodeChallengeMethodS256 || !ValidCodeChallenge(req.CodeChallenge) {
			t.Fatalf("accepted request without a valid S256 challenge: %+v", req)
		}
		if len(req.Scopes) == 0 || len(c.DisallowedScopes(req.Scopes)) > 0 {
			t.Fatalf("accepted scopes %q are outside the client's %q", req.Scopes, c.Scopes)
		}
		for i, s := range req.Scopes {
			if !client.ValidScopeToken(s) || slices.Contains(req.Scopes[:i], s) {
				t.Fatalf("accepted scopes are malformed or duplicated: %q", req.Scopes)
			}
		}
		for _, uri := range req.Resource {
			if r, ok := resources.Lookup(uri); !ok || r.URI != uri || !c.AllowsResource(uri) {
				t.Fatalf("accepted resource %q is not configured or not allowed for %s", uri, c.ID)
			}
		}
		if len(resources.DisallowedScopes(req.Resource, req.Scopes)) > 0 {
			t.Fatalf("accepted scopes %q exceed the limits of resources %q", req.Scopes, req.Resource)
		}
	})
}

// FuzzVerifyS256 は、VerifyS256 が真になるのは構文どおりの code_verifier と、その
// BASE64URL(SHA256(code_verifier)) の組だけであることを確かめる（RFC 7636 §4.1、§4.6）。
func FuzzVerifyS256(f *testing.F) {
	f.Add(rfcChallenge, rfcVerifier)
	f.Add(rfcChallenge, rfcVerifier+"x")
	f.Add(rfcVerifier, rfcVerifier) // plain 相当の取り違え
	f.Add("", "")
	f.Fuzz(func(t *testing.T, challenge, verifier string) {
		sum := sha256.Sum256([]byte(verifier))
		want := ValidCodeVerifier(verifier) && challenge == base64.RawURLEncoding.EncodeToString(sum[:])
		if got := VerifyS256(challenge, verifier); got != want {
			t.Fatalf("VerifyS256(%q, %q) = %v, want %v", challenge, verifier, got, want)
		}
	})
}

// FuzzParseScopes は、parseScopes が返す scope が空でなく、構文どおりで、重複がなく、
// 元の文字列に現れた順であることを確かめる（RFC 6749 §3.3）。
func FuzzParseScopes(f *testing.F) {
	for _, seed := range []string{"openid profile", "openid  profile ", "openid openid", `bad"token`, "a\tb", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		scopes, bad := parseScopes(raw)
		if bad != "" {
			if scopes != nil || client.ValidScopeToken(bad) {
				t.Fatalf("parseScopes(%q) reported %q as malformed with %q", raw, bad, scopes)
			}
			return
		}
		for i, s := range scopes {
			if !client.ValidScopeToken(s) || slices.Contains(scopes[:i], s) {
				t.Fatalf("parseScopes(%q) = %q", raw, scopes)
			}
		}
	})
}
