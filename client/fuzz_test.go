package client

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// FuzzResolveRedirectURI は、照合に通った redirect_uri が登録 URI のどれかと完全一致するか、
// Native / MCP の http loopback でポート番号だけが違うものであることを確かめる
// （RFC 9700 §4.1.3、RFC 8252 §7.3）。照合の抜けはオープンリダイレクトと Code の漏洩に直結する。
func FuzzResolveRedirectURI(f *testing.F) {
	web, _, err := NewWeb(WebParams{Name: "w", Scopes: []string{"openid"},
		RedirectURIs: []string{"https://app.example.com/cb?env=prod", "https://app.example.com/cb2"}}, now)
	if err != nil {
		f.Fatal(err)
	}
	native, err := NewNative(NativeParams{Name: "n", Scopes: []string{"openid"},
		RedirectURIs: []string{"http://127.0.0.1/cb", "http://[::1]:8080/cb?x=1", "com.example.app:/cb"}}, now)
	if err != nil {
		f.Fatal(err)
	}
	mcp, err := NewMCP(MetadataDocument{ClientID: "https://client.example.com/cimd.json", ClientName: "m",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://127.0.0.1/callback", "https://client.example.com/cb"}},
		"https://client.example.com/cimd.json", now)
	if err != nil {
		f.Fatal(err)
	}
	clients := []*Client{web, native, mcp}
	for _, c := range clients {
		for _, u := range c.RedirectURIs {
			f.Add(u)
		}
	}
	for _, seed := range []string{
		"", "https://app.example.com/cb?env=prod#x", "https://APP.example.com/cb?env=prod",
		"http://127.0.0.1:51004/cb", "http://127.0.0.1:51004/cb?x", "http://[::1]/cb?x=1", "http://127.0.0.2/cb",
		"http://localhost:3001/callback", "http://user@127.0.0.1:1/cb", "HTTP://127.0.0.1:1/cb",
		"http://127.0.0.1:1/cb#", "http://127.0.0.1:1/%63b", "http://[::1%25eth0]:1/cb",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, requested string) {
		for _, c := range clients {
			got, err := c.ResolveRedirectURI(requested)
			if err != nil {
				continue
			}
			if requested == "" {
				// RFC 6749 §3.1.2.3: 省略できるのは登録 URI が 1 つのときだけ
				if len(c.RedirectURIs) != 1 || got != c.RedirectURIs[0] {
					t.Fatalf("%s: omitted redirect_uri resolved to %q with %d registered", c.Profile, got, len(c.RedirectURIs))
				}
				continue
			}
			if got != requested {
				t.Fatalf("%s: %q resolved to a different URI %q", c.Profile, requested, got)
			}
			if slices.Contains(c.RedirectURIs, got) {
				continue
			}
			// 完全一致でないのは、ポート番号だけが違う http loopback に限る
			if !c.Profile.rules().redirect.ignoresLoopbackPort() {
				t.Fatalf("%s: unregistered redirect_uri %q was accepted", c.Profile, got)
			}
			u, err := url.Parse(got)
			if err != nil || u.Scheme != "http" || !isLoopbackIP(u.Hostname()) || u.User != nil || strings.Contains(got, "#") {
				t.Fatalf("%s: non-exact match %q is not a plain http loopback URI", c.Profile, got)
			}
			if !slices.ContainsFunc(c.RedirectURIs, func(r string) bool {
				ru, err := url.Parse(r)
				return err == nil && ru.Scheme == "http" && ru.Hostname() == u.Hostname() &&
					ru.Path == u.Path && ru.RawQuery == u.RawQuery
			}) {
				t.Fatalf("%s: %q differs from every registered URI in more than the port", c.Profile, got)
			}
		}
	})
}

// FuzzParseClientIDURL は、CIMD の Client Identifier URL として受理した値が CIMD §3 の条件
// （https、host あり、userinfo なし、path あり、fragment なし、"." / ".." セグメントなし）を満たすことを確かめる。
// dot セグメントは、パーセントエンコードした形（%2e%2e）も復号後に同じものとして扱う（RFC 3986 §2.3、§6.2.2.2）。
func FuzzParseClientIDURL(f *testing.F) {
	for _, seed := range []string{
		"https://client.example.com/cimd.json", "https://client.example.com/", "https://client.example.com",
		"http://client.example.com/cimd.json", "https://user@client.example.com/cimd.json",
		"https://client.example.com/a/../cimd.json", "https://client.example.com/a/%2e%2e/cimd.json",
		"https://client.example.com/./cimd.json", "https://client.example.com/cimd.json#",
		"https://client.example.com/cimd.json?v=1", "https://[::1]:8443/cimd.json", "https:///cimd.json",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		u, err := ParseClientIDURL(id)
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path == "" || strings.Contains(id, "#") {
			t.Fatalf("accepted %q violates CIMD §3: %#v", id, u)
		}
		for seg := range strings.SplitSeq(u.Path, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("accepted %q has a dot segment after decoding (path %q)", id, u.Path)
			}
		}
	})
}

// FuzzNewMCP は、任意の CIMD 文書から組み立てた Client が MCP Profile の固定値を守ることを確かめる
// （ADR-0004、ADR-0008 §4、§5）。文書は認可サーバーと関係のない第三者が書くので、すべての値を信用しない。
func FuzzNewMCP(f *testing.F) {
	const id = "https://client.example.com/cimd.json"
	for _, seed := range []string{
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["http://localhost:3000/cb"]}`,
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["https://client.example.com/cb"],"scope":"files:read  openid",` +
			`"client_uri":"https://client.example.com","logo_uri":"https://client.example.com/logo.png","policy_uri":"https://client.example.com/policy"}`,
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["http://localhost/cb"],"policy_uri":"javascript:alert(1)"}`,
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["http://localhost/cb"],"logo_uri":"data:image/svg+xml,<svg/>"}`,
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["http://localhost/cb"],"client_secret":"s"}`,
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["http://evil.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		`{"client_id":"` + id + `","client_name":"m","redirect_uris":["http://localhost/cb"],"grant_types":["client_credentials"]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var doc MetadataDocument
		if json.Unmarshal(data, &doc) != nil {
			return
		}
		c, err := NewMCP(doc, id, now)
		if err != nil {
			return
		}
		if c.ID != id || c.Profile != ProfileMCP || !c.IsPublic() || c.SecretHash != "" || !c.RequiresPKCE() {
			t.Fatalf("client does not follow the MCP profile: %+v", c)
		}
		for _, r := range c.RedirectURIs {
			u, err := url.Parse(r)
			if err != nil || !validMCPRedirect(u) || strings.Contains(r, "#") {
				t.Fatalf("accepted redirect URI %q is not allowed for MCP clients", r)
			}
		}
		for _, s := range c.Scopes {
			if !ValidScopeToken(s) {
				t.Fatalf("accepted scope token %q is malformed", s)
			}
		}
		// Interaction App が同意画面にリンクや画像として出す値。http(s) の絶対 URL 以外は危険なスキーム
		// （javascript: / data: など）を同意画面に持ち込む。
		for name, v := range map[string]string{"client_uri": c.ClientURI, "logo_uri": c.LogoURI, "policy_uri": c.PolicyURI} {
			if v == "" {
				continue
			}
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				t.Fatalf("accepted %s %q is not an absolute http(s) URL", name, v)
			}
		}
	})
}
