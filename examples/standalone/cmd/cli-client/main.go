// Command cli-client は、Native / MCP Profile のクライアントとして Authorization Code + PKCE を実行する。
//
//	go run ./cmd/cli-client -issuer http://localhost:8080
//
// loopback でコールバックを待ち受け、認可 URL を表示する。ブラウザでその URL を開いて
// ログイン画面を承認すると、Code を交換して Access Token を表示する。
//
// MCP クライアントとして動かすには、CIMD 文書の URL を client_id にし（-client-id-url）、
// 対象の MCP サーバーを -mcp で与える。MCP 仕様「Authorization Server Location」のとおり、
// MCP サーバーの 401 応答と Protected Resource Metadata（RFC 9728）から認可サーバーと resource、
// 必要な scope を見つけ、resource 付き（RFC 8707）で認可を受けたあと Access Token で MCP サーバーを呼ぶ。
//
//	go run ./cmd/cli-client -client-id-url https://localhost:8444/demo-cli.json -mcp http://localhost:8090/mcp
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
)

func main() {
	var (
		issuer      = flag.String("issuer", "http://localhost:8080", "issuer URL (with -mcp: taken from the resource metadata unless set)")
		clientID    = flag.String("client-id", "demo-cli", "client_id (Native profile)")
		clientIDURL = flag.String("client-id-url", "", "URL of the Client ID Metadata Document to use as client_id (MCP profile; overrides -client-id)")
		scope       = flag.String("scope", "openid profile", "space separated scopes (with -mcp: taken from the 401 challenge or scopes_supported unless set)")
		mcp         = flag.String("mcp", "", "URL of an MCP server to discover the authorization server from and to call with the access token")
		timeout     = flag.Duration("timeout", 5*time.Minute, "how long to wait for the browser")
		resources   []string
	)
	flag.Func("resource", "resource indicator (RFC 8707; repeatable; with -mcp: defaults to the server's resource)", func(v string) error {
		resources = append(resources, v)
		return nil
	})
	flag.Parse()
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	o := options{issuer: *issuer, clientID: *clientID, scopes: strings.Fields(*scope), resources: resources, mcp: *mcp, timeout: *timeout,
		issuerSet: explicit["issuer"], scopeSet: explicit["scope"]}
	if *clientIDURL != "" {
		o.clientID = *clientIDURL
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type options struct {
	issuer, clientID, mcp string
	scopes, resources     []string
	timeout               time.Duration
	issuerSet, scopeSet   bool
}

func run(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	hc := &http.Client{Timeout: 10 * time.Second}

	if o.mcp != "" {
		d, err := oauthclient.DiscoverResource(ctx, hc, o.mcp)
		if err != nil {
			return err
		}
		fmt.Printf("resource metadata: resource=%s authorization_servers=%v scopes_supported=%v\n",
			d.Metadata.Resource, d.Metadata.AuthorizationServers, d.Metadata.ScopesSupported)
		if !o.issuerSet {
			o.issuer = d.Metadata.AuthorizationServers[0]
		}
		if len(o.resources) == 0 {
			o.resources = []string{d.Metadata.Resource}
		}
		if !o.scopeSet {
			// MCP「Scope Selection Strategy」: 401 の scope、なければ scopes_supported
			if d.Challenge.Scope != "" {
				o.scopes = strings.Fields(d.Challenge.Scope)
			} else {
				o.scopes = d.Metadata.ScopesSupported
			}
		}
	}

	md, err := oauthclient.Discover(ctx, hc, o.issuer)
	if err != nil {
		return err
	}
	ln, redirectURI, err := oauthclient.ListenLoopback()
	if err != nil {
		return err
	}
	flow, err := oauthclient.NewCodeFlow(md, o.clientID, redirectURI, o.scopes)
	if err != nil {
		return err
	}
	flow.Resources = o.resources
	fmt.Println("Open this URL in your browser:")
	fmt.Println()
	fmt.Println("  " + flow.AuthorizationURL())
	fmt.Println()

	q, err := oauthclient.WaitForCallback(ctx, ln)
	if err != nil {
		return err
	}
	code, err := flow.HandleCallback(q)
	if err != nil {
		return err
	}
	tok, err := flow.Exchange(ctx, code)
	if err != nil {
		return err
	}
	fmt.Printf("token_type:    %s\n", tok.TokenType)
	fmt.Printf("expires_in:    %d\n", tok.ExpiresIn)
	fmt.Printf("scope:         %s\n", tok.Scope)
	fmt.Printf("access_token:  %s\n", tok.AccessToken)
	if tok.RefreshToken != "" {
		fmt.Printf("refresh_token: %s\n", tok.RefreshToken)
	}
	if tok.IDToken != "" {
		fmt.Printf("id_token:      %s\n", tok.IDToken)
	}
	if strings.Contains(tok.Scope, "openid") && md.UserInfoEndpoint != "" {
		claims, err := flow.UserInfo(ctx, tok.AccessToken)
		if err != nil {
			return err
		}
		fmt.Printf("userinfo:      %v\n", claims)
	}
	if o.mcp != "" {
		res, err := oauthclient.CallResource(ctx, hc, http.MethodGet, o.mcp, tok.AccessToken)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		fmt.Printf("mcp:           %s %d\n", o.mcp, res.StatusCode)
		if h := res.Header.Get("WWW-Authenticate"); h != "" {
			fmt.Printf("               %s\n", h)
		}
		fmt.Printf("               %s\n", strings.TrimSpace(string(body)))
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("mcp server returned %d", res.StatusCode)
		}
	}
	return nil
}
