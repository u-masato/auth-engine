// Command cli-client は、Native / CLI Profile のクライアントとして Authorization Code + PKCE を実行する。
//
//	go run ./cmd/cli-client -issuer http://localhost:8080
//
// loopback でコールバックを待ち受け、認可 URL を表示する。ブラウザでその URL を開いて
// ログイン画面を承認すると、Code を交換して Access Token を表示する。
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/muno/auth-engine/examples/standalone/oauthclient"
)

func main() {
	var (
		issuer   = flag.String("issuer", "http://localhost:8080", "issuer URL")
		clientID = flag.String("client-id", "demo-cli", "client_id (Native profile)")
		scope    = flag.String("scope", "openid profile", "space separated scopes")
		timeout  = flag.Duration("timeout", 5*time.Minute, "how long to wait for the browser")
	)
	flag.Parse()

	if err := run(*issuer, *clientID, strings.Fields(*scope), *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(issuer, clientID string, scopes []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	md, err := oauthclient.Discover(ctx, &http.Client{Timeout: 10 * time.Second}, issuer)
	if err != nil {
		return err
	}
	ln, redirectURI, err := oauthclient.ListenLoopback()
	if err != nil {
		return err
	}
	flow, err := oauthclient.NewCodeFlow(md, clientID, redirectURI, scopes)
	if err != nil {
		return err
	}
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
	return nil
}
