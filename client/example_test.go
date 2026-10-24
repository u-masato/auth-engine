package client_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/storage/memory"
)

// describe は Profile が固定する性質を 1 行にまとめる（ADR-0004）。
func describe(c *client.Client) string {
	return fmt.Sprintf("profile=%s public=%t pkce=%t authorization_code=%t refresh_token=%t client_credentials=%t",
		c.Profile, c.IsPublic(), c.RequiresPKCE(),
		c.Allows(client.GrantAuthorizationCode), c.IssuesRefreshToken(), c.Allows(client.GrantClientCredentials))
}

// ExampleNewWeb はサーバー側で秘密を保持できる Web アプリを登録する。
// シークレットはここで 1 度だけ平文で返り、Store には SHA-256 ハッシュだけが残る。
// 呼び出し側で Client に渡し、ログには残さないこと。
func ExampleNewWeb() {
	c, secret, err := client.NewWeb(client.WebParams{
		ID:           "web-app",
		Name:         "Example Web App",
		RedirectURIs: []string{"https://app.example.com/callback"}, // 完全一致で照合する
		Scopes:       []string{"openid", "profile", "email"},
	}, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	store := memory.New() // 本番では adapters/sqlite か adapters/postgres
	if err := store.CreateClient(context.Background(), c); err != nil {
		log.Fatal(err)
	}
	fmt.Println(describe(c))
	fmt.Println("secret issued:", len(secret) > 0, "stored as hash:", c.SecretHash != "" && c.SecretHash != string(secret))

	// Output:
	// profile=web public=false pkce=true authorization_code=true refresh_token=true client_credentials=false
	// secret issued: true stored as hash: true
}

// ExampleNewNative は CLI やモバイルアプリのような、秘密を持てない public クライアントを登録する。
// loopback の redirect URI はポートを問わず照合する（RFC 8252 §7.3）。
func ExampleNewNative() {
	c, err := client.NewNative(client.NativeParams{
		ID:           "cli",
		Name:         "Example CLI",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
		Scopes:       []string{"openid", "offline_access"},
	}, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(describe(c))

	// Output:
	// profile=native public=true pkce=true authorization_code=true refresh_token=true client_credentials=false
}

// ExampleNewMachine はユーザーを介さないサービス間通信（client_credentials）のクライアントを登録する。
// Introspection を呼ぶ Resource Server もこの Profile で登録する（ADR-0006 §1）。
func ExampleNewMachine() {
	c, secret, err := client.NewMachine(client.MachineParams{
		ID:     "billing-batch",
		Name:   "Billing Batch",
		Scopes: []string{"invoices.read"},
	}, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(describe(c))
	fmt.Println("secret issued:", len(secret) > 0)

	// Output:
	// profile=machine public=false pkce=false authorization_code=false refresh_token=false client_credentials=true
	// secret issued: true
}
