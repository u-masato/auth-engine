package client_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage/memory"
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

// ExampleNewMCP は CIMD（Client ID Metadata Document）から MCP クライアントを組み立てる。
// 通常は cimd.Resolver が文書を取得してこの関数を呼ぶので、組み込む側が直接呼ぶのは
// 文書を事前に Store に登録しておきたいとき（CIMD §7）に限られる。
func ExampleNewMCP() {
	const documentURL = "https://mcp-client.example/oauth/client.json"
	c, err := client.NewMCP(client.MetadataDocument{
		ClientID:     documentURL, // 取得した URL と単純文字列比較で一致すること
		ClientName:   "Example MCP Client",
		ClientURI:    "https://mcp-client.example",
		RedirectURIs: []string{"http://localhost:3000/callback"}, // MCP では http://localhost を許す
		Scope:        "files:read",
	}, documentURL, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(describe(c))
	fmt.Println("requires resource:", c.RequiresResource())

	// Output:
	// profile=mcp public=true pkce=true authorization_code=true refresh_token=true client_credentials=false
	// requires resource: true
}

// ExampleClient_Update は登録済みの Client の redirect URI を差し替える。
// 変えられるのは開放項目（ADR-0004 §2）だけで、ID・Profile・シークレットはそのまま残る。
func ExampleClient_Update() {
	ctx := context.Background()
	store := memory.New()
	c, _, err := client.NewWeb(client.WebParams{
		ID:           "web-app",
		Name:         "Example Web App",
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
	}, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := store.CreateClient(ctx, c); err != nil {
		log.Fatal(err)
	}

	cur, err := store.GetClient(ctx, "web-app")
	if err != nil {
		log.Fatal(err)
	}
	p := cur.UpdateParams() // 現在値から変えたい項目だけを書き換える
	p.RedirectURIs = []string{"https://app.example.com/oauth/callback"}
	next, err := cur.Update(p) // Profile の規則で検証する
	if err != nil {
		log.Fatal(err)
	}
	if err := store.UpdateClient(ctx, next); err != nil {
		log.Fatal(err)
	}

	got, err := store.GetClient(ctx, "web-app")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(got.Profile, got.RedirectURIs, got.SecretHash == c.SecretHash)

	// Output:
	// web [https://app.example.com/oauth/callback] true
}
