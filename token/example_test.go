package token_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

// exampleEngine は Machine クライアント svc を登録した Engine と、svc に client_credentials で
// 発行した Access Token を返す。
func exampleEngine(ctx context.Context) (*authengine.Engine, string) {
	now := time.Now()
	store := memory.New()
	svc, secret, err := client.NewMachine(client.MachineParams{ID: "svc", Name: "Service", Scopes: []string{"api.read"}}, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.CreateClient(ctx, svc); err != nil {
		log.Fatal(err)
	}
	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		log.Fatal(err)
	}
	engine, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: store, Keys: ks, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		log.Fatal(err)
	}
	res, err := engine.Token.Exchange(ctx, token.Request{
		GrantType:   "client_credentials",
		Credentials: token.Credentials{ClientID: "svc", Secret: string(secret), Method: client.AuthClientSecretBasic},
	})
	if err != nil {
		log.Fatal(err)
	}
	return engine, res.AccessToken
}

// ExampleService_Inspect は Go API でトークンの状態を調べる。Resource Server をエンジンと同じプロセスに
// 置くなら、HTTP の Introspection（RFC 7662）を経由せずにこれで検証できる。
// 不明・期限切れ・失効はすべて Active: false で返り、エラーにはならない。
func ExampleService_Inspect() {
	ctx := context.Background()
	engine, accessToken := exampleEngine(ctx)

	info, err := engine.Token.Inspect(ctx, accessToken, token.HintAccessToken)
	if err != nil {
		log.Fatal(err) // 内部障害だけがエラーになる
	}
	fmt.Println(info.Active, info.TokenType, info.ClientID, info.Scopes)

	info, err = engine.Token.Inspect(ctx, "at_unknown", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(info.Active)

	// Output:
	// true Bearer svc [api.read]
	// false
}

// ExampleService_RevokeToken は管理画面やサポート対応から、トークンを 1 本だけ失効させる。
// Refresh Token を渡すと、その Token Family（後継の Refresh Token と全 Access Token）がまとめて失効する。
// ユーザーと Client の連携そのものを解除するなら grant.Service.Revoke を使う。
func ExampleService_RevokeToken() {
	ctx := context.Background()
	engine, accessToken := exampleEngine(ctx)

	found, err := engine.Token.RevokeToken(ctx, accessToken, token.HintAccessToken)
	if err != nil {
		log.Fatal(err)
	}
	info, err := engine.Token.Inspect(ctx, accessToken, token.HintAccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("found:", found, "active:", info.Active)

	// Output:
	// found: true active: false
}

// ExampleJWTIssuer は、resource ごとに Access Token の形式を JWT（RFC 9068）にする。
// JWTIssuer は Engine が配線するので、利用者は Config.Resources の AccessTokenFormat を選ぶだけでよい。
// Resource Server は JWKS の鍵でローカルに検証できる。ただし失効は exp まで伝わらないので、
// JWT を選ぶ resource には AccessTokenTTL の短い Client を組み合わせる（ADR-0008 §3）。
func ExampleJWTIssuer() {
	ctx := context.Background()
	now := time.Now()
	store := memory.New()
	svc, secret, err := client.NewMachine(client.MachineParams{
		ID: "svc", Name: "Service", Scopes: []string{"files.read"}, AccessTokenTTL: 5 * time.Minute,
	}, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.CreateClient(ctx, svc); err != nil {
		log.Fatal(err)
	}
	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		log.Fatal(err)
	}
	engine, err := authengine.New(authengine.Config{
		Issuer: "https://as.example.com", Store: store, Keys: ks, Logger: slog.New(slog.DiscardHandler),
		Resources: []resource.Resource{{URI: "https://files.example.com", AccessTokenFormat: resource.FormatJWT}},
	})
	if err != nil {
		log.Fatal(err)
	}
	res, err := engine.Token.Exchange(ctx, token.Request{
		GrantType:   "client_credentials",
		Credentials: token.Credentials{ClientID: "svc", Secret: string(secret), Method: client.AuthClientSecretBasic},
		Resource:    []string{"https://files.example.com"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Resource Server 側の検証。実際には /jwks から得た公開鍵で行い、
	// typ・iss・aud・exp を確かめる（RFC 9068 §4）。
	var claims struct {
		Iss      string   `json:"iss"`
		Aud      []string `json:"aud"`
		ClientID string   `json:"client_id"`
		Scope    string   `json:"scope"`
	}
	h, err := engine.Keys.Verify(res.AccessToken, &claims)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(h.Type, h.Alg, claims.Iss, claims.Aud, claims.ClientID, claims.Scope, res.ExpiresIn)

	// Opaque と同じく Store に記録されるので、Introspection と失効も使える。
	info, err := engine.Token.Inspect(ctx, res.AccessToken, token.HintAccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(info.Active, info.Audience)

	// Output:
	// at+jwt RS256 https://as.example.com [https://files.example.com] svc files.read 300
	// true [https://files.example.com]
}
