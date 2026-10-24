package token_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/storage/memory"
	"github.com/muno/auth-engine/token"
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
