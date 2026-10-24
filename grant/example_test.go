package grant_test

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

// ExampleService_Revoke は「連携済みアプリ」画面の操作を示す。List で subject の Grant を一覧し、
// Revoke で 1 つの Client との連携を解除する。解除すると、その Grant から発行した
// 全 Token Family・全トークンが失効する。
//
// ここでは Grant を作るために client_credentials を使う（subject は Client 自身）。
// ユーザーの Grant は Authorization Code フローの Resume で作られ、subject は
// Interaction App が Complete で渡した値になる。
func ExampleService_Revoke() {
	ctx := context.Background()
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

	grants, err := engine.Grants.List(ctx, "svc")
	if err != nil {
		log.Fatal(err)
	}
	for _, g := range grants {
		fmt.Println(g.ClientID, g.Scopes, g.Status)
	}

	if err := engine.Grants.Revoke(ctx, "svc", "svc"); err != nil {
		log.Fatal(err)
	}
	info, err := engine.Token.Inspect(ctx, res.AccessToken, token.HintAccessToken)
	if err != nil {
		log.Fatal(err)
	}
	grants, err = engine.Grants.List(ctx, "svc")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token active:", info.Active, "grants:", len(grants))

	// Output:
	// svc [api.read] active
	// token active: false grants: 0
}
