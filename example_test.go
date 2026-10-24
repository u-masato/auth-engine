package authengine_test

import (
	"fmt"
	"log"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/resource"
	"github.com/muno/auth-engine/storage/memory"
)

// ExampleNew は Engine を組み立てる最小の構成を示す。必須は Issuer・Store・Keys（RS256 の署名鍵を含む）の 3 つで、
// TTL などは 0 のままなら既定値になる。HTTP への公開は httpapi.New に Engine を渡して行う。
func ExampleNew() {
	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, time.Now()) // OIDC Core §15.1: RS256 は必須
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		log.Fatal(err)
	}

	engine, err := authengine.New(authengine.Config{
		Issuer: "https://as.example.com",
		Store:  memory.New(), // テスト用。本番では adapters/sqlite か adapters/postgres を使う
		Keys:   ks,
		// resource パラメータ（RFC 8707）で指定できる Resource Server。空なら resource 付きの要求はすべて invalid_target。
		Resources: []resource.Resource{{URI: "https://API.example.com/v1", Scopes: []string{"read", "write"}}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(engine.Issuer)
	fmt.Println(engine.Resources.URIs())

	// Output:
	// https://as.example.com
	// [https://api.example.com/v1]
}
