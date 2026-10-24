package authengine_test

import (
	"fmt"
	"log"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/cimd"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/storage/memory"
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

// ExampleNew_cimd は MCP クライアントを事前登録なしに受け入れる構成を示す。Config.CIMD を与えると、
// https の URL 形式の client_id を CIMD（Client ID Metadata Document）として取得・検証する Resolver が
// Store の後ろに配線され、Discovery に client_id_metadata_document_supported: true が載る（ADR-0008 §5）。
func ExampleNew_cimd() {
	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		log.Fatal(err)
	}

	engine, err := authengine.New(authengine.Config{
		Issuer: "https://as.example.com",
		Store:  memory.New(),
		Keys:   ks,
		// MCP クライアントは resource を必ず送るので、受け手の MCP サーバーを列挙しておく
		Resources: []resource.Resource{{URI: "https://mcp.example.com", Name: "Example MCP Server"}},
		CIMD: &cimd.Config{
			// 既定は全ドメインを信頼する。許可リストで絞るなら TrustPolicy を与える（CIMD §8.9）
			TrustPolicy: cimd.HostAllowlist{"*.example", "mcp-client.example"},
			// AllowLoopback は開発用。本番では false のまま（CIMD §8.6）
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("cimd enabled:", engine.CIMD != nil)

	// Output:
	// cimd enabled: true
}
