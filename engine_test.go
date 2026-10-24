package authengine_test

import (
	"testing"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/cimd"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

func testKeys(t *testing.T, algs ...string) *keys.Set {
	t.Helper()
	set := keys.NewSet()
	for _, alg := range algs {
		k, err := keys.Generate(alg, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := set.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

func TestNew(t *testing.T) {
	ks := testKeys(t, keys.AlgRS256)
	e, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks})
	if err != nil {
		t.Fatal(err)
	}
	if e.Authorization == nil || e.Token == nil || e.Authorization.Issuer != "https://as.example.com" || e.Clock == nil || e.IDTokens == nil ||
		e.Token.IDTokens == nil || e.Token.Grants == nil || e.Grants == nil || e.Token.RefreshTokenTTL != 30*24*time.Hour || e.Token.RefreshTokenIdleTTL != 14*24*time.Hour {
		t.Fatalf("engine not wired: %+v", e)
	}
	if time.Since(e.Clock.Now()) > time.Minute {
		t.Fatal("default clock must be real time")
	}
	if e.Resources == nil || e.Resources.Len() != 0 || e.Authorization.Resources != e.Resources {
		t.Fatalf("resources must default to an empty set wired into authorization: %+v", e.Resources)
	}
	withRes, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks,
		Resources: []resource.Resource{{URI: "https://MCP.example.com", AccessTokenFormat: resource.FormatJWT}}})
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := withRes.Authorization.Resources.Lookup("https://mcp.example.com"); !ok || r.EffectiveFormat() != resource.FormatJWT {
		t.Fatalf("resources not wired: %+v %v", r, ok)
	}
	if issuers, ok := withRes.Token.Issuer.(token.ByFormat); !ok || issuers[resource.FormatOpaque] == nil || issuers[resource.FormatJWT] == nil {
		t.Fatalf("token issuers not wired: %#v", withRes.Token.Issuer)
	}
	// CIMD なし: Clients は Store そのもの。あり: Store → CIMD の ChainResolver（ADR-0008 §5）
	if e.CIMD != nil || e.Clients == nil || e.Authorization.Clients != e.Clients || e.Token.Clients != e.Clients {
		t.Fatalf("clients not wired without CIMD: %+v", e)
	}
	if _, isChain := e.Clients.(client.ChainResolver); isChain {
		t.Fatal("without CIMD the store itself must be the resolver")
	}
	withCIMD, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, CIMD: &cimd.Config{}})
	if err != nil {
		t.Fatal(err)
	}
	// ChainResolver はスライスなので == で比べられない。各 Service が同じ構成の Chain を持つことを確かめる
	isWiredChain := func(r client.Resolver) bool {
		chain, ok := r.(client.ChainResolver)
		return ok && len(chain) == 2 && chain[1] == withCIMD.CIMD
	}
	if withCIMD.CIMD == nil || !isWiredChain(withCIMD.Clients) || !isWiredChain(withCIMD.Authorization.Clients) || !isWiredChain(withCIMD.Token.Clients) {
		t.Fatalf("cimd not wired: %+v", withCIMD)
	}

	bad := []authengine.Config{
		{Issuer: "", Store: memory.New(), Keys: ks},
		{Issuer: "as.example.com", Store: memory.New(), Keys: ks},
		{Issuer: "http://as.example.com", Store: memory.New(), Keys: ks},
		{Issuer: "https://as.example.com/path", Store: memory.New(), Keys: ks},
		{Issuer: "https://as.example.com?x=1", Store: memory.New(), Keys: ks},
		{Issuer: "https://as.example.com", Keys: ks},
		{Issuer: "https://as.example.com", Store: memory.New()},                                   // Keys なし
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: testKeys(t, keys.AlgES256)}, // RS256 なし
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, TransactionTTL: 2 * time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, CodeTTL: time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, IDTokenTTL: 48 * time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, RefreshTokenTTL: -time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, RefreshTokenTTL: 24 * time.Hour}, // 既定のスライド期限 14 日を下回る
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, RefreshTokenTTL: 48 * time.Hour, RefreshTokenIdleTTL: 72 * time.Hour},
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, Resources: []resource.Resource{{URI: "mcp.example.com"}}},                                       // 相対 URI
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, Resources: []resource.Resource{{URI: "https://a.example.com"}, {URI: "https://A.example.com"}}}, // 重複
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, Resources: []resource.Resource{{URI: "https://a.example.com", AccessTokenFormat: "paseto"}}},
		// JWT の署名アルゴリズムに対応する署名鍵がない（Keys は RS256 のみ）
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, Resources: []resource.Resource{{URI: "https://a.example.com", AccessTokenFormat: resource.FormatJWT, AccessTokenAlg: resource.AlgES256}}},
		// CIMD の設定が不正
		{Issuer: "https://as.example.com", Store: memory.New(), Keys: ks, CIMD: &cimd.Config{MinCacheTTL: time.Hour, MaxCacheTTL: time.Minute}},
	}
	for i, cfg := range bad {
		if _, err := authengine.New(cfg); err == nil {
			t.Errorf("config %d must be rejected: %+v", i, cfg)
		}
	}
	for _, iss := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "https://as.example.com/"} {
		if _, err := authengine.New(authengine.Config{Issuer: iss, Store: memory.New(), Keys: ks}); err != nil {
			t.Errorf("%s must be accepted: %v", iss, err)
		}
	}
	// AllowInsecureIssuer は localhost 以外の http を許す（警告付き）。https 以外のスキームは依然拒否
	if _, err := authengine.New(authengine.Config{Issuer: "http://host.docker.internal:8080", Store: memory.New(), Keys: ks, AllowInsecureIssuer: true}); err != nil {
		t.Errorf("insecure issuer must be accepted when allowed: %v", err)
	}
	if _, err := authengine.New(authengine.Config{Issuer: "ftp://as.example.com", Store: memory.New(), Keys: ks, AllowInsecureIssuer: true}); err == nil {
		t.Error("non-http scheme must be rejected even when insecure issuer is allowed")
	}
}
