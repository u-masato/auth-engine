package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestImportJWKS(t *testing.T) {
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	signing := NewSet()
	for _, alg := range []string{AlgRS256, AlgES256} {
		k, err := Generate(alg, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := signing.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	jwks, err := signing.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	verifying, err := ImportJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifying.SigningAlgorithms()) != 0 {
		t.Fatal("imported jwks must not provide signing keys")
	}
	for _, alg := range []string{AlgRS256, AlgES256} {
		tok, err := signing.SignTyped(alg, "at+jwt", map[string]any{"sub": "alice"})
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Sub string `json:"sub"`
		}
		h, err := verifying.Verify(tok, &claims)
		if err != nil || claims.Sub != "alice" || h.Alg != alg || h.Type != "at+jwt" {
			t.Fatalf("%s: verify with imported keys: %+v %v", alg, h, err)
		}
	}

	// alg を省いた JWK は鍵種別から推定する。kid のない鍵は拒否。RS256 / ES256 以外は読み飛ばす
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	for _, k := range set.Keys {
		delete(k, "alg")
	}
	_, edPub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edJWK, _ := json.Marshal(jose.JSONWebKey{Key: edPub, KeyID: "ed", Algorithm: "EdDSA"})
	var edMap map[string]any
	_ = json.Unmarshal(edJWK, &edMap)
	set.Keys = append(set.Keys, edMap)
	noAlg, _ := json.Marshal(set)
	imported, err := ImportJWKS(noAlg)
	if err != nil {
		t.Fatalf("jwks without alg: %v", err)
	}
	for _, k := range set.Keys[:2] {
		if key, ok := imported.Key(k["kid"].(string)); !ok || (key.Alg != AlgRS256 && key.Alg != AlgES256) {
			t.Fatalf("alg must be inferred for %v: %+v", k["kid"], key)
		}
	}
	if _, ok := imported.Key("ed"); ok {
		t.Fatal("unsupported key types must be skipped")
	}

	for _, k := range set.Keys {
		delete(k, "kid")
	}
	noKid, _ := json.Marshal(set)
	if _, err := ImportJWKS(noKid); err == nil {
		t.Fatal("keys without kid must be rejected")
	}
	if _, err := ImportJWKS([]byte("{")); err == nil {
		t.Fatal("malformed jwks must be rejected")
	}

	// 秘密鍵が混ざった JWKS は拒否する
	private, err := signing.ExportPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportJWKS(private); err == nil {
		t.Fatal("private keys must be rejected")
	}
	// インポートした鍵で署名はできない
	if _, err := verifying.Sign(AlgRS256, map[string]any{}); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("want ErrNoSigningKey, got %v", err)
	}
}
