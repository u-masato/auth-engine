package keys

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

type claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	N   int    `json:"n"`
}

func newSet(t *testing.T, algs ...string) *Set {
	t.Helper()
	s := NewSet()
	for _, alg := range algs {
		k, err := Generate(alg, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range []string{AlgRS256, AlgES256} {
		t.Run(alg, func(t *testing.T) {
			s := newSet(t, alg)
			tok, err := s.Sign(alg, claims{Iss: "https://as.example.com", Sub: "alice"}, map[string]any{"n": 7})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(tok, ".") != 2 {
				t.Fatalf("compact JWS expected: %s", tok)
			}
			var got claims
			h, err := s.Verify(tok, &got)
			if err != nil {
				t.Fatal(err)
			}
			k, _ := s.SigningKey(alg)
			if h.KeyID != k.ID || h.Alg != alg || h.Type != "JWT" || got.Iss != "https://as.example.com" || got.Sub != "alice" || got.N != 7 {
				t.Fatalf("header=%+v claims=%+v", h, got)
			}
			// typ を指定して署名でき、検証側で読める（RFC 9068 §2.1 の at+jwt）
			typed, err := s.SignTyped(alg, "at+jwt", claims{Sub: "bob"})
			if err != nil {
				t.Fatal(err)
			}
			if h, err := s.Verify(typed, &got); err != nil || h.Type != "at+jwt" || got.Sub != "bob" {
				t.Fatalf("typed: header=%+v claims=%+v err=%v", h, got, err)
			}
			if _, err := s.SignTyped(alg, "", claims{}); err == nil {
				t.Fatal("empty typ must be rejected")
			}
			// 別の Set では検証できない（kid 不明）
			other := newSet(t, alg)
			if _, err := other.Verify(tok, &got); !errors.Is(err, ErrUnknownKey) {
				t.Fatalf("other set: %v", err)
			}
			// 改ざん
			tampered := tok[:len(tok)-2] + "xx"
			if _, err := s.Verify(tampered, &got); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("tampered: %v", err)
			}
		})
	}
}

func TestNoSigningKey(t *testing.T) {
	s := newSet(t, AlgRS256)
	if _, err := s.Sign(AlgES256, claims{}); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("want ErrNoSigningKey, got %v", err)
	}
	if _, err := Generate("HS256", now); err == nil {
		t.Fatal("HS256 must be rejected")
	}
	pub := &Key{ID: "x", Alg: AlgRS256}
	if err := s.AddSigning(pub); err == nil {
		t.Fatal("public-only key cannot sign")
	}
}

func TestRotation(t *testing.T) {
	s := newSet(t, AlgRS256)
	old, _ := s.SigningKey(AlgRS256)
	tokOld, err := s.Sign(AlgRS256, claims{Sub: "a"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := Generate(AlgRS256, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddSigning(next); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.SigningKey(AlgRS256)
	if cur.ID != next.ID || cur.ID == old.ID {
		t.Fatal("new key must become the signing key")
	}
	// 旧鍵で署名したトークンはまだ検証できる
	var got claims
	if _, err := s.Verify(tokOld, &got); err != nil {
		t.Fatalf("old token must verify during rotation: %v", err)
	}
	tokNew, _ := s.Sign(AlgRS256, claims{Sub: "b"})
	h, _ := s.Verify(tokNew, &got)
	if h.KeyID != next.ID {
		t.Fatal("new tokens must use the new key")
	}
	// JWKS には両方の公開鍵
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	raw, _ := s.JWKS()
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("jwks must list both keys: %s", raw)
	}
	// 旧鍵を外すと旧トークンは検証できない
	s.Remove(old.ID)
	if _, err := s.Verify(tokOld, &got); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("after remove: %v", err)
	}
	if algs := s.SigningAlgorithms(); len(algs) != 1 || algs[0] != AlgRS256 {
		t.Fatalf("algs: %v", algs)
	}
}

func TestJWKSHasNoPrivateMaterial(t *testing.T) {
	s := newSet(t, AlgRS256, AlgES256)
	raw, err := s.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("want 2 keys: %s", raw)
	}
	for _, k := range jwks.Keys {
		for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, leaked := k[priv]; leaked {
				t.Fatalf("private field %q in JWKS: %s", priv, raw)
			}
		}
		if k["use"] != "sig" || k["kid"] == "" || k["alg"] == "" {
			t.Fatalf("jwk metadata: %v", k)
		}
	}
	if algs := s.SigningAlgorithms(); len(algs) != 2 || algs[0] != AlgRS256 || algs[1] != AlgES256 {
		t.Fatalf("algs: %v", algs)
	}
}

func TestExportImportPrivate(t *testing.T) {
	s := newSet(t, AlgRS256, AlgES256)
	tok, _ := s.Sign(AlgES256, claims{Sub: "a"})
	data, err := s.ExportPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"d":`) {
		t.Fatal("private export must contain private material")
	}
	restored, err := ImportPrivate(data)
	if err != nil {
		t.Fatal(err)
	}
	var got claims
	if _, err := restored.Verify(tok, &got); err != nil || got.Sub != "a" {
		t.Fatalf("restored set must verify old tokens: %v", err)
	}
	orig, _ := s.SigningKey(AlgES256)
	cur, err := restored.SigningKey(AlgES256)
	if err != nil || cur.ID != orig.ID || !cur.HasPrivate() || !cur.CreatedAt.Equal(now) {
		t.Fatalf("signing key not restored: %+v %v", cur, err)
	}
	if _, err := restored.Sign(AlgRS256, claims{Sub: "b"}); err != nil {
		t.Fatalf("restored set must sign: %v", err)
	}
	if _, err := ImportPrivate([]byte(`{"keys":[],"signing":{"RS256":"nope"}}`)); err == nil {
		t.Fatal("dangling signing reference must fail")
	}
}

func TestKidIsThumbprint(t *testing.T) {
	k, _ := Generate(AlgES256, now)
	k2, _ := newKey(AlgES256, k.private, now)
	if k.ID != k2.ID || len(k.ID) != 43 {
		t.Fatalf("kid must be deterministic thumbprint: %q %q", k.ID, k2.ID)
	}
}
