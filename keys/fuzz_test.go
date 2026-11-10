package keys

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// FuzzVerify は、Verify が受理するトークンのペイロードが、この Set で署名したものから変わっていないことを
// 確かめる。alg: none や、公開鍵を HMAC の鍵に使う取り違え（RFC 8725 §2.1、§3.1）を seed に入れる。
func FuzzVerify(f *testing.F) {
	s := NewSet()
	for _, alg := range []string{AlgRS256, AlgES256} {
		k, err := Generate(alg, now)
		if err != nil {
			f.Fatal(err)
		}
		if err := s.AddSigning(k); err != nil {
			f.Fatal(err)
		}
	}
	var payloads [][]byte
	for _, alg := range []string{AlgRS256, AlgES256} {
		tok, err := s.Sign(alg, claims{Iss: "https://as.example.com", Sub: "alice"})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(tok)
		parts := strings.Split(tok, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		payloads = append(payloads, payload)

		k, _ := s.SigningKey(alg)
		kid := k.ID
		evil := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://as.example.com","sub":"mallory"}`))
		none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + kid + `"}`))
		f.Add(none + "." + evil + ".")
		// 公開鍵（JWKS の JSON）を HS256 の共有鍵に見立てて署名したもの
		jwks, _ := s.JWKS()
		hs := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"` + kid + `"}`))
		mac := hmac.New(sha256.New, jwks)
		mac.Write([]byte(hs + "." + evil))
		f.Add(hs + "." + evil + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
		// 別の鍵の alg を名乗るもの
		f.Add(parts[0] + "." + evil + "." + parts[2])
	}

	f.Fuzz(func(t *testing.T, token string) {
		var c claims
		h, err := s.Verify(token, &c)
		if err != nil {
			return
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("accepted a token that is not a compact JWS: %q", token)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil || !slices.ContainsFunc(payloads, func(p []byte) bool { return bytes.Equal(p, payload) }) {
			t.Fatalf("accepted a payload this set never signed: %q", parts[1])
		}
		if k, ok := s.Key(h.KeyID); !ok || k.Alg != h.Alg {
			t.Fatalf("accepted header %+v that does not match the key", h)
		}
	})
}

// FuzzImportJWKS は、取り込んだ Set が検証専用で（秘密鍵を持たない）、対応アルゴリズムの鍵だけを
// 持つことを確かめる。JWKS は Resource Server が認可サーバーから取得する外部入力である。
func FuzzImportJWKS(f *testing.F) {
	s := NewSet()
	k, err := Generate(AlgES256, now)
	if err != nil {
		f.Fatal(err)
	}
	if err := s.AddSigning(k); err != nil {
		f.Fatal(err)
	}
	pub, _ := s.JWKS()
	priv, _ := s.ExportPrivate()
	f.Add(pub)
	f.Add(priv)
	f.Add([]byte(`{"keys":[{"kty":"oct","kid":"h","k":"c2VjcmV0"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-384","kid":"p","x":"","y":""}]}`))
	f.Add([]byte(`{"keys":[{}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := ImportJWKS(data)
		if err != nil {
			return
		}
		for _, kid := range set.order {
			k, _ := set.Key(kid)
			if k.HasPrivate() || !slices.Contains(supportedAlgs, k.Alg) || k.public == nil {
				t.Fatalf("imported key %q is not a public key of a supported algorithm: %+v", kid, k)
			}
		}
		if len(set.SigningAlgorithms()) != 0 {
			t.Fatalf("an imported jwks must not produce signing keys")
		}
	})
}
