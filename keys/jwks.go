package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ImportJWKS は公開鍵の JWK Set（RFC 7517 §5。認可サーバーの /jwks の応答）から検証専用の Set を作る。
//
// Resource Server が JWT Access Token をローカル検証するときに使う（resourceserver パッケージ）。
// 各鍵は kid を持つこと。alg がなければ鍵の種類から推定する（RSA → RS256、P-256 → ES256）。
// RS256 / ES256 以外の鍵は読み飛ばす（他の用途の鍵が同居していてもよい。その kid で署名された
// トークンは Verify が ErrUnknownKey で拒否する）。
func ImportJWKS(data []byte) (*Set, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("keys: import jwks: %w", err)
	}
	s := NewSet()
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			return nil, errors.New("keys: import jwks: key without kid")
		}
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		alg := jwk.Algorithm
		if alg == "" {
			alg = inferAlg(jwk.Key)
		}
		if alg != AlgRS256 && alg != AlgES256 {
			continue
		}
		if !jwk.IsPublic() {
			return nil, errors.New("keys: import jwks: private key in a public jwks")
		}
		s.AddVerification(&Key{ID: jwk.KeyID, Alg: alg, CreatedAt: time.Time{}, public: jwk.Key})
	}
	return s, nil
}

// inferAlg は alg を持たない JWK の鍵種別から署名アルゴリズムを推定する。
func inferAlg(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return AlgRS256
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return AlgES256
		}
	}
	return ""
}
