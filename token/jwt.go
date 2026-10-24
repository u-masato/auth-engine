package token

import (
	"context"
	"errors"
	"strings"

	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/keys"
)

// JWTAccessTokenType は JWT Access Token の typ ヘッダ（RFC 9068 §2.1）。
// Resource Server はこれ以外（ID Token の "JWT" など）を拒否する（§4）。
const JWTAccessTokenType = "at+jwt"

// JWTIssuer は RFC 9068 の JWT Access Token を発行する Issuer。
//
// 署名は keys の RS256 / ES256（ADR-0002。JOSE の利用は keys に閉じる）。JWT でも Store に
// AccessToken の行を持ち（Hash は JWT 文字列の SHA-256）、Introspection と Revocation は Opaque と
// 同じ経路で動く。ただし Resource Server が JWKS でローカル検証する限り、失効は exp まで伝播しない
// （ADR-0006 §1、ADR-0008 §3）。JWT を選ぶ resource は短い AccessTokenTTL の Client と組み合わせること。
type JWTIssuer struct {
	// Issuer は iss クレーム（RFC 8414 の issuer と同じ値）。
	Issuer string
	Keys   *keys.Set
}

var _ Issuer = (*JWTIssuer)(nil)

// jwtAccessClaims は RFC 9068 §2.2 の Claims。
type jwtAccessClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"` // resource indicator の値（§3）。常に配列で出す
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"` // 空白区切り（§2.2.3）
	// 認可コード由来のときだけ載せる（§2.2.1）。client_credentials ではユーザー認証がないので省く。
	AuthTime int64    `json:"auth_time,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
}

// Issue は in.Alg で署名した JWT を平文として返す。aud は in.Audience で、空なら発行しない
// （JWT は resource 向けにだけ使う。ADR-0008 §3）。
func (j *JWTIssuer) Issue(_ context.Context, in IssueInput) (string, *AccessToken, error) {
	if j.Keys == nil || j.Issuer == "" {
		return "", nil, errors.New("token: JWTIssuer requires Issuer and Keys")
	}
	if len(in.Audience) == 0 {
		return "", nil, errors.New("token: jwt access token requires an audience")
	}
	alg := in.Alg
	if alg == "" {
		alg = keys.AlgRS256
	}
	jti, err := rand.Token("")
	if err != nil {
		return "", nil, err
	}
	claims := jwtAccessClaims{
		Issuer:    j.Issuer,
		Subject:   in.Family.Subject,
		Audience:  in.Audience,
		ExpiresAt: in.expiresAt().Unix(),
		IssuedAt:  in.Now.Unix(),
		JWTID:     jti,
		ClientID:  in.Client.ID,
		Scope:     strings.Join(in.Scopes, " "),
		ACR:       in.Family.ACR,
		AMR:       in.Family.AMR,
	}
	if !in.Family.AuthenticatedAt.IsZero() {
		claims.AuthTime = in.Family.AuthenticatedAt.Unix()
	}
	plaintext, err := j.Keys.SignTyped(alg, JWTAccessTokenType, claims)
	if err != nil {
		return "", nil, err
	}
	return plaintext, newAccessRecord(in, plaintext), nil
}
