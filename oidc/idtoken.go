package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/token"
)

// DefaultIDTokenTTL は ID Token の既定の有効期間。
const DefaultIDTokenTTL = time.Hour

// IDTokenIssuer は ID Token を発行する。token.IDTokenIssuer を実装し、Engine が token.Service に配線する。
type IDTokenIssuer struct {
	// Issuer は iss クレーム（RFC 8414 / OIDC Discovery の issuer と同じ値）。
	Issuer string
	Keys   *keys.Set
	Clock  clock.Clock
	// TTL は 0 なら DefaultIDTokenTTL。
	TTL time.Duration
}

var _ token.IDTokenIssuer = (*IDTokenIssuer)(nil)

// idTokenClaims は OIDC Core §2 の ID Token クレーム。
type idTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	AuthTime  int64    `json:"auth_time"`
	Nonce     string   `json:"nonce,omitempty"`
	ATHash    string   `json:"at_hash,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	ACR       string   `json:"acr,omitempty"`
}

// IssueIDToken は Client の署名アルゴリズムで ID Token を発行する。
//
// Code フローでは scope 由来の Claims（profile, email, ...）は UserInfo から返し、
// ID Token には載せない（OIDC Core §5.4）。
func (i *IDTokenIssuer) IssueIDToken(_ context.Context, c *client.Client, in token.IDTokenInput) (string, error) {
	if in.Subject == "" {
		return "", errors.New("oidc: subject is required")
	}
	if !c.IssuesIDToken() {
		return "", fmt.Errorf("oidc: client profile %q does not issue id tokens", c.Profile)
	}
	now := i.Clock.Now()
	ttl := i.TTL
	if ttl == 0 {
		ttl = DefaultIDTokenTTL
	}
	claims := idTokenClaims{
		Issuer:    i.Issuer,
		Subject:   in.Subject,
		Audience:  []string{c.ID},
		ExpiresAt: now.Add(ttl).Unix(),
		IssuedAt:  now.Unix(),
		AuthTime:  in.AuthenticatedAt.Unix(),
		Nonce:     in.Nonce,
		AMR:       in.AMR,
		ACR:       in.ACR,
	}
	if in.AccessToken != "" {
		h, err := AccessTokenHash(c.IDTokenAlg, in.AccessToken)
		if err != nil {
			return "", err
		}
		claims.ATHash = h
	}
	return i.Keys.Sign(c.IDTokenAlg, claims)
}

// AccessTokenHash は at_hash（OIDC Core §3.1.3.6）を返す。
// ID Token の署名アルゴリズムのハッシュ（RS256 / ES256 は SHA-256）で Access Token の
// ASCII 表現をハッシュし、左半分を base64url にする。
func AccessTokenHash(alg, accessToken string) (string, error) {
	switch alg {
	case keys.AlgRS256, keys.AlgES256:
		sum := sha256.Sum256([]byte(accessToken))
		return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
	default:
		return "", fmt.Errorf("oidc: unsupported id token alg %q", alg)
	}
}
