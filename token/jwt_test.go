package token_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/token"
)

const (
	jwtRS256Res = "https://jwt-rs.example.com"
	jwtES256Res = "https://jwt-es.example.com"
)

// jwtClaims は検証側（Resource Server）が読む RFC 9068 §2.2 の Claims。
type jwtClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      []string `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	JTI      string   `json:"jti"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	AuthTime int64    `json:"auth_time"`
	ACR      string   `json:"acr"`
	AMR      []string `json:"amr"`
}

// withJWT は fixture に署名鍵と、JWT を発行する resource（RS256 と ES256）および Opaque の resource を与える。
func (f *fixture) withJWT(t *testing.T) *keys.Set {
	t.Helper()
	set := keys.NewSet()
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		k, err := keys.Generate(alg, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	f.withResources(t,
		resource.Resource{URI: apiRes},
		resource.Resource{URI: jwtRS256Res, AccessTokenFormat: resource.FormatJWT},
		resource.Resource{URI: jwtES256Res, AccessTokenFormat: resource.FormatJWT, AccessTokenAlg: resource.AlgES256},
	)
	f.svc.Issuer = token.ByFormat{
		resource.FormatOpaque: token.OpaqueIssuer{},
		resource.FormatJWT:    &token.JWTIssuer{Issuer: "https://as.example.com", Keys: set},
	}
	return set
}

func TestJWTAccessTokenFromCode(t *testing.T) {
	f := newFixture(t)
	set := f.withJWT(t)
	code := f.issueCodeFor(t, "web", true, []string{"openid", "profile"}, []string{jwtRS256Res})
	res, err := f.svc.Exchange(f.ctx, f.codeRequest(code))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(res.AccessToken, token.AccessTokenPrefix) || strings.Count(res.AccessToken, ".") != 2 {
		t.Fatalf("jwt resource must yield a compact JWS: %q", res.AccessToken)
	}
	var c jwtClaims
	h, err := set.Verify(res.AccessToken, &c)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != token.JWTAccessTokenType || h.Alg != keys.AlgRS256 {
		t.Fatalf("header: %+v", h)
	}
	if c.Iss != "https://as.example.com" || c.Sub != "alice" || !slices.Equal(c.Aud, []string{jwtRS256Res}) || c.ClientID != "web" ||
		c.Scope != "openid profile" || c.JTI == "" || c.Iat != now.Unix() || c.Exp != now.Add(time.Hour).Unix() || c.AuthTime != now.Unix() {
		t.Fatalf("claims: %+v", c)
	}
	// Store には JWT 文字列の SHA-256 で行があり、Introspection / UserInfo 向けの参照は Opaque と同じ経路
	at := f.lookupAccess(t, res.AccessToken)
	if at.Hash != rand.Hash(res.AccessToken) || !slices.Equal(at.Audience, []string{jwtRS256Res}) || !slices.Equal(at.Scopes, []string{"openid", "profile"}) {
		t.Fatalf("stored record: %+v", at)
	}
	in, _ := f.svc.Inspect(f.ctx, res.AccessToken, "")
	if !in.Active || !slices.Equal(in.Audience, []string{jwtRS256Res}) || in.ClientID != "web" {
		t.Fatalf("introspection: %+v", in)
	}
	// ID Token の at_hash は JWT の平文から計算される（IDTokens が nil の fixture では省略）。
	// Revocation は Opaque と同じく効く
	if found, err := f.svc.RevokeToken(f.ctx, res.AccessToken, ""); err != nil || !found {
		t.Fatalf("revoke: %v %v", found, err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("revoked jwt must be inactive in introspection")
	}
	// 署名は失効後も検証できる（ローカル検証に失効は伝播しない。ADR-0008 §3）
	if _, err := set.Verify(res.AccessToken, &c); err != nil {
		t.Fatalf("signature must still verify: %v", err)
	}

	// Refresh でも JWT が出る。jti は毎回異なる
	refreshed, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	var c2 jwtClaims
	if _, err := set.Verify(refreshed.AccessToken, &c2); err != nil || c2.JTI == c.JTI || !slices.Equal(c2.Aud, []string{jwtRS256Res}) {
		t.Fatalf("refreshed jwt: %+v %v", c2, err)
	}
}

func TestJWTAccessTokenES256AndOpaqueUnchanged(t *testing.T) {
	f := newFixture(t)
	set := f.withJWT(t)

	res, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, []string{"openid"}, []string{jwtES256Res})))
	if err != nil {
		t.Fatal(err)
	}
	var c jwtClaims
	h, err := set.Verify(res.AccessToken, &c)
	if err != nil || h.Alg != keys.AlgES256 || h.Type != token.JWTAccessTokenType || !slices.Equal(c.Aud, []string{jwtES256Res}) {
		t.Fatalf("es256 jwt: header=%+v claims=%+v err=%v", h, c, err)
	}

	// Opaque の resource と resource なしは従来どおり at_ 接頭辞
	for _, resources := range [][]string{{apiRes}, nil} {
		res, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, []string{"openid"}, resources)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(res.AccessToken, token.AccessTokenPrefix) {
			t.Fatalf("opaque expected for %v: %q", resources, res.AccessToken)
		}
	}
}

func TestJWTAccessTokenClientCredentials(t *testing.T) {
	f := newFixture(t)
	set := f.withJWT(t)
	res, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Scope: "api:read", Resource: []string{jwtRS256Res},
		Credentials: f.machineCreds(t)})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if _, err := set.Verify(res.AccessToken, &c); err != nil {
		t.Fatal(err)
	}
	// ユーザー認証がないので auth_time / amr / acr は載らない（RFC 9068 §2.2.1）。sub は client_id
	for _, absent := range []string{"auth_time", "amr", "acr"} {
		if _, has := c[absent]; has {
			t.Fatalf("%s must be omitted for client_credentials: %v", absent, c)
		}
	}
	if c["sub"] != "m2m" || c["client_id"] != "m2m" || c["scope"] != "api:read" {
		t.Fatalf("claims: %v", c)
	}
}

func TestJWTIssuerNotWired(t *testing.T) {
	f := newFixture(t)
	f.withJWT(t)
	// Issuer を外すと JWT の resource は内部エラー（プロトコルエラーではない）。Opaque は動く
	f.svc.Issuer = nil
	_, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, []string{"openid"}, []string{jwtRS256Res})))
	var perr *token.Error
	if err == nil || errors.As(err, &perr) || !errors.Is(err, token.ErrUnsupportedFormat) {
		t.Fatalf("missing jwt issuer must be an internal error: %v", err)
	}
	if _, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, []string{"openid"}, []string{apiRes}))); err != nil {
		t.Fatalf("opaque must still work: %v", err)
	}
	// JWTIssuer 単体: Audience なしは拒否
	j := &token.JWTIssuer{Issuer: "https://as.example.com", Keys: keys.NewSet()}
	if _, _, err := j.Issue(context.Background(), token.IssueInput{Client: &client.Client{}, Family: &token.Family{}, Now: now}); err == nil {
		t.Fatal("jwt without audience must be rejected")
	}
}
