package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/examples/standalone/oauthclient"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/token"
)

// idTokenClaims は RP が検証する ID Token のクレーム。
type idTokenClaims struct {
	jwt.Claims
	Nonce    string   `json:"nonce"`
	AuthTime int64    `json:"auth_time"`
	ATHash   string   `json:"at_hash"`
	AMR      []string `json:"amr"`
}

// verifyIDToken は RP と同じ手順で /jwks を取得し、署名と iss / aud / exp を検証する。
// エンジンの keys パッケージではなく go-jose を直接使い、公開 JWKS だけで検証できることを確かめる。
func (s *system) verifyIDToken(t *testing.T, idToken, clientID string) idTokenClaims {
	t.Helper()
	res, err := http.Get(s.public.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	keys := jwks.Key(parsed.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q not found in jwks", parsed.Headers[0].KeyID)
	}
	var claims idTokenClaims
	if err := parsed.Claims(keys[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	if err := claims.Validate(jwt.Expected{Issuer: s.public.URL, AnyAudience: jwt.Audience{clientID}, Time: s.clock()}); err != nil {
		t.Fatalf("id token claims: %v (%+v)", err, claims)
	}
	return claims
}

// runCodeFlow は自動承認の loginapp でフローを完走し、トークン応答を返す。
func (s *system) runCodeFlow(t *testing.T, b *http.Client, clientID, secret string, scopes []string) (*oauthclient.CodeFlow, *oauthclient.TokenResponse) {
	t.Helper()
	flow, cb := s.startFlow(t, clientID, secret, scopes)
	if clientID == "web" {
		registerRedirect(t, s, "web", flow.RedirectURI)
	}
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	code, err := flow.HandleCallback(waitCallback(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := flow.Exchange(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	return flow, tok
}

func TestOIDCTokenLifecycle(t *testing.T) {
	s := newSystem(t, true)
	ctx := context.Background()
	flow, tok := s.runCodeFlow(t, browser(t), "web", s.webSecret, []string{"openid", "profile", "email"})

	// ID Token を公開 JWKS で検証できる（OIDC Core §3.1.3.7）
	if tok.IDToken == "" || tok.RefreshToken == "" {
		t.Fatalf("web client must receive id_token and refresh_token: %+v", tok)
	}
	claims := s.verifyIDToken(t, tok.IDToken, "web")
	if claims.Subject != "alice" || claims.AuthTime == 0 || claims.ATHash == "" || len(claims.AMR) != 1 {
		t.Fatalf("id token claims: %+v", claims)
	}

	// UserInfo は Grant の Claims を scope で絞って返す
	ui, err := flow.UserInfo(ctx, tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if ui["sub"] != "alice" || ui["email"] != "alice@example.com" || ui["name"] == nil || ui["phone_number"] != nil {
		t.Fatalf("userinfo: %v", ui)
	}

	// Refresh: Rotation され、ID Token も新しくなる。auth_time は元の認証、nonce はなし
	s.advance(time.Hour)
	refreshed, err := flow.Refresh(ctx, tok.RefreshToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == tok.RefreshToken || refreshed.AccessToken == tok.AccessToken || refreshed.IDToken == "" {
		t.Fatalf("refresh: %+v", refreshed)
	}
	rclaims := s.verifyIDToken(t, refreshed.IDToken, "web")
	if rclaims.AuthTime != claims.AuthTime || rclaims.Nonce != "" || rclaims.Subject != "alice" {
		t.Fatalf("refreshed id token: %+v", rclaims)
	}
	// 旧 Refresh Token の再利用は invalid_grant で、Family 全体が失効する
	_, err = flow.Refresh(ctx, tok.RefreshToken, "")
	var terr *oauthclient.TokenError
	if !errors.As(err, &terr) || terr.Code != "invalid_grant" {
		t.Fatalf("refresh reuse: %v", err)
	}
	at, _, _ := s.store.LookupAccessToken(ctx, rand.Hash(refreshed.AccessToken))
	if at.Status != token.AccessRevoked {
		t.Fatal("refresh reuse must revoke the family")
	}
	if _, err := flow.UserInfo(ctx, refreshed.AccessToken); err == nil {
		t.Fatal("userinfo must reject a revoked token")
	}
}

func TestRevocationAndIntrospection(t *testing.T) {
	s := newSystem(t, true)
	ctx := context.Background()
	flow, tok := s.runCodeFlow(t, browser(t), "web", s.webSecret, []string{"openid"})

	// Resource Server（Machine Profile）が Introspection で検証する
	rs, rsSecret, err := client.NewMachine(client.MachineParams{ID: "rs", Name: "Resource Server", Scopes: []string{"api"}}, s.clock())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateClient(ctx, rs); err != nil {
		t.Fatal(err)
	}
	introspect := func(tok string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, s.public.URL+"/introspect", strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("rs", string(rsSecret))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("introspect: %d %s", res.StatusCode, body)
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		return m
	}
	in := introspect(tok.AccessToken)
	if in["active"] != true || in["client_id"] != "web" || in["sub"] != "alice" || in["scope"] != "openid" || in["iss"] != s.public.URL {
		t.Fatalf("introspection: %v", in)
	}

	// Access Token だけ失効 → Refresh はまだ使える
	if err := flow.Revoke(ctx, tok.AccessToken, "access_token"); err != nil {
		t.Fatal(err)
	}
	if in := introspect(tok.AccessToken); in["active"] != false {
		t.Fatalf("after access revoke: %v", in)
	}
	refreshed, err := flow.Refresh(ctx, tok.RefreshToken, "")
	if err != nil {
		t.Fatal(err)
	}
	// Refresh Token を失効 → Family 全体が無効
	if err := flow.Revoke(ctx, refreshed.RefreshToken, "refresh_token"); err != nil {
		t.Fatal(err)
	}
	for _, tk := range []string{refreshed.AccessToken, refreshed.RefreshToken} {
		if in := introspect(tk); in["active"] != false {
			t.Fatalf("after refresh revoke: %v", in)
		}
	}
	_, err = flow.Refresh(ctx, refreshed.RefreshToken, "")
	var terr *oauthclient.TokenError
	if !errors.As(err, &terr) || terr.Code != "invalid_grant" {
		t.Fatalf("refresh after revoke: %v", err)
	}
	// 不明なトークンの失効も 200
	if err := flow.Revoke(ctx, "at_unknown", ""); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	s := newSystem(t, true)
	ctx := context.Background()
	m2m, secret, err := client.NewMachine(client.MachineParams{ID: "batch", Name: "Batch", Scopes: []string{"api:read", "api:write"}}, s.clock())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateClient(ctx, m2m); err != nil {
		t.Fatal(err)
	}
	md, err := oauthclient.Discover(ctx, http.DefaultClient, s.public.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, md.TokenEndpoint, strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"api:read"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("batch", string(secret))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var tok oauthclient.TokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("client_credentials: %d %v", res.StatusCode, err)
	}
	if tok.Scope != "api:read" || tok.RefreshToken != "" || tok.IDToken != "" {
		t.Fatalf("client_credentials response: %+v", tok)
	}
	at, g, err := s.store.LookupAccessToken(ctx, rand.Hash(tok.AccessToken))
	if err != nil || at.Subject != "batch" || g.Subject != "batch" {
		t.Fatalf("stored: %+v %+v %v", at, g, err)
	}
}

// TestPromptNoneWithLoginSession は loginapp の Cookie セッションによる prompt=none の解釈を確かめる。
func TestPromptNoneWithLoginSession(t *testing.T) {
	s := newSystem(t, true)
	b := browser(t)

	// 1 回目: 通常のログイン（自動承認）でセッションができる
	_, first := s.runCodeFlow(t, b, "cli", "", []string{"openid"})
	firstClaims := s.verifyIDToken(t, first.IDToken, "cli")

	// 2 回目: 同じブラウザで prompt=none → セッションを再利用し、auth_time は 1 回目と同じ
	s.advance(time.Minute)
	flow, cb := s.startFlow(t, "cli", "", []string{"openid"})
	res, err := b.Get(flow.AuthorizationURL() + "&prompt=none")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	code, err := flow.HandleCallback(waitCallback(t, cb))
	if err != nil {
		t.Fatalf("prompt=none with session: %v", err)
	}
	tok, err := flow.Exchange(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if c := s.verifyIDToken(t, tok.IDToken, "cli"); c.AuthTime != firstClaims.AuthTime {
		t.Fatalf("auth_time must be reused: %d != %d", c.AuthTime, firstClaims.AuthTime)
	}

	// 別ブラウザ（セッションなし）で prompt=none → login_required
	flow, cb = s.startFlow(t, "cli", "", []string{"openid"})
	res, err = browser(t).Get(flow.AuthorizationURL() + "&prompt=none")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	_, err = flow.HandleCallback(waitCallback(t, cb))
	var aerr *oauthclient.AuthorizationError
	if !errors.As(err, &aerr) || aerr.Code != "login_required" {
		t.Fatalf("prompt=none without session: %v", err)
	}

	// prompt=login は同じブラウザでも再認証し、auth_time が進む
	flow, cb = s.startFlow(t, "cli", "", []string{"openid"})
	res, err = b.Get(flow.AuthorizationURL() + "&prompt=login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	code, err = flow.HandleCallback(waitCallback(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	tok, err = flow.Exchange(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if c := s.verifyIDToken(t, tok.IDToken, "cli"); c.AuthTime <= firstClaims.AuthTime {
		t.Fatalf("prompt=login must re-authenticate: %d <= %d", c.AuthTime, firstClaims.AuthTime)
	}
}
