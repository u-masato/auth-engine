package token_test

import (
	"testing"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/token"
)

func TestInspect(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)

	at, err := f.svc.Inspect(f.ctx, res.AccessToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if !at.Active || at.TokenType != "Bearer" || at.ClientID != "web" || at.Subject != "alice" || len(at.Scopes) != 2 ||
		!at.IssuedAt.Equal(now) || !at.ExpiresAt.Equal(now.Add(time.Hour)) || at.Kind != token.HintAccessToken {
		t.Fatalf("access introspection: %+v", at)
	}
	// hint が外れていても見つかる
	rt, err := f.svc.Inspect(f.ctx, res.RefreshToken, token.HintAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !rt.Active || rt.TokenType != "" || rt.ClientID != "web" || rt.Subject != "alice" || rt.Kind != token.HintRefreshToken ||
		!rt.ExpiresAt.Equal(now.Add(14*24*time.Hour)) {
		t.Fatalf("refresh introspection: %+v", rt)
	}
	// 不明・空は active:false でエラーにしない
	for _, tok := range []string{"", "at_unknown"} {
		in, err := f.svc.Inspect(f.ctx, tok, "")
		if err != nil || in.Active {
			t.Fatalf("unknown token %q: %+v %v", tok, in, err)
		}
	}
	// 期限切れ
	f.clock.Advance(time.Hour)
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("expired access token must be inactive")
	}
	if in, _ := f.svc.Inspect(f.ctx, res.RefreshToken, ""); !in.Active {
		t.Fatal("refresh token must still be active")
	}
	// Grant の失効で両方とも inactive
	if err := f.store.RevokeGrant(f.ctx, f.grantID, f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.RefreshToken, ""); in.Active {
		t.Fatal("refresh token must be inactive after grant revocation")
	}
}

func TestRevokeAccessTokenOnly(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.AccessToken, Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("access token must be revoked")
	}
	// Access Token の失効は Refresh Token に及ばず、Refresh は続けられる
	if in, _ := f.svc.Inspect(f.ctx, res.RefreshToken, ""); !in.Active {
		t.Fatal("refresh token must survive access token revocation")
	}
	if _, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, "")); err != nil {
		t.Fatal(err)
	}
	// 二重失効・不明なトークンも成功
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.AccessToken, Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: "at_nope", TokenTypeHint: "refresh_token", Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeRefreshTokenRevokesFamily(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	second, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	// 後継の Refresh Token を失効 → Family の全 Access Token も失効、Grant は残る
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: second.RefreshToken, TokenTypeHint: token.HintRefreshToken, Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{res.AccessToken, second.AccessToken, second.RefreshToken} {
		if in, _ := f.svc.Inspect(f.ctx, tok, ""); in.Active {
			t.Fatalf("%s must be inactive after refresh token revocation", tok[:3])
		}
	}
	g, _ := f.store.GetGrant(f.ctx, f.grantID)
	if !g.Active() {
		t.Fatal("revoking a refresh token must not revoke the grant")
	}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(second.RefreshToken, ""))), token.CodeInvalidGrant)
}

func TestRevokeOtherClientsTokenIsSilentlyIgnored(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	cli := token.Credentials{ClientID: "cli", Method: client.AuthNone}
	for _, tok := range []string{res.AccessToken, res.RefreshToken} {
		if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: tok, Credentials: cli}); err != nil {
			t.Fatal(err)
		}
		if in, _ := f.svc.Inspect(f.ctx, tok, ""); !in.Active {
			t.Fatal("another client must not be able to revoke the token")
		}
	}
	// 認証失敗は invalid_client、token なしは invalid_request
	wantProtocolErr(t, f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.AccessToken, Credentials: token.Credentials{ClientID: "web", Secret: "bad", Method: client.AuthClientSecretBasic}}), token.CodeInvalidClient)
	wantProtocolErr(t, f.svc.Revoke(f.ctx, token.RevocationRequest{Credentials: f.webCreds()}), token.CodeInvalidRequest)

	// Go API の RevokeToken は所有者を問わない
	found, err := f.svc.RevokeToken(f.ctx, res.AccessToken, "")
	if err != nil || !found {
		t.Fatalf("management revoke: %v %v", found, err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("management revoke must revoke")
	}
	found, _ = f.svc.RevokeToken(f.ctx, "at_nope", "")
	if found {
		t.Fatal("unknown token must report not found")
	}
}

func TestIntrospectRequiresConfidentialClient(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	m2m := f.machineCreds(t)

	// Machine Client（Resource Server）は他 Client のトークンを検証できる
	in, err := f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: res.AccessToken, Credentials: m2m})
	if err != nil || !in.Active || in.ClientID != "web" {
		t.Fatalf("introspect by resource server: %+v %v", in, err)
	}
	// Web Client も可
	if in, err := f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: res.AccessToken, Credentials: f.webCreds()}); err != nil || !in.Active {
		t.Fatalf("introspect by web: %+v %v", in, err)
	}
	// public Client は invalid_client
	_, err = f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: res.AccessToken, Credentials: token.Credentials{ClientID: "cli", Method: client.AuthNone}})
	wantProtocolErr(t, err, token.CodeInvalidClient)
	_, err = f.svc.Introspect(f.ctx, token.IntrospectionRequest{Credentials: m2m})
	wantProtocolErr(t, err, token.CodeInvalidRequest)
	// 平文ではなくハッシュで検索しているので、ハッシュ値を提示しても見つからない
	if in, _ := f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: rand.Hash(res.AccessToken), Credentials: m2m}); in.Active {
		t.Fatal("hash must not be accepted as a token")
	}
}
