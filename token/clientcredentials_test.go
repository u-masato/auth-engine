package token_test

import (
	"testing"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/token"
)

func (f *fixture) machineCreds(t *testing.T) token.Credentials {
	t.Helper()
	// fixture の svc クライアントはシークレットを捨てているので、テスト用に作り直す
	c, secret, err := client.NewMachine(client.MachineParams{ID: "m2m", Name: "M2M", Scopes: []string{"api:read", "api:write"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateClient(f.ctx, c); err != nil {
		t.Fatal(err)
	}
	return token.Credentials{ClientID: "m2m", Secret: string(secret), Method: client.AuthClientSecretBasic}
}

func TestClientCredentials(t *testing.T) {
	f := newFixture(t)
	creds := f.machineCreds(t)
	res, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	// scope 未指定なら Client の全 scope。Refresh Token と ID Token は出ない
	if res.Scope != "api:read api:write" || res.RefreshToken != "" || res.IDToken != "" || res.TokenType != "Bearer" || res.ExpiresIn != 3600 {
		t.Fatalf("response: %+v", res)
	}
	at, g, err := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	// Grant は subject = client_id
	if at.Subject != "m2m" || at.ClientID != "m2m" || g.ClientID != "m2m" || g.Subject != "m2m" || !g.Active() || g.Claims != nil {
		t.Fatalf("stored: token=%+v grant=%+v", at, g)
	}
	fam, _ := f.store.GetTokenFamily(f.ctx, at.FamilyID)
	if !fam.ExpiresAt.IsZero() || !fam.AuthenticatedAt.IsZero() {
		t.Fatalf("m2m family must not carry refresh expiry or auth info: %+v", fam)
	}

	// scope の縮小。2 回目の要求は同じ Grant を更新する
	res2, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Scope: "api:read", Credentials: creds})
	if err != nil || res2.Scope != "api:read" {
		t.Fatalf("narrowed: %+v %v", res2, err)
	}
	at2, g2, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(res2.AccessToken))
	if g2.ID != g.ID || len(at2.Scopes) != 1 {
		t.Fatalf("second request: token=%+v grant=%+v", at2, g2)
	}

	// 許可外の scope は invalid_scope
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Scope: "api:read admin", Credentials: creds})), token.CodeInvalidScope)

	// シークレットなしは invalid_client
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials",
		Credentials: token.Credentials{ClientID: "m2m", Method: client.AuthNone}})), token.CodeInvalidClient)
	// Machine Profile は refresh_token も使えない
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, token.Request{GrantType: "refresh_token", RefreshToken: "x", Credentials: creds})), token.CodeUnauthorizedClient)
	// Native Profile は client_credentials を使えない
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials",
		Credentials: token.Credentials{ClientID: "cli", Method: client.AuthNone}})), token.CodeUnauthorizedClient)
}

func TestClientCredentialsRevokedGrantRevives(t *testing.T) {
	f := newFixture(t)
	creds := f.machineCreds(t)
	res, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	_, g, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if err := f.store.RevokeGrant(f.ctx, g.ID, now); err != nil {
		t.Fatal(err)
	}
	// 失効後の再要求は Grant を active に戻して発行する（Client 自身の権限なので同意は不要）
	res2, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	at, g2, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(res2.AccessToken))
	if !g2.Active() || at.Status != token.AccessActive {
		t.Fatalf("revived: token=%+v grant=%+v", at, g2)
	}
	old, _, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if old.Status != token.AccessRevoked {
		t.Fatal("tokens from before the revocation must stay revoked")
	}
}
