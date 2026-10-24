package token_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	redirect     = "https://app.example.com/cb"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type fixture struct {
	svc       *token.Service
	store     *memory.Store
	clock     *clock.Fixed
	ctx       context.Context
	webSecret string
	grantID   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	web, secret, err := client.NewWeb(client.WebParams{ID: "web", Name: "Web", RedirectURIs: []string{redirect}, Scopes: []string{"openid", "profile"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	native, err := client.NewNative(client.NativeParams{ID: "cli", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	m2m, _, err := client.NewMachine(client.MachineParams{ID: "svc", Name: "Svc", Scopes: []string{"api"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*client.Client{web, native, m2m} {
		if err := store.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	g, err := store.UpsertGrant(ctx, &grant.Grant{ID: "g1", ClientID: "web", Subject: "alice", Scopes: []string{"openid", "profile"},
		Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFixed(now)
	return &fixture{
		svc:       &token.Service{Clients: store, Store: store, Grants: store, Clock: clk, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		store:     store,
		clock:     clk,
		ctx:       ctx,
		webSecret: string(secret),
		grantID:   g.ID,
	}
}

// issueCode は Resume が発行したのと同等の Code を保存し、平文を返す。
func (f *fixture) issueCode(t *testing.T, clientID string, explicit bool) string {
	t.Helper()
	return f.issueCodeFor(t, clientID, explicit, []string{"openid", "profile"}, nil)
}

// issueCodeFor は scope と resource を指定して Code を保存し、平文を返す。
func (f *fixture) issueCodeFor(t *testing.T, clientID string, explicit bool, scopes, resources []string) string {
	t.Helper()
	plain, err := rand.Token("")
	if err != nil {
		t.Fatal(err)
	}
	fam, _ := rand.Token("")
	code := &authorization.AuthorizationCode{
		Hash: rand.Hash(plain), TxnID: "t", ClientID: clientID, GrantID: f.grantID, FamilyID: fam,
		Subject: "alice", RedirectURI: redirect, RedirectURIExplicit: explicit, Scopes: scopes, Resource: resources,
		CodeChallenge: rfcChallenge, CodeChallengeMethod: "S256", Nonce: "n", AuthenticatedAt: now,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := f.store.CreateAuthorizationCode(f.ctx, code); err != nil {
		t.Fatal(err)
	}
	return plain
}

func (f *fixture) webCreds() token.Credentials {
	return token.Credentials{ClientID: "web", Secret: f.webSecret, Method: client.AuthClientSecretBasic}
}

func (f *fixture) codeRequest(code string) token.Request {
	return token.Request{GrantType: "authorization_code", Code: code, RedirectURI: redirect, CodeVerifier: rfcVerifier, Credentials: f.webCreds()}
}

func wantProtocolErr(t *testing.T, err error, code string) *token.Error {
	t.Helper()
	var perr *token.Error
	if !errors.As(err, &perr) {
		t.Fatalf("want *token.Error %s, got %v", code, err)
	}
	if perr.Code != code {
		t.Fatalf("want %s, got %s (%s)", code, perr.Code, perr.Description)
	}
	return perr
}

func TestExchangeSuccess(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "web", true)
	res, err := f.svc.Exchange(f.ctx, f.codeRequest(code))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.AccessToken, token.AccessTokenPrefix) || res.TokenType != "Bearer" || res.ExpiresIn != 3600 ||
		res.Scope != "openid profile" || !strings.HasPrefix(res.RefreshToken, token.RefreshTokenPrefix) || res.IDToken != "" {
		t.Fatalf("response: %+v", res)
	}
	at, g, err := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if at.ClientID != "web" || at.Subject != "alice" || at.GrantID != f.grantID || !at.Valid(now) || !at.ExpiresAt.Equal(now.Add(time.Hour)) || !g.Active() {
		t.Fatalf("stored token: %+v", at)
	}
	// Web Profile は Refresh Token を発行する。Family は絶対期限 30 日、Refresh Token はスライド期限 14 日
	rt, err := f.store.LookupRefreshToken(f.ctx, rand.Hash(res.RefreshToken))
	if err != nil || rt.FamilyID != at.FamilyID || rt.Status != token.RefreshActive || !rt.ExpiresAt.Equal(now.Add(14*24*time.Hour)) {
		t.Fatalf("stored refresh token: %+v %v", rt, err)
	}
	fam, err := f.store.GetTokenFamily(f.ctx, at.FamilyID)
	if err != nil || !fam.ExpiresAt.Equal(now.Add(30*24*time.Hour)) || !fam.AuthenticatedAt.Equal(now) {
		t.Fatalf("stored family: %+v %v", fam, err)
	}
	if _, _, err := f.store.LookupAccessToken(f.ctx, res.AccessToken); err == nil {
		t.Fatal("plaintext token must not be a lookup key")
	}
}

func TestExchangePublicClient(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "cli", false)
	req := token.Request{GrantType: "authorization_code", Code: code, CodeVerifier: rfcVerifier,
		Credentials: token.Credentials{ClientID: "cli", Method: client.AuthNone}}
	// redirect_uri は認可要求で省略されていたので、トークン要求でも省略できる
	if _, err := f.svc.Exchange(f.ctx, req); err != nil {
		t.Fatal(err)
	}
}

func TestClientAuthentication(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name  string
		creds token.Credentials
	}{
		{"missing client_id", token.Credentials{}},
		{"unknown client", token.Credentials{ClientID: "nope", Secret: "x", Method: client.AuthClientSecretBasic}},
		{"wrong secret", token.Credentials{ClientID: "web", Secret: f.webSecret + "x", Method: client.AuthClientSecretBasic}},
		{"empty secret", token.Credentials{ClientID: "web", Secret: "", Method: client.AuthClientSecretBasic}},
		{"confidential without auth", token.Credentials{ClientID: "web", Method: client.AuthNone}},
		{"public with secret", token.Credentials{ClientID: "cli", Secret: "x", Method: client.AuthClientSecretPost}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := f.issueCode(t, "web", true)
			req := f.codeRequest(code)
			req.Credentials = tt.creds
			perr := wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidClient)
			if perr.HTTPStatus() != 401 {
				t.Fatalf("invalid_client must be 401, got %d", perr.HTTPStatus())
			}
			// 認証に失敗した要求は Code を消費しない
			if _, err := f.store.ConsumeAuthorizationCode(f.ctx, rand.Hash(code), now); err != nil {
				t.Fatalf("code must remain unconsumed: %v", err)
			}
		})
	}
	// client_secret_post も受理する
	code := f.issueCode(t, "web", true)
	req := f.codeRequest(code)
	req.Credentials.Method = client.AuthClientSecretPost
	if _, err := f.svc.Exchange(f.ctx, req); err != nil {
		t.Fatal(err)
	}
}

func TestGrantTypeErrors(t *testing.T) {
	f := newFixture(t)
	req := f.codeRequest(f.issueCode(t, "web", true))
	req.GrantType = ""
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidRequest)
	req.GrantType = "password"
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeUnsupportedGrantType)
	req.GrantType = "refresh_token"
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidRequest) // refresh_token パラメータなし
	// Web Profile は client_credentials を使えない
	req.GrantType = "client_credentials"
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeUnauthorizedClient)

	// Machine Profile は authorization_code を使えない
	m2m, _ := f.store.GetClient(f.ctx, "svc")
	_ = m2m
	svcClient, secret, _ := client.NewMachine(client.MachineParams{ID: "svc2", Name: "S", Scopes: []string{"api"}}, now)
	_ = f.store.CreateClient(f.ctx, svcClient)
	req = f.codeRequest(f.issueCode(t, "web", true))
	req.Credentials = token.Credentials{ClientID: "svc2", Secret: string(secret), Method: client.AuthClientSecretBasic}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeUnauthorizedClient)
}

func TestMissingParameters(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "web", true)
	req := f.codeRequest(code)
	req.Code = ""
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidRequest)
	req = f.codeRequest(code)
	req.CodeVerifier = ""
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidRequest)
	// パラメータ不足の要求は Code を消費しない
	if _, err := f.store.ConsumeAuthorizationCode(f.ctx, rand.Hash(code), now); err != nil {
		t.Fatalf("code must remain unconsumed: %v", err)
	}
}

func TestInvalidGrant(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name string
		req  func() token.Request
	}{
		{"unknown code", func() token.Request { return f.codeRequest("ac_unknown") }},
		{"code for another client", func() token.Request { return f.codeRequest(f.issueCode(t, "cli", true)) }},
		{"redirect mismatch", func() token.Request {
			r := f.codeRequest(f.issueCode(t, "web", true))
			r.RedirectURI = "https://app.example.com/other"
			return r
		}},
		{"redirect missing when required", func() token.Request {
			r := f.codeRequest(f.issueCode(t, "web", true))
			r.RedirectURI = ""
			return r
		}},
		{"redirect mismatch when optional", func() token.Request {
			r := f.codeRequest(f.issueCode(t, "web", false))
			r.RedirectURI = "https://app.example.com/other"
			return r
		}},
		{"pkce mismatch", func() token.Request {
			r := f.codeRequest(f.issueCode(t, "web", true))
			r.CodeVerifier = strings.Repeat("a", 43)
			return r
		}},
		{"malformed verifier", func() token.Request {
			r := f.codeRequest(f.issueCode(t, "web", true))
			r.CodeVerifier = "short"
			return r
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.req()
			wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidGrant)
			if req.Code != "ac_unknown" {
				// 消費後に検証が失敗した Code は戻らない（fail-closed）
				_, err := f.store.ConsumeAuthorizationCode(f.ctx, rand.Hash(req.Code), now)
				if err == nil {
					t.Fatal("code must stay consumed after a failed exchange")
				}
			}
		})
	}
}

func TestExpiredCode(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "web", true)
	f.svc.Clock = clock.NewFixed(now.Add(authorization.DefaultCodeTTL))
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.codeRequest(code))), token.CodeInvalidGrant)
}

func TestCodeReuseRevokesFamily(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "web", true)
	res, err := f.svc.Exchange(f.ctx, f.codeRequest(code))
	if err != nil {
		t.Fatal(err)
	}
	// 同じ Code の再提示（別クライアントの資格情報でも同様）
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.codeRequest(code))), token.CodeInvalidGrant)

	at, g, err := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if at.Status != token.AccessRevoked {
		t.Fatalf("token issued from a reused code must be revoked: %+v", at)
	}
	if !g.Active() {
		t.Fatal("code reuse must revoke the family, not the grant")
	}
}

func TestRevokedGrant(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "web", true)
	if err := f.store.RevokeGrant(f.ctx, f.grantID, now); err != nil {
		t.Fatal(err)
	}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.codeRequest(code))), token.CodeInvalidGrant)
}

func TestConcurrentExchange(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "web", true)
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.Exchange(f.ctx, f.codeRequest(code))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
			continue
		}
		wantProtocolErr(t, err, token.CodeInvalidGrant)
	}
	if ok != 1 {
		t.Fatalf("exactly one exchange must succeed, got %d", ok)
	}
}

// fakeIDTokens は発行要求を記録する IDTokenIssuer。
type fakeIDTokens struct {
	calls []token.IDTokenInput
}

func (f *fakeIDTokens) IssueIDToken(_ context.Context, c *client.Client, in token.IDTokenInput) (string, error) {
	f.calls = append(f.calls, in)
	return "idtoken-for-" + c.ID, nil
}

func TestIDTokenIssuedForOpenID(t *testing.T) {
	f := newFixture(t)
	fake := &fakeIDTokens{}
	f.svc.IDTokens = fake
	code := f.issueCode(t, "web", true) // scopes: openid profile
	res, err := f.svc.Exchange(f.ctx, f.codeRequest(code))
	if err != nil {
		t.Fatal(err)
	}
	if res.IDToken != "idtoken-for-web" || len(fake.calls) != 1 {
		t.Fatalf("id token not issued: %+v", res)
	}
	in := fake.calls[0]
	if in.Subject != "alice" || in.Nonce != "n" || in.AccessToken != res.AccessToken || !in.AuthenticatedAt.Equal(now) {
		t.Fatalf("id token input: %+v", in)
	}

	// openid がない Code では発行しない
	plain, _ := rand.Token("")
	fam, _ := rand.Token("")
	_ = f.store.CreateAuthorizationCode(f.ctx, &authorization.AuthorizationCode{
		Hash: rand.Hash(plain), TxnID: "t", ClientID: "web", GrantID: f.grantID, FamilyID: fam, Subject: "alice",
		RedirectURI: redirect, RedirectURIExplicit: true, Scopes: []string{"profile"},
		CodeChallenge: rfcChallenge, CodeChallengeMethod: "S256", AuthenticatedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	res, err = f.svc.Exchange(f.ctx, f.codeRequest(plain))
	if err != nil {
		t.Fatal(err)
	}
	if res.IDToken != "" || len(fake.calls) != 1 {
		t.Fatalf("id token must not be issued without openid: %+v", res)
	}

	// IDTokens が nil なら openid でも発行しない（OAuth 2.0 のみの構成）
	f.svc.IDTokens = nil
	res, err = f.svc.Exchange(f.ctx, f.codeRequest(f.issueCode(t, "web", true)))
	if err != nil || res.IDToken != "" {
		t.Fatalf("nil issuer: %+v %v", res, err)
	}
}

func mustErr(_ *token.Response, err error) error { return err }
