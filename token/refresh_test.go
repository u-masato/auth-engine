package token_test

import (
	"sync"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/token"
)

// exchangeForRefresh は Code 交換を行い、応答を返す（web は Refresh Token 付き）。
func (f *fixture) exchangeForRefresh(t *testing.T) *token.Response {
	t.Helper()
	res, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCode(t, "web", true)))
	if err != nil {
		t.Fatal(err)
	}
	if res.RefreshToken == "" {
		t.Fatal("web client must receive a refresh token")
	}
	return res
}

func (f *fixture) refreshRequest(rt, scope string) token.Request {
	return token.Request{GrantType: "refresh_token", RefreshToken: rt, Scope: scope, Credentials: f.webCreds()}
}

func TestRefreshRotation(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t)
	f.clock.Advance(time.Hour)

	res, err := f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == first.AccessToken || res.RefreshToken == first.RefreshToken || res.RefreshToken == "" ||
		res.Scope != "openid profile" || res.ExpiresIn != 3600 || res.TokenType != "Bearer" {
		t.Fatalf("refresh response: %+v", res)
	}
	// 旧 Refresh Token は rotated、後継は同じ Family で active。旧 Access Token は有効なまま
	old, _ := f.store.LookupRefreshToken(f.ctx, rand.Hash(first.RefreshToken))
	next, _ := f.store.LookupRefreshToken(f.ctx, rand.Hash(res.RefreshToken))
	if old.Status != token.RefreshRotated || old.ReplacedByHash != next.Hash || next.Status != token.RefreshActive || next.FamilyID != old.FamilyID {
		t.Fatalf("rotation: old=%+v next=%+v", old, next)
	}
	// スライド期限は最終使用から 14 日に延びる
	if !next.ExpiresAt.Equal(now.Add(time.Hour + 14*24*time.Hour)) {
		t.Fatalf("sliding expiry: %v", next.ExpiresAt)
	}
	at, _, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(first.AccessToken))
	if at.Status != token.AccessActive {
		t.Fatal("refresh must not revoke the previous access token")
	}
	newAT, _, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if newAT.FamilyID != old.FamilyID || newAT.Subject != "alice" || !newAT.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("new access token: %+v", newAT)
	}

	// 後継で続けて Rotation できる
	if _, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, "")); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshReuseRevokesFamily(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t)
	second, err := f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	// rotated なトークンの再提示 → invalid_grant、Family 全体（後継 Refresh と全 Access Token）が失効
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))), token.CodeInvalidGrant)
	next, _ := f.store.LookupRefreshToken(f.ctx, rand.Hash(second.RefreshToken))
	if next.Status != token.RefreshRevoked {
		t.Fatalf("successor must be revoked: %+v", next)
	}
	for _, at := range []string{first.AccessToken, second.AccessToken} {
		tok, g, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(at))
		if tok.Status != token.AccessRevoked {
			t.Fatalf("access token must be revoked: %+v", tok)
		}
		if !g.Active() {
			t.Fatal("refresh reuse must not revoke the grant")
		}
	}
	// 後継も使えない
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(second.RefreshToken, ""))), token.CodeInvalidGrant)
}

func TestRefreshScope(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t) // openid profile

	// 縮小は今回の Access Token にだけ効く
	res, err := f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, "profile"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Scope != "profile" || res.IDToken != "" {
		t.Fatalf("narrowed: %+v", res)
	}
	at, _, _ := f.store.LookupAccessToken(f.ctx, rand.Hash(res.AccessToken))
	if len(at.Scopes) != 1 || at.Scopes[0] != "profile" {
		t.Fatalf("narrowed token scopes: %+v", at.Scopes)
	}
	// 後継で元の scope に戻せる（Family の scope は縮小されない）
	res2, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, ""))
	if err != nil || res2.Scope != "openid profile" {
		t.Fatalf("family scope must be kept: %+v %v", res2, err)
	}
	// 拡大は invalid_scope で、Rotation は起きない
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(res2.RefreshToken, "openid email"))), token.CodeInvalidScope)
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(res2.RefreshToken, "bad\"scope"))), token.CodeInvalidScope)
	rt, _ := f.store.LookupRefreshToken(f.ctx, rand.Hash(res2.RefreshToken))
	if rt.Status != token.RefreshActive {
		t.Fatal("rejected scope must not rotate the token")
	}
}

func TestRefreshInvalid(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t)

	// 不明
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest("rt_unknown", ""))), token.CodeInvalidGrant)
	// 他の Client からの提示は拒否され、トークンは無傷
	nativeReq := token.Request{GrantType: "refresh_token", RefreshToken: first.RefreshToken, Credentials: token.Credentials{ClientID: "cli", Method: client.AuthNone}}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, nativeReq)), token.CodeInvalidGrant)
	rt, _ := f.store.LookupRefreshToken(f.ctx, rand.Hash(first.RefreshToken))
	if rt.Status != token.RefreshActive {
		t.Fatal("presenting to another client must not change the token")
	}
	// スライド期限切れ
	f.clock.Advance(14 * 24 * time.Hour)
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))), token.CodeInvalidGrant)
}

func TestRefreshAbsoluteExpiry(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t)
	// 13 日ごとに使い続けても、30 日の絶対期限で止まる
	rt := first.RefreshToken
	for day := 13; day < 30; day += 13 {
		f.clock.Set(now.Add(time.Duration(day) * 24 * time.Hour))
		res, err := f.svc.Exchange(f.ctx, f.refreshRequest(rt, ""))
		if err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
		rt = res.RefreshToken
	}
	next, _ := f.store.LookupRefreshToken(f.ctx, rand.Hash(rt))
	if !next.ExpiresAt.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("expiry must be capped at the family expiry: %v", next.ExpiresAt)
	}
	f.clock.Set(now.Add(30 * 24 * time.Hour))
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(rt, ""))), token.CodeInvalidGrant)
}

func TestRefreshAfterRevocation(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t)
	if err := f.store.RevokeGrant(f.ctx, f.grantID, now); err != nil {
		t.Fatal(err)
	}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))), token.CodeInvalidGrant)
}

func TestRefreshIssuesIDToken(t *testing.T) {
	f := newFixture(t)
	fake := &fakeIDTokens{}
	f.svc.IDTokens = fake
	first := f.exchangeForRefresh(t)
	f.clock.Advance(time.Hour)
	res, err := f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.IDToken != "idtoken-for-web" || len(fake.calls) != 2 {
		t.Fatalf("id token on refresh: %+v", res)
	}
	// OIDC Core §12.2: auth_time は元の認証、nonce は載せない
	in := fake.calls[1]
	if in.Subject != "alice" || !in.AuthenticatedAt.Equal(now) || in.Nonce != "" || in.AccessToken != res.AccessToken {
		t.Fatalf("refresh id token input: %+v", in)
	}
}

func TestNativeClientRefresh(t *testing.T) {
	f := newFixture(t)
	creds := token.Credentials{ClientID: "cli", Method: client.AuthNone}
	first, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "authorization_code", Code: f.issueCode(t, "cli", false), CodeVerifier: rfcVerifier, Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	if first.RefreshToken == "" {
		t.Fatal("native client must receive a refresh token")
	}
	if _, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "refresh_token", RefreshToken: first.RefreshToken, Credentials: creds}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRefresh(t *testing.T) {
	f := newFixture(t)
	first := f.exchangeForRefresh(t)
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.Exchange(f.ctx, f.refreshRequest(first.RefreshToken, ""))
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
		t.Fatalf("exactly one refresh must succeed, got %d", ok)
	}
	// 敗者は再利用とみなされ Family が失効している（同時提示は正規クライアントの不具合でも、安全側に倒す）
	fam, _ := f.store.GetTokenFamily(f.ctx, mustFamilyID(t, f, first.AccessToken))
	if fam.Active() {
		t.Fatal("concurrent presentation must revoke the family")
	}
}

func mustFamilyID(t *testing.T, f *fixture, accessToken string) string {
	t.Helper()
	at, _, err := f.store.LookupAccessToken(f.ctx, rand.Hash(accessToken))
	if err != nil {
		t.Fatal(err)
	}
	return at.FamilyID
}
