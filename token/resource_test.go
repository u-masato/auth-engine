package token_test

import (
	"slices"
	"testing"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/token"
)

const (
	apiRes   = "https://api.example.com"
	mcpRes   = "https://mcp.example.com"
	jwtRes   = "https://jwt.example.com"
	filesRes = "https://files.example.com"
)

// withResources は fixture に Resource Server の設定を与える。
func (f *fixture) withResources(t *testing.T, rs ...resource.Resource) {
	t.Helper()
	if rs == nil {
		rs = []resource.Resource{
			{URI: apiRes},
			{URI: mcpRes},
			{URI: jwtRes, AccessTokenFormat: resource.FormatJWT},
			{URI: filesRes, Scopes: []string{"files:read"}},
		}
	}
	set, err := resource.NewSet(rs)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Resources = set
}

func (f *fixture) lookupAccess(t *testing.T, plain string) *token.AccessToken {
	t.Helper()
	at, _, err := f.store.LookupAccessToken(f.ctx, rand.Hash(plain))
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestExchangeAudience(t *testing.T) {
	f := newFixture(t)
	f.withResources(t)
	scopes := []string{"openid", "profile"}

	// resource 未指定: Code の resource 全部が Family と Access Token の Audience になる
	res, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, scopes, []string{apiRes, mcpRes})))
	if err != nil {
		t.Fatal(err)
	}
	at := f.lookupAccess(t, res.AccessToken)
	fam, _ := f.store.GetTokenFamily(f.ctx, at.FamilyID)
	if !slices.Equal(at.Audience, []string{apiRes, mcpRes}) || !slices.Equal(fam.Audience, []string{apiRes, mcpRes}) {
		t.Fatalf("audience: token=%v family=%v", at.Audience, fam.Audience)
	}
	in, _ := f.svc.Inspect(f.ctx, res.AccessToken, "")
	if !in.Active || !slices.Equal(in.Audience, []string{apiRes, mcpRes}) {
		t.Fatalf("introspection audience: %+v", in)
	}
	rtIn, _ := f.svc.Inspect(f.ctx, res.RefreshToken, token.HintRefreshToken)
	if !rtIn.Active || !slices.Equal(rtIn.Audience, []string{apiRes, mcpRes}) {
		t.Fatalf("refresh introspection audience must be the family's: %+v", rtIn)
	}

	// resource 指定: Access Token だけ絞られ、Family は全部を保つ。host の大文字は正規化される
	req := f.codeRequest(f.issueCodeFor(t, "web", true, scopes, []string{apiRes, mcpRes}))
	req.Resource = []string{"https://API.example.com"}
	res, err = f.svc.Exchange(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	at = f.lookupAccess(t, res.AccessToken)
	fam, _ = f.store.GetTokenFamily(f.ctx, at.FamilyID)
	if !slices.Equal(at.Audience, []string{apiRes}) || !slices.Equal(fam.Audience, []string{apiRes, mcpRes}) {
		t.Fatalf("narrowed audience: token=%v family=%v", at.Audience, fam.Audience)
	}

	// Refresh: 未指定なら Family の全部、指定なら部分集合。範囲外・不明は invalid_target
	refreshed, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	if at := f.lookupAccess(t, refreshed.AccessToken); !slices.Equal(at.Audience, []string{apiRes, mcpRes}) {
		t.Fatalf("refresh without resource: %v", at.Audience)
	}
	rreq := f.refreshRequest(refreshed.RefreshToken, "")
	rreq.Resource = []string{mcpRes}
	refreshed, err = f.svc.Exchange(f.ctx, rreq)
	if err != nil {
		t.Fatal(err)
	}
	if at := f.lookupAccess(t, refreshed.AccessToken); !slices.Equal(at.Audience, []string{mcpRes}) {
		t.Fatalf("refresh narrowed to mcp: %v", at.Audience)
	}
	for _, bad := range [][]string{{jwtRes}, {"https://unknown.example.com"}, {"not a uri"}, {apiRes, jwtRes}} {
		rreq = f.refreshRequest(refreshed.RefreshToken, "")
		rreq.Resource = bad
		wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, rreq)), token.CodeInvalidTarget)
	}
	// 失敗した要求は Rotation していないので、同じ Refresh Token で続けられる
	if _, err := f.svc.Exchange(f.ctx, f.refreshRequest(refreshed.RefreshToken, "")); err != nil {
		t.Fatalf("refresh token must survive a rejected resource request: %v", err)
	}

	// resource なしの Code は従来どおり Audience なし
	res, err = f.svc.Exchange(f.ctx, f.codeRequest(f.issueCode(t, "web", true)))
	if err != nil {
		t.Fatal(err)
	}
	if at := f.lookupAccess(t, res.AccessToken); len(at.Audience) != 0 {
		t.Fatalf("code without resource must yield no audience: %v", at.Audience)
	}
	// resource なしの Code に resource を要求するのは範囲外
	req = f.codeRequest(f.issueCode(t, "web", true))
	req.Resource = []string{apiRes}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidTarget)
}

func TestExchangeAudienceErrors(t *testing.T) {
	f := newFixture(t)
	f.withResources(t)
	scopes := []string{"openid", "profile"}

	// 認可されていない resource
	req := f.codeRequest(f.issueCodeFor(t, "web", true, scopes, []string{apiRes}))
	req.Resource = []string{mcpRes}
	perr := wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidTarget)
	if perr.Description == "" {
		t.Fatal("description must name the rejected resource")
	}
	// Code は消費済みなので、同じ Code の再提示は invalid_grant（fail-closed）
	req.Resource = nil
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, req)), token.CodeInvalidGrant)

	// 設定から外された resource を持つ Code は、未指定でも invalid_target
	f.withResources(t, resource.Resource{URI: mcpRes})
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, scopes, []string{apiRes})))), token.CodeInvalidTarget)

	// Resources 未設定（nil）の Service でも resource 付き Code は invalid_target
	f.svc.Resources = nil
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, scopes, []string{apiRes})))), token.CodeInvalidTarget)
	// resource なしの Code は Resources 未設定でも通る
	if _, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCode(t, "web", true))); err != nil {
		t.Fatal(err)
	}

	// resource ごとの scope 上限（設定変更で認可時より狭くなった場合）
	f.withResources(t)
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, []string{"openid", "files:write"}, []string{filesRes})))), token.CodeInvalidScope)
	if _, err := f.svc.Exchange(f.ctx, f.codeRequest(f.issueCodeFor(t, "web", true, []string{"openid", "files:read"}, []string{filesRes}))); err != nil {
		t.Fatalf("scope within the resource limit: %v", err)
	}
}

func TestClientCredentialsAudience(t *testing.T) {
	f := newFixture(t)
	f.withResources(t)
	// limited は api だけ、open は全 resource を要求できる
	limited, limitedSecret, err := client.NewMachine(client.MachineParams{ID: "limited", Name: "Limited", Scopes: []string{"api:read"}, Resources: []string{apiRes}}, now)
	if err != nil {
		t.Fatal(err)
	}
	open, openSecret, err := client.NewMachine(client.MachineParams{ID: "open", Name: "Open", Scopes: []string{"api:read", "files:read"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*client.Client{limited, open} {
		if err := f.store.CreateClient(f.ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	limitedCreds := token.Credentials{ClientID: "limited", Secret: string(limitedSecret), Method: client.AuthClientSecretBasic}
	openCreds := token.Credentials{ClientID: "open", Secret: string(openSecret), Method: client.AuthClientSecretBasic}
	cc := func(creds token.Credentials, scope string, res ...string) (*token.Response, error) {
		return f.svc.Exchange(f.ctx, token.Request{GrantType: "client_credentials", Scope: scope, Resource: res, Credentials: creds})
	}

	// 未指定なら Audience なし
	res, err := cc(limitedCreds, "")
	if err != nil {
		t.Fatal(err)
	}
	if at := f.lookupAccess(t, res.AccessToken); len(at.Audience) != 0 {
		t.Fatalf("no resource must mean no audience: %v", at.Audience)
	}
	// 許可範囲内: Family と Access Token の Audience に載る
	res, err = cc(limitedCreds, "", "https://API.example.com")
	if err != nil {
		t.Fatal(err)
	}
	at := f.lookupAccess(t, res.AccessToken)
	fam, _ := f.store.GetTokenFamily(f.ctx, at.FamilyID)
	if !slices.Equal(at.Audience, []string{apiRes}) || !slices.Equal(fam.Audience, []string{apiRes}) {
		t.Fatalf("m2m audience: token=%v family=%v", at.Audience, fam.Audience)
	}
	// Client の許可範囲外、不明、形式の混在は invalid_target
	wantProtocolErr(t, mustErr(cc(limitedCreds, "", mcpRes)), token.CodeInvalidTarget)
	wantProtocolErr(t, mustErr(cc(openCreds, "", "https://unknown.example.com")), token.CodeInvalidTarget)
	wantProtocolErr(t, mustErr(cc(openCreds, "", apiRes, jwtRes)), token.CodeInvalidTarget)
	// 制限のない Client はどの resource でも要求できる
	res, err = cc(openCreds, "", mcpRes, apiRes)
	if err != nil {
		t.Fatal(err)
	}
	if at := f.lookupAccess(t, res.AccessToken); !slices.Equal(at.Audience, []string{mcpRes, apiRes}) {
		t.Fatalf("open client audience: %v", at.Audience)
	}
	// resource ごとの scope 上限
	if _, err := cc(openCreds, "files:read", filesRes); err != nil {
		t.Fatalf("scope within the resource limit: %v", err)
	}
	wantProtocolErr(t, mustErr(cc(openCreds, "api:read", filesRes)), token.CodeInvalidScope)
	wantProtocolErr(t, mustErr(cc(openCreds, "", filesRes)), token.CodeInvalidScope) // 未指定 = Client の全 scope に api:read が含まれる
}
