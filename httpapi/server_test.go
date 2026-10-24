package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/httpapi"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/oidc"
	"github.com/muno/auth-engine/storage/memory"
	"github.com/muno/auth-engine/token"
)

const (
	issuer       = "https://as.example.com"
	interaction  = "https://login.example.com/login?ui=v2"
	apiToken     = "interaction-api-secret"
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	redirectURI  = "https://app.example.com/cb"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type env struct {
	t         *testing.T
	store     *memory.Store
	keys      *keys.Set
	public    http.Handler
	internal  http.Handler
	webSecret string
	now       time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, store: memory.New(), now: now}
	web, secret, err := client.NewWeb(client.WebParams{ID: "web", Name: "Web App", RedirectURIs: []string{redirectURI},
		Scopes: []string{"openid", "profile"}, LogoURI: "https://app.example.com/logo.png"}, now)
	if err != nil {
		t.Fatal(err)
	}
	native, err := client.NewNative(client.NativeParams{ID: "cli", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*client.Client{web, native} {
		if err := e.store.CreateClient(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	e.webSecret = string(secret)
	e.keys = keys.NewSet()
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		k, err := keys.Generate(alg, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.keys.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := authengine.New(authengine.Config{
		Issuer: issuer, Store: e.store, Keys: e.keys, Now: func() time.Time { return e.now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Config{Engine: engine, InteractionURL: interaction, InteractionAuth: httpapi.BearerAuthenticator{Token: apiToken}})
	if err != nil {
		t.Fatal(err)
	}
	e.public, e.internal = srv.PublicHandler(), srv.InteractionHandler()
	return e
}

func (e *env) do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func authorizeQuery() url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {"web"}, "redirect_uri": {redirectURI}, "scope": {"openid profile"},
		"state": {"xyz"}, "code_challenge": {rfcChallenge}, "code_challenge_method": {"S256"}, "nonce": {"n1"}, "max_age": {"600"},
	}
}

// authorize は /authorize を呼び、結合 Cookie と Txn ID を返す。
func (e *env) authorize(q url.Values) (cookie *http.Cookie, txnID string, rec *httptest.ResponseRecorder) {
	e.t.Helper()
	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		e.t.Fatalf("authorize: status %d body %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-ae_bind" {
			cookie = c
		}
	}
	return cookie, loc.Query().Get("txn"), rec
}

func (e *env) interactionReq(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (e *env) complete(txnID string) string {
	e.t.Helper()
	rec := e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{
		"subject": "alice", "authenticated_at": now.Add(-time.Minute).Format(time.RFC3339), "granted_scopes": []string{"openid", "profile"},
		"amr": []string{"pwd"}, "claims": map[string]any{"name": "Alice"},
	}))
	if rec.Code != http.StatusOK {
		e.t.Fatalf("complete: status %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		ResumeURL string `json:"resume_url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ResumeURL
}

func (e *env) resume(resumeURL string, cookie *http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	u, err := url.Parse(resumeURL)
	if err != nil {
		e.t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return e.do(e.public, req)
}

func (e *env) tokenReq(form url.Values, basicID, basicSecret string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	return req
}

func TestFullAuthorizationCodeFlow(t *testing.T) {
	e := newEnv(t)

	// (1)(2) /authorize → Interaction App へ 302、結合 Cookie 発行
	cookie, txnID, rec := e.authorize(authorizeQuery())
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("binding cookie: %+v", cookie)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Scheme != "https" || loc.Host != "login.example.com" || loc.Path != "/login" || loc.Query().Get("ui") != "v2" || txnID == "" {
		t.Fatalf("interaction redirect: %s", loc)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("redirects must be no-store")
	}

	// (4) Interaction App が Txn を参照
	rec = e.do(e.internal, e.interactionReq(http.MethodGet, "/transactions/"+txnID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get txn: %d %s", rec.Code, rec.Body)
	}
	var view map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view["status"] != "pending" || view["client"].(map[string]any)["name"] != "Web App" || view["request"].(map[string]any)["max_age"] != float64(600) {
		t.Fatalf("txn view: %s", rec.Body)
	}
	if _, leaked := view["request"].(map[string]any)["code_challenge"]; leaked {
		t.Fatal("txn view must not expose code_challenge")
	}
	if _, leaked := view["request"].(map[string]any)["state"]; leaked {
		t.Fatal("txn view must not expose state")
	}

	// (5) Complete → resume_url
	resumeURL := e.complete(txnID)
	ru, _ := url.Parse(resumeURL)
	if ru.Host != "as.example.com" || ru.Path != "/authorize/resume" || ru.Query().Get("txn") != txnID || !strings.HasPrefix(ru.Query().Get("token"), "rs_") {
		t.Fatalf("resume url: %s", resumeURL)
	}

	// (7)(8) Resume → Client へ code
	rec = e.resume(resumeURL, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("resume: %d %s", rec.Code, rec.Body)
	}
	cb, _ := url.Parse(rec.Header().Get("Location"))
	code := cb.Query().Get("code")
	if cb.Host != "app.example.com" || code == "" || cb.Query().Get("state") != "xyz" || cb.Query().Get("iss") != issuer {
		t.Fatalf("client redirect: %s", cb)
	}

	// /token（client_secret_basic）
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {rfcVerifier}}
	rec = e.do(e.public, e.tokenReq(form, "web", e.webSecret))
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("token headers: %v", rec.Header())
	}
	var res token.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !strings.HasPrefix(res.AccessToken, "at_") || res.TokenType != "Bearer" || res.ExpiresIn != 3600 || res.Scope != "openid profile" {
		t.Fatalf("token response: %s", rec.Body)
	}
	// openid が付与されたので ID Token が付き、/jwks の鍵で検証できる（OIDC Core §3.1.3.3, §3.1.3.7）
	if res.IDToken == "" {
		t.Fatal("id_token must be issued for openid scope")
	}
	var idc struct {
		Iss      string   `json:"iss"`
		Sub      string   `json:"sub"`
		Aud      []string `json:"aud"`
		Nonce    string   `json:"nonce"`
		ATHash   string   `json:"at_hash"`
		AuthTime int64    `json:"auth_time"`
		Exp      int64    `json:"exp"`
		AMR      []string `json:"amr"`
	}
	h, err := e.keys.Verify(res.IDToken, &idc)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, _ := oidc.AccessTokenHash(h.Alg, res.AccessToken)
	if h.Alg != "RS256" || idc.Iss != issuer || idc.Sub != "alice" || len(idc.Aud) != 1 || idc.Aud[0] != "web" || idc.Nonce != "n1" ||
		idc.ATHash != wantHash || idc.AuthTime != now.Add(-time.Minute).Unix() || idc.Exp != now.Add(time.Hour).Unix() || len(idc.AMR) != 1 {
		t.Fatalf("id token claims: %+v", idc)
	}
	at, g, err := e.store.LookupAccessToken(context.Background(), rand.Hash(res.AccessToken))
	if err != nil || at.Subject != "alice" || !g.Active() {
		t.Fatalf("stored token: %+v %v", at, err)
	}

	// /userinfo: Access Token で Grant の Claims を scope で絞って返す（OIDC Core §5.3）
	ureq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	ureq.Header.Set("Authorization", "bearer "+res.AccessToken) // スキームは大文字小文字を区別しない
	rec = e.do(e.public, ureq)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", rec.Code, rec.Body)
	}
	var ui map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ui)
	if ui["sub"] != "alice" || ui["name"] != "Alice" {
		t.Fatalf("userinfo claims: %s", rec.Body)
	}
	// POST フォームでも受ける
	ureq = httptest.NewRequest(http.MethodPost, "/userinfo", strings.NewReader(url.Values{"access_token": {res.AccessToken}}.Encode()))
	ureq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec = e.do(e.public, ureq); rec.Code != http.StatusOK {
		t.Fatalf("userinfo POST: %d %s", rec.Code, rec.Body)
	}

	// Code の再利用は invalid_grant、発行済みトークンは失効
	rec = e.do(e.public, e.tokenReq(form, "web", e.webSecret))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_grant"`) {
		t.Fatalf("code reuse: %d %s", rec.Code, rec.Body)
	}
	at, _, _ = e.store.LookupAccessToken(context.Background(), rand.Hash(res.AccessToken))
	if at.Status != token.AccessRevoked {
		t.Fatal("token from reused code must be revoked")
	}
	// 失効したトークンでの /userinfo は 401 invalid_token（RFC 6750 §3.1）
	ureq = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	ureq.Header.Set("Authorization", "Bearer "+res.AccessToken)
	rec = e.do(e.public, ureq)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("userinfo revoked: %d %v", rec.Code, rec.Header())
	}
}

func TestUserInfoErrors(t *testing.T) {
	e := newEnv(t)
	// 認証情報なし: 401、WWW-Authenticate に error なし
	rec := e.do(e.public, httptest.NewRequest(http.MethodGet, "/userinfo", nil))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer realm="userinfo"` {
		t.Fatalf("no credentials: %d %v", rec.Code, rec.Header())
	}
	// 不明なトークン
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer at_nope")
	rec = e.do(e.public, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("unknown token: %d %v", rec.Code, rec.Header())
	}
	// ヘッダとフォームの両方
	req = httptest.NewRequest(http.MethodPost, "/userinfo", strings.NewReader("access_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer y")
	rec = e.do(e.public, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("both: %d", rec.Code)
	}
	// openid なしのトークン → 403 insufficient_scope
	cookie, txnID, _ := e.authorize(func() url.Values { q := authorizeQuery(); q.Set("scope", "profile"); return q }())
	rec = e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{
		"subject": "alice", "authenticated_at": now.Format(time.RFC3339), "granted_scopes": []string{"profile"}}))
	var out struct {
		ResumeURL string `json:"resume_url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	rec = e.resume(out.ResumeURL, cookie)
	cb, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {rfcVerifier}}
	rec = e.do(e.public, e.tokenReq(form, "web", e.webSecret))
	var res token.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.IDToken != "" {
		t.Fatal("no id_token without openid")
	}
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+res.AccessToken)
	rec = e.do(e.public, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatalf("no openid: %d %v", rec.Code, rec.Header())
	}
}

func TestAuthorizeErrors(t *testing.T) {
	e := newEnv(t)

	// client_id 不明: リダイレクトせずエラーページ（400、HTML）
	q := authorizeQuery()
	q.Set("client_id", "nope")
	rec := e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("unknown client: %d %s", rec.Code, rec.Body)
	}
	// redirect_uri 不一致: 同様
	q = authorizeQuery()
	q.Set("redirect_uri", "https://evil.example.com/cb")
	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("bad redirect: %d", rec.Code)
	}
	// PKCE なし: Client へエラーリダイレクト
	q = authorizeQuery()
	q.Del("code_challenge")
	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Host != "app.example.com" || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "xyz" || loc.Query().Get("iss") != issuer {
		t.Fatalf("pkce missing: %d %s", rec.Code, loc)
	}
	// POST フォームでも受ける
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(authorizeQuery().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = e.do(e.public, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://login.example.com/") {
		t.Fatalf("POST authorize: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// 他メソッドは 405
	rec = e.do(e.public, httptest.NewRequest(http.MethodDelete, "/authorize", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE authorize: %d", rec.Code)
	}
}

func TestBindingCookieIsReused(t *testing.T) {
	e := newEnv(t)
	cookie, _, _ := e.authorize(authorizeQuery())
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+authorizeQuery().Encode(), nil)
	req.AddCookie(cookie)
	rec := e.do(e.public, req)
	if rec.Code != http.StatusFound || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("existing cookie must be reused, not reissued: %d %v", rec.Code, rec.Result().Cookies())
	}
}

func TestResumeErrors(t *testing.T) {
	e := newEnv(t)
	cookie, txnID, _ := e.authorize(authorizeQuery())
	resumeURL := e.complete(txnID)

	// 別ブラウザ（Cookie なし）→ 400 エラーページ、Txn は消費されない
	rec := e.resume(resumeURL, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "resume_denied") {
		t.Fatalf("no cookie: %d %s", rec.Code, rec.Body)
	}
	// 誤ったトークン
	rec = e.resume(strings.Replace(resumeURL, "token=rs_", "token=rs_x", 1), cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	// パラメータ不足
	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize/resume?txn="+txnID, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing token: %d", rec.Code)
	}
	// 未知の Txn → 404
	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize/resume?txn=nope&token=rs_x", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown txn: %d", rec.Code)
	}
	// 正しい要求はまだ通る（拒否された試行で消費されていない）
	rec = e.resume(resumeURL, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("valid resume after denied attempts: %d %s", rec.Code, rec.Body)
	}
	// 再利用 → 400
	rec = e.resume(resumeURL, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("resume reuse: %d", rec.Code)
	}
	// 期限切れ → 410
	_, txn2, _ := e.authorize(authorizeQuery())
	resume2 := e.complete(txn2)
	e.now = now.Add(time.Hour)
	rec = e.resume(resume2, cookie)
	if rec.Code != http.StatusGone {
		t.Fatalf("expired: %d", rec.Code)
	}
}

func TestRejectFlow(t *testing.T) {
	e := newEnv(t)
	cookie, txnID, _ := e.authorize(authorizeQuery())
	rec := e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/reject", map[string]any{"error": "access_denied", "error_description": "no"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ResumeURL string `json:"resume_url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	rec = e.resume(out.ResumeURL, cookie)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Host != "app.example.com" || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "xyz" || loc.Query().Has("code") {
		t.Fatalf("reject redirect: %d %s", rec.Code, loc)
	}
}

func TestInteractionAPIErrors(t *testing.T) {
	e := newEnv(t)
	_, txnID, _ := e.authorize(authorizeQuery())

	// 認証なし / 誤トークン → 401 + WWW-Authenticate
	for _, auth := range []string{"", "Bearer wrong", "Basic abc"} {
		req := httptest.NewRequest(http.MethodGet, "/transactions/"+txnID, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := e.do(e.internal, req)
		if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("auth %q: %d", auth, rec.Code)
		}
	}
	// 未知 → 404
	rec := e.do(e.internal, e.interactionReq(http.MethodGet, "/transactions/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rec.Code)
	}
	// 不正な本文（未知フィールド）→ 400 invalid_body
	rec = e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{"subject": "a", "bogus": 1}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_body") {
		t.Fatalf("unknown field: %d %s", rec.Code, rec.Body)
	}
	// 契約違反（scope 超過）→ 400 invalid_outcome
	rec = e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{
		"subject": "alice", "authenticated_at": now.Format(time.RFC3339), "granted_scopes": []string{"openid", "email"}}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_outcome") {
		t.Fatalf("scope superset: %d %s", rec.Code, rec.Body)
	}
	// 不正な reject コード → 400
	rec = e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/reject", map[string]any{"error": "nope"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad reject code: %d", rec.Code)
	}
	// 完了後の再 Complete → 409
	e.complete(txnID)
	rec = e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{
		"subject": "alice", "authenticated_at": now.Format(time.RFC3339), "granted_scopes": []string{"openid"}}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("double complete: %d %s", rec.Code, rec.Body)
	}
	// 完了後の参照は outcome を含む
	rec = e.do(e.internal, e.interactionReq(http.MethodGet, "/transactions/"+txnID, nil))
	if !strings.Contains(rec.Body.String(), `"status":"completed"`) || !strings.Contains(rec.Body.String(), `"subject":"alice"`) {
		t.Fatalf("completed view: %s", rec.Body)
	}
	// 期限切れ → 410
	e.now = now.Add(time.Hour)
	rec = e.do(e.internal, e.interactionReq(http.MethodGet, "/transactions/"+txnID, nil))
	if rec.Code != http.StatusGone {
		t.Fatalf("expired view: %d", rec.Code)
	}
}

func TestTokenEndpointClientAuth(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "code_verifier": {rfcVerifier}}

	// Basic + form client_secret の併用 → invalid_request
	f2 := url.Values{}
	for k, v := range form {
		f2[k] = v
	}
	f2.Set("client_secret", "s")
	rec := e.do(e.public, e.tokenReq(f2, "web", e.webSecret))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("multiple auth methods: %d %s", rec.Code, rec.Body)
	}
	// 誤ったシークレット（Basic）→ 401 + WWW-Authenticate: Basic
	rec = e.do(e.public, e.tokenReq(form, "web", "wrong"))
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic") || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("wrong secret: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	// client_secret_post でも 401 だが WWW-Authenticate は付かない
	f3 := url.Values{}
	for k, v := range form {
		f3[k] = v
	}
	f3.Set("client_id", "web")
	f3.Set("client_secret", "wrong")
	rec = e.do(e.public, e.tokenReq(f3, "", ""))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("post wrong secret: %d %v", rec.Code, rec.Header())
	}
	// Basic の user と form の client_id が食い違う → invalid_request
	f4 := url.Values{}
	for k, v := range form {
		f4[k] = v
	}
	f4.Set("client_id", "cli")
	rec = e.do(e.public, e.tokenReq(f4, "web", e.webSecret))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched client_id: %d %s", rec.Code, rec.Body)
	}
	// public クライアント: client_id のみ。Code 不明なので invalid_grant（認証は通っている）
	f5 := url.Values{}
	for k, v := range form {
		f5[k] = v
	}
	f5.Set("client_id", "cli")
	rec = e.do(e.public, e.tokenReq(f5, "", ""))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("public client: %d %s", rec.Code, rec.Body)
	}
	// GET は 405
	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/token", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET token: %d", rec.Code)
	}
}

func TestBasicCredentialsAreFormDecoded(t *testing.T) {
	// RFC 6749 §2.3.1: client_id / client_secret は form-urlencoded してから Basic にする。
	// ':' を含む client_id は素の Basic では表現できないが、エンコードすれば通る。
	e := newEnv(t)
	c, secret, err := client.NewWeb(client.WebParams{ID: "id:colon", Name: "X", RedirectURIs: []string{redirectURI}, Scopes: []string{"openid"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateClient(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "code_verifier": {rfcVerifier}}
	rec := e.do(e.public, e.tokenReq(form, "id:colon", string(secret)))
	// 認証は通り、Code 不明で invalid_grant になる
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("encoded basic: %d %s", rec.Code, rec.Body)
	}
}

func TestJWKSAndOpenIDConfiguration(t *testing.T) {
	e := newEnv(t)
	rec := e.do(e.public, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("jwks: %d %v", rec.Code, rec.Header())
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil || len(jwks.Keys) != 2 {
		t.Fatalf("jwks body: %s %v", rec.Body, err)
	}
	if strings.Contains(rec.Body.String(), `"d":`) {
		t.Fatal("jwks must not contain private keys")
	}

	rec = e.do(e.public, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("openid-configuration: %d", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["issuer"] != issuer || m["jwks_uri"] != issuer+"/jwks" || m["userinfo_endpoint"] != issuer+"/userinfo" ||
		m["claims_parameter_supported"] != false || m["request_parameter_supported"] != false {
		t.Fatalf("openid-configuration body: %s", rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`"subject_types_supported":["public"]`, `"id_token_signing_alg_values_supported":["RS256","ES256"]`,
		`"scopes_supported":["openid","profile","email","address","phone"]`, `"email_verified"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
}

func TestMetadata(t *testing.T) {
	e := newEnv(t)
	rec := e.do(e.public, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata: %d", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["issuer"] != issuer || m["authorization_endpoint"] != issuer+"/authorize" || m["token_endpoint"] != issuer+"/token" ||
		m["jwks_uri"] != issuer+"/jwks" || m["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("metadata body: %s", rec.Body)
	}
	if _, oidcOnly := m["subject_types_supported"]; oidcOnly {
		t.Fatal("oauth-authorization-server must not carry OIDC-only fields")
	}
	if !strings.Contains(rec.Body.String(), `"code_challenge_methods_supported":["S256"]`) {
		t.Fatalf("pkce methods: %s", rec.Body)
	}
}

func TestConfigValidation(t *testing.T) {
	ks := keys.NewSet()
	k, _ := keys.Generate(keys.AlgRS256, now)
	_ = ks.AddSigning(k)
	engine, _ := authengine.New(authengine.Config{Issuer: issuer, Store: memory.New(), Keys: ks})
	bad := []httpapi.Config{
		{InteractionURL: interaction, InteractionAuth: httpapi.BearerAuthenticator{Token: "x"}},
		{Engine: engine, InteractionURL: "/relative", InteractionAuth: httpapi.BearerAuthenticator{Token: "x"}},
		{Engine: engine, InteractionURL: interaction},
	}
	for i, cfg := range bad {
		if _, err := httpapi.New(cfg); err == nil {
			t.Errorf("config %d must be rejected", i)
		}
	}
	// 空トークンの BearerAuthenticator は何も通さない
	if (httpapi.BearerAuthenticator{}).Authenticate(httptest.NewRequest("GET", "/", nil)) == nil {
		t.Error("empty bearer token must reject")
	}
}
