package e2e

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/adapters/sqlite"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/examples/standalone/loginapp"
	"github.com/muno/auth-engine/examples/standalone/oauthclient"
	"github.com/muno/auth-engine/httpapi"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/token"
)

const apiToken = "e2e-interaction-token"

// system は 1 テスト分の結合環境。
type system struct {
	t         *testing.T
	store     *sqlite.Store
	public    *httptest.Server
	internal  *httptest.Server
	login     *httptest.Server
	webSecret string

	mu  sync.Mutex
	now time.Time
}

func (s *system) clock() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *system) advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

// newSystem は SQLite・Engine・公開 / Interaction / login の 3 サーバーを起動する。
// Issuer は公開サーバーの URL なので、ハンドラは後から差し込む。
func newSystem(t *testing.T, autoApprove bool) *system {
	t.Helper()
	ctx := context.Background()
	s := &system{t: t, now: time.Now()}

	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.store = store
	t.Cleanup(func() { _ = store.Close() })

	var publicHandler, internalHandler http.Handler
	s.public = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { publicHandler.ServeHTTP(w, r) }))
	s.internal = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { internalHandler.ServeHTTP(w, r) }))
	t.Cleanup(s.public.Close)
	t.Cleanup(s.internal.Close)

	login, err := loginapp.New(loginapp.Config{InteractionAPI: s.internal.URL, APIToken: apiToken, AutoApprove: autoApprove, AutoSubject: "alice",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	s.login = httptest.NewServer(login.Handler())
	t.Cleanup(s.login.Close)

	engine, err := authengine.New(authengine.Config{
		Issuer: s.public.URL, Store: store, Now: s.clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Config{
		Engine: engine, InteractionURL: s.login.URL + "/login",
		InteractionAuth: httpapi.BearerAuthenticator{Token: apiToken},
		InsecureCookies: true, // httptest は http
	})
	if err != nil {
		t.Fatal(err)
	}
	publicHandler, internalHandler = srv.PublicHandler(), srv.InteractionHandler()

	native, err := client.NewNative(client.NativeParams{ID: "cli", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/callback"}, Scopes: []string{"openid", "profile"}}, s.now)
	if err != nil {
		t.Fatal(err)
	}
	web, secret, err := client.NewWeb(client.WebParams{ID: "web", Name: "Web", RedirectURIs: []string{"http://127.0.0.1/callback"},
		Scopes: []string{"openid", "profile", "email"}, AllowInsecureLocalhost: true}, s.now)
	if err != nil {
		t.Fatal(err)
	}
	s.webSecret = string(secret)
	for _, c := range []*client.Client{native, web} {
		if err := store.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// browser は Cookie を保持しリダイレクトを追う「ブラウザ」。
func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

// startFlow は loopback で待ち受けるクライアントのフローを作る。
// Web Profile は redirect URI を完全一致で照合するため、待ち受けポートを含む URI を登録し直す。
func (s *system) startFlow(t *testing.T, clientID, secret string, scopes []string) (*oauthclient.CodeFlow, <-chan url.Values) {
	t.Helper()
	ctx := context.Background()
	md, err := oauthclient.Discover(ctx, http.DefaultClient, s.public.URL)
	if err != nil {
		t.Fatal(err)
	}
	ln, redirectURI, err := oauthclient.ListenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := oauthclient.NewCodeFlow(md, clientID, redirectURI, scopes)
	if err != nil {
		t.Fatal(err)
	}
	flow.ClientSecret = secret
	cb := make(chan url.Values, 1)
	go func() {
		q, err := oauthclient.WaitForCallback(ctx, ln)
		if err == nil {
			cb <- q
		}
	}()
	return flow, cb
}

func waitCallback(t *testing.T, cb <-chan url.Values) url.Values {
	t.Helper()
	select {
	case q := <-cb:
		return q
	case <-time.After(10 * time.Second):
		t.Fatal("callback did not arrive")
		return nil
	}
}

func TestNativeClientAutoApprove(t *testing.T) {
	s := newSystem(t, true)
	flow, cb := s.startFlow(t, "cli", "", []string{"openid", "profile"})

	// ブラウザが authorize → login（自動承認）→ resume → callback と遷移する
	res, err := browser(t).Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasSuffix(res.Request.URL.Path, "/callback") {
		t.Fatalf("browser ended at %s (%d)", res.Request.URL, res.StatusCode)
	}

	code, err := flow.HandleCallback(waitCallback(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := flow.Exchange(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if tok.TokenType != "Bearer" || tok.ExpiresIn != 3600 || tok.Scope != "openid profile" || !strings.HasPrefix(tok.AccessToken, "at_") {
		t.Fatalf("token: %+v", tok)
	}

	// SQLite に Grant と Access Token が残っている
	at, g, err := s.store.LookupAccessToken(context.Background(), rand.Hash(tok.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if at.Subject != "alice" || at.ClientID != "cli" || !g.Active() || g.Claims["email"] != "alice@example.com" {
		t.Fatalf("stored: token=%+v grant=%+v", at, g)
	}

	// Code の再利用は拒否され、発行済みトークンは失効する
	_, err = flow.Exchange(context.Background(), code)
	var terr *oauthclient.TokenError
	if !errors.As(err, &terr) || terr.Code != "invalid_grant" {
		t.Fatalf("reuse: %v", err)
	}
	at, _, _ = s.store.LookupAccessToken(context.Background(), rand.Hash(tok.AccessToken))
	if at.Status != token.AccessRevoked {
		t.Fatal("token from reused code must be revoked")
	}
}

func TestWebClientWithLoginForm(t *testing.T) {
	s := newSystem(t, false)
	flow, cb := s.startFlow(t, "web", s.webSecret, []string{"openid", "email"})
	// Web Profile は完全一致なので、待ち受けポート込みの URI を登録する
	registerRedirect(t, s, "web", flow.RedirectURI)

	b := browser(t)
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	// ブラウザはログイン画面で止まる
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in to Web") || !strings.Contains(string(body), "email") {
		t.Fatalf("login form: %d %s %s", res.StatusCode, res.Request.URL, body)
	}
	txnID := res.Request.URL.Query().Get("txn")
	if txnID == "" {
		t.Fatalf("login url must carry txn: %s", res.Request.URL)
	}

	// ユーザーが openid だけ承認する
	form := url.Values{"txn": {txnID}, "username": {"bob"}, "action": {"approve"}, "scope": {"openid"}}
	res, err = b.PostForm(s.login.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.HasSuffix(res.Request.URL.Path, "/callback") {
		t.Fatalf("browser ended at %s", res.Request.URL)
	}
	code, err := flow.HandleCallback(waitCallback(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := flow.Exchange(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Scope != "openid" {
		t.Fatalf("granted scope must be what the user approved: %+v", tok)
	}
	at, _, err := s.store.LookupAccessToken(context.Background(), rand.Hash(tok.AccessToken))
	if err != nil || at.Subject != "bob" {
		t.Fatalf("stored token: %+v %v", at, err)
	}
}

func TestUserDenies(t *testing.T) {
	s := newSystem(t, false)
	flow, cb := s.startFlow(t, "cli", "", []string{"openid"})
	b := browser(t)
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	txnID := res.Request.URL.Query().Get("txn")
	res, err = b.PostForm(s.login.URL+"/login", url.Values{"txn": {txnID}, "username": {"alice"}, "action": {"deny"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	_, err = flow.HandleCallback(waitCallback(t, cb))
	var aerr *oauthclient.AuthorizationError
	if !errors.As(err, &aerr) || aerr.Code != "access_denied" {
		t.Fatalf("deny: %v", err)
	}
	if _, err := s.store.FindGrant(context.Background(), "cli", "alice"); err == nil {
		t.Fatal("denied request must not create a grant")
	}
}

func TestResumeFromAnotherBrowserIsDenied(t *testing.T) {
	s := newSystem(t, false)
	flow, _ := s.startFlow(t, "cli", "", []string{"openid"})
	b := browser(t)
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	txnID := res.Request.URL.Query().Get("txn")

	// 承認は正規のブラウザで行うが、Resume URL へは Cookie を持たない別ブラウザが向かう
	noRedirect := &http.Client{Jar: b.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err = noRedirect.PostForm(s.login.URL+"/login", url.Values{"txn": {txnID}, "username": {"alice"}, "action": {"approve"}, "scope": {"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	resumeURL := res.Header.Get("Location")
	if !strings.Contains(resumeURL, "/authorize/resume?") {
		t.Fatalf("login app must redirect to resume url, got %q", resumeURL)
	}

	other := browser(t)
	res, err = other.Get(resumeURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "resume_denied") {
		t.Fatalf("other browser: %d %s", res.StatusCode, body)
	}
	// 正規のブラウザなら通る
	res, err = b.Get(resumeURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.HasSuffix(res.Request.URL.Path, "/callback") {
		t.Fatalf("legit browser ended at %s", res.Request.URL)
	}
}

func TestExpiredTransaction(t *testing.T) {
	s := newSystem(t, false)
	flow, _ := s.startFlow(t, "cli", "", []string{"openid"})
	b := browser(t)
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	txnID := res.Request.URL.Query().Get("txn")

	s.advance(time.Hour)
	res, err = b.PostForm(s.login.URL+"/login", url.Values{"txn": {txnID}, "username": {"alice"}, "action": {"approve"}, "scope": {"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	// Interaction API が 410 を返し、login app はそれをユーザーに伝える
	if res.StatusCode != http.StatusGone || !strings.Contains(string(body), "expired") {
		t.Fatalf("expired: %d %s", res.StatusCode, body)
	}
}

func TestMetadataAndDiscovery(t *testing.T) {
	s := newSystem(t, true)
	md, err := oauthclient.Discover(context.Background(), http.DefaultClient, s.public.URL)
	if err != nil {
		t.Fatal(err)
	}
	if md.AuthorizationEndpoint != s.public.URL+"/authorize" || md.TokenEndpoint != s.public.URL+"/token" {
		t.Fatalf("metadata: %+v", md)
	}
}

// registerRedirect は Web クライアントの redirect URI を差し替える（完全一致照合のため）。
func registerRedirect(t *testing.T, s *system, clientID, redirectURI string) {
	t.Helper()
	ctx := context.Background()
	c, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	// Store に更新操作はない（M1 では登録のみ）ので、SQL で直接書き換える。
	if _, err := s.store.DB().ExecContext(ctx, `UPDATE clients SET redirect_uris = ? WHERE id = ?`, `["`+redirectURI+`"]`, c.ID); err != nil {
		t.Fatal(err)
	}
}
