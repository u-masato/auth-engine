package console_test

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/examples/standalone/console"
	"github.com/muno/auth-engine/examples/standalone/loginapp"
	"github.com/muno/auth-engine/httpapi"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/storage/memory"
)

const apiToken = "console-test-token"

// env はエンジン・自動承認の loginapp・コンソールを httptest で立てた環境。
type env struct {
	console *httptest.Server
	browser *http.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := memory.New()

	var publicHandler, internalHandler, consoleHandler http.Handler
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { publicHandler.ServeHTTP(w, r) }))
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { internalHandler.ServeHTTP(w, r) }))
	con := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { consoleHandler.ServeHTTP(w, r) }))
	t.Cleanup(public.Close)
	t.Cleanup(internal.Close)
	t.Cleanup(con.Close)

	login, err := loginapp.New(loginapp.Config{InteractionAPI: internal.URL, APIToken: apiToken, AutoApprove: true, AutoSubject: "alice", Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	loginSrv := httptest.NewServer(login.Handler())
	t.Cleanup(loginSrv.Close)

	// cmd/server と同じく RS256 と ES256 の両方を持つ（Client ごとに id_token_alg を選べる）
	ks := keys.NewSet()
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		signing, err := keys.Generate(alg, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.AddSigning(signing); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := authengine.New(authengine.Config{Issuer: public.URL, Store: store, Keys: ks, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Config{Engine: engine, InteractionURL: loginSrv.URL + "/login",
		InteractionAuth: httpapi.BearerAuthenticator{Token: apiToken}, InsecureCookies: true})
	if err != nil {
		t.Fatal(err)
	}
	publicHandler, internalHandler = srv.PublicHandler(), srv.InteractionHandler()

	// httptest は 127.0.0.1 で待ち受けるので、Native の loopback 照合（ポート無視）がそのまま効く
	native, err := client.NewNative(client.NativeParams{ID: "demo-cli", Name: "Demo CLI",
		RedirectURIs: []string{"http://127.0.0.1/callback"}, Scopes: []string{"openid", "profile"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateClient(t.Context(), native); err != nil {
		t.Fatal(err)
	}
	app, err := console.New(console.Config{Issuer: public.URL, BaseURL: con.URL, Store: store,
		Known: []console.KnownClient{{ID: "demo-cli"}}, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	consoleHandler = app.Handler()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{console: con, browser: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

// post はフォームを送り、リダイレクトを辿った後の URL と本文を返す。
func (e *env) post(t *testing.T, path string, form url.Values) (*url.URL, string) {
	t.Helper()
	res, err := e.browser.PostForm(e.console.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return res.Request.URL, readBody(t, res)
}

func (e *env) get(t *testing.T, rawURL string) (*url.URL, string) {
	t.Helper()
	res, err := e.browser.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return res.Request.URL, readBody(t, res)
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d: %s", res.Request.URL, res.StatusCode, b)
	}
	return string(b)
}

var (
	authLink    = regexp.MustCompile(`<a class="button" href="([^"]+)">認可エンドポイントへ進む`)
	secretInput = regexp.MustCompile(`name="secret" value="([^"]+)"`)
)

// runCodeFlow は開始フォームを送り、認可エンドポイントへのリンクを辿ってフロー画面の本文を返す。
func (e *env) runCodeFlow(t *testing.T, form url.Values) (flowURL *url.URL, page string) {
	t.Helper()
	_, page = e.post(t, "/flows", form)
	m := authLink.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no authorization link:\n%s", page)
	}
	// authorize → loginapp（自動承認）→ resume → コンソールの /callback → フロー画面
	flowURL, page = e.get(t, html.UnescapeString(m[1]))
	if !strings.HasPrefix(flowURL.Path, "/flows/") {
		t.Fatalf("ended at %s:\n%s", flowURL, page)
	}
	return flowURL, page
}

func assertAllPassed(t *testing.T, page string, wants ...string) {
	t.Helper()
	if strings.Contains(page, "✗") || strings.Contains(page, `class="error"`) {
		t.Fatalf("a check failed:\n%s", page)
	}
	for _, w := range wants {
		if !strings.Contains(page, w) {
			t.Fatalf("page does not contain %q:\n%s", w, page)
		}
	}
}

func TestWebClientRegisteredInConsole(t *testing.T) {
	e := newEnv(t)
	u, page := e.post(t, "/clients", url.Values{
		"profile": {"web"}, "client_id": {"console-web"}, "name": {"Console Web"},
		"redirect_uris": {e.console.URL + "/callback"}, "scopes": {"openid profile email"},
		"id_token_alg": {"ES256"}, "allow_insecure_localhost": {"on"},
	})
	if u.Path != "/clients/console-web" {
		t.Fatalf("redirected to %s:\n%s", u, page)
	}
	m := secretInput.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("secret is not shown after registration:\n%s", page)
	}

	flowURL, page := e.runCodeFlow(t, url.Values{"client_id": {"console-web"}, "secret": {m[1]}, "scope": {"openid profile email"}})
	assertAllPassed(t, page, "認可応答（コールバック）", "トークン要求（authorization_code）", "ID Token の検証", "ES256", "nonce が認可要求と一致")

	// Refresh で Rotation され、Introspection で active が分かる
	_, page = e.post(t, flowURL.Path+"/refresh", nil)
	assertAllPassed(t, page, "Refresh Token が Rotation された", "ID Token の検証（Refresh）")
	_, page = e.post(t, flowURL.Path+"/introspect-access", nil)
	assertAllPassed(t, page, `&#34;active&#34;: true`)
	_, page = e.post(t, flowURL.Path+"/revoke-refresh", nil)
	assertAllPassed(t, page, "200 OK（本文なし）")
	_, page = e.post(t, flowURL.Path+"/introspect-refresh", nil)
	assertAllPassed(t, page, `&#34;active&#34;: false`)
}

func TestNativeClientWithLoopbackRedirect(t *testing.T) {
	e := newEnv(t)
	flowURL, page := e.runCodeFlow(t, url.Values{"client_id": {"demo-cli"}, "scope": {"openid profile"}, "prompt": {"login"}})
	assertAllPassed(t, page, "ID Token の検証", "<th>prompt</th><td><code>login</code>")

	_, page = e.post(t, flowURL.Path+"/userinfo", nil)
	assertAllPassed(t, page, `&#34;sub&#34;: &#34;alice&#34;`)
	// public クライアントは Introspection を呼べない（ボタンも無効）
	_, page = e.post(t, flowURL.Path+"/introspect-access", nil)
	if !strings.Contains(page, "confidential クライアントだけが呼べる") {
		t.Fatalf("introspection must be refused for a native client:\n%s", page)
	}
}

// TestAuthorizationErrorResponse は認可応答がエラーのとき、交換に進まずエラーを表示することを確かめる。
// 新しいブラウザには loginapp のセッションがないので、prompt=none は login_required で戻る。
func TestAuthorizationErrorResponse(t *testing.T) {
	e := newEnv(t)
	_, page := e.runCodeFlow(t, url.Values{"client_id": {"demo-cli"}, "scope": {"openid"}, "prompt": {"none"}})
	// RFC 9207 §2: エラー応答にも iss が付くので、state と iss の検査はどちらも通る
	if strings.Count(page, `<span class="ok">✓</span>`) != 2 || !strings.Contains(page, "login_required") {
		t.Fatalf("error response is not shown:\n%s", page)
	}
	if strings.Contains(page, "トークン要求（authorization_code）") || strings.Contains(page, "トークン操作") {
		t.Fatalf("must not exchange a code after an error response:\n%s", page)
	}
}

func TestMachineClientCredentials(t *testing.T) {
	e := newEnv(t)
	_, page := e.post(t, "/clients", url.Values{"profile": {"machine"}, "client_id": {"batch"}, "name": {"Batch"}, "scopes": {"api.read"}})
	m := secretInput.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("secret is not shown after registration:\n%s", page)
	}
	_, page = e.post(t, "/flows", url.Values{"client_id": {"batch"}, "secret": {m[1]}, "scope": {"api.read"}})
	assertAllPassed(t, page, "トークン要求（client_credentials）", `&#34;scope&#34;: &#34;api.read&#34;`)
}

func TestRegistrationErrors(t *testing.T) {
	e := newEnv(t)
	res, err := e.browser.PostForm(e.console.URL+"/clients", url.Values{"profile": {"native"}, "client_id": {"demo-cli"}, "name": {"Dup"},
		"redirect_uris": {"http://127.0.0.1/callback"}, "scopes": {"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(body), "登録済み") {
		t.Fatalf("duplicate client_id: %d\n%s", res.StatusCode, body)
	}
}
