package console_test

import (
	"errors"
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

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/console"
	"github.com/u-masato/auth-engine/examples/standalone/loginapp"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/httpapi"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/storage/memory"
)

const apiToken = "console-test-token"

// env はエンジン・自動承認の loginapp・コンソールを httptest で立てた環境。
type env struct {
	console *httptest.Server
	browser *http.Client
	store   *memory.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	discard := slog.New(slog.DiscardHandler)
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
	app, err := console.New(console.Config{Issuer: public.URL, BaseURL: con.URL, Store: store, Grants: engine.Grants, PageSize: 2, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	consoleHandler = app.Handler()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{console: con, browser: &http.Client{Jar: jar, Timeout: 10 * time.Second}, store: store}
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

// status は要求を送り、リダイレクトを辿った後のステータスと本文を返す（エラー応答の確認用）。
func (e *env) status(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	res, err := e.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(b)
}

func (e *env) postStatus(t *testing.T, path string, form url.Values) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.console.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.status(t, req)
}

// 一覧は Store.ListClients のキーセットページングをそのまま辿る（テストの PageSize は 2）。
func TestClientListPaging(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"a-batch", "z-batch"} {
		e.post(t, "/clients", url.Values{"profile": {"machine"}, "client_id": {id}, "name": {id}, "scopes": {"api.read"}})
	}
	// client_id の昇順: a-batch、demo-cli | z-batch
	_, first := e.get(t, e.console.URL+"/")
	if !strings.Contains(first, "a-batch") || !strings.Contains(first, "demo-cli") || strings.Contains(first, "z-batch") {
		t.Fatalf("first page must list a-batch and demo-cli only:\n%s", first)
	}
	if !strings.Contains(first, `href="/?after=demo-cli"`) {
		t.Fatalf("first page must link to the next page:\n%s", first)
	}
	_, second := e.get(t, e.console.URL+"/?after=demo-cli")
	if !strings.Contains(second, "z-batch") || strings.Contains(second, "a-batch") || strings.Contains(second, "次のページ") {
		t.Fatalf("second page must list z-batch only and be the last:\n%s", second)
	}
	// 「client_id を指定して開く」は詳細へ飛ぶ
	u, _ := e.get(t, e.console.URL+"/?open=z-batch")
	if u.Path != "/clients/z-batch" {
		t.Fatalf("open redirected to %s", u)
	}
}

// シークレットの再発行は、新しい平文を 1 度表示し、旧シークレットを直ちに無効にする。
func TestRotateSecret(t *testing.T) {
	e := newEnv(t)
	_, page := e.post(t, "/clients", url.Values{"profile": {"machine"}, "client_id": {"batch"}, "name": {"Batch"}, "scopes": {"api.read"}})
	m := secretInput.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("secret is not shown after registration:\n%s", page)
	}
	oldSecret := m[1]
	before, err := e.store.GetClient(t.Context(), "batch")
	if err != nil {
		t.Fatal(err)
	}

	// 確認欄が一致しなければ何もしない
	status, body := e.postStatus(t, "/clients/batch/secret", url.Values{"confirm": {"other"}})
	if status != http.StatusBadRequest || !strings.Contains(body, "再発行していない") {
		t.Fatalf("mismatched confirmation: %d\n%s", status, body)
	}
	if got, err := e.store.GetClient(t.Context(), "batch"); err != nil || got.SecretHash != before.SecretHash {
		t.Fatalf("secret must not change without confirmation: %+v, %v", got, err)
	}

	u, page := e.post(t, "/clients/batch/secret", url.Values{"confirm": {"batch"}})
	if u.Path != "/clients/batch" || !strings.Contains(page, "再発行した") {
		t.Fatalf("rotation ended at %s:\n%s", u, page)
	}
	m = secretInput.FindStringSubmatch(page)
	if m == nil || m[1] == oldSecret {
		t.Fatalf("the new secret must be shown once after rotation:\n%s", page)
	}
	newSecret := m[1]
	got, err := e.store.GetClient(t.Context(), "batch")
	if err != nil || !got.VerifySecret(newSecret) || got.VerifySecret(oldSecret) || got.Name != "Batch" {
		t.Fatalf("store must hold only the new secret: %+v, %v", got, err)
	}

	// 旧シークレットはトークンエンドポイントで拒否され、新しいシークレットは通る（RFC 6749 §5.2）
	_, page = e.post(t, "/flows", url.Values{"client_id": {"batch"}, "secret": {oldSecret}, "scope": {"api.read"}})
	if !strings.Contains(page, "invalid_client") {
		t.Fatalf("the old secret must be rejected:\n%s", page)
	}
	_, page = e.post(t, "/flows", url.Values{"client_id": {"batch"}, "secret": {newSecret}, "scope": {"api.read"}})
	assertAllPassed(t, page, "トークン要求（client_credentials）", `&#34;scope&#34;: &#34;api.read&#34;`)

	// コンソールの外で再発行されたら、覚えている平文は表示しない（古い値を開始フォームに入れない）
	cur, err := e.store.GetClient(t.Context(), "batch")
	if err != nil {
		t.Fatal(err)
	}
	outside, _, err := cur.RotateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.RotateClientSecret(t.Context(), "batch", outside.SecretHash); err != nil {
		t.Fatal(err)
	}
	_, page = e.get(t, e.console.URL+"/clients/batch")
	if strings.Contains(page, newSecret) || !strings.Contains(page, "コンソールは平文を知らない") {
		t.Fatalf("a secret rotated elsewhere must not be shown:\n%s", page)
	}

	// public クライアントには再発行の欄がなく、直接送っても拒否される
	_, native := e.get(t, e.console.URL+"/clients/demo-cli")
	if strings.Contains(native, "/clients/demo-cli/secret") {
		t.Fatalf("a public client must not offer secret rotation:\n%s", native)
	}
	status, body = e.postStatus(t, "/clients/demo-cli/secret", url.Values{"confirm": {"demo-cli"}})
	if status != http.StatusBadRequest || !strings.Contains(body, "シークレットを持たない") {
		t.Fatalf("rotating a public client: %d\n%s", status, body)
	}
	status, _ = e.postStatus(t, "/clients/missing/secret", url.Values{"confirm": {"missing"}})
	if status != http.StatusNotFound {
		t.Fatalf("rotating a missing client: %d", status)
	}
}

// 詳細画面は Client の利用者（Grant）を subject の昇順で一覧し、1 人ずつ連携を解除できる。
func TestClientGrants(t *testing.T) {
	e := newEnv(t)
	_, page := e.get(t, e.console.URL+"/clients/demo-cli")
	if !strings.Contains(page, "まだ誰も同意していない") {
		t.Fatalf("no grants yet:\n%s", page)
	}

	// フローを通すと alice の Grant ができ、Access Token が有効になる
	flowURL, _ := e.runCodeFlow(t, url.Values{"client_id": {"demo-cli"}, "scope": {"openid profile"}})
	_, page = e.post(t, flowURL.Path+"/userinfo", nil)
	assertAllPassed(t, page, `&#34;sub&#34;: &#34;alice&#34;`)
	_, page = e.get(t, e.console.URL+"/clients/demo-cli")
	if !strings.Contains(page, "<code>alice</code>") || !strings.Contains(page, `<span class="ok">active</span>`) ||
		!strings.Contains(page, `action="/clients/demo-cli/grants/revoke"`) {
		t.Fatalf("alice's grant must be listed as active:\n%s", page)
	}

	// ページング（テストの PageSize は 2）: alice、bob | carol
	now := time.Now()
	for _, sub := range []string{"carol", "bob"} {
		if _, err := e.store.UpsertGrant(t.Context(), &grant.Grant{ID: "g-" + sub, ClientID: "demo-cli", Subject: sub,
			Scopes: []string{"openid"}, Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	_, first := e.get(t, e.console.URL+"/clients/demo-cli")
	if !strings.Contains(first, "<code>alice</code>") || !strings.Contains(first, "<code>bob</code>") || strings.Contains(first, "<code>carol</code>") ||
		!strings.Contains(first, `href="/clients/demo-cli?grants_after=bob#grants"`) {
		t.Fatalf("first page must list alice and bob and link to the next page:\n%s", first)
	}
	_, second := e.get(t, e.console.URL+"/clients/demo-cli?grants_after=bob")
	if !strings.Contains(second, "<code>carol</code>") || strings.Contains(second, "<code>alice</code>") || strings.Contains(second, "次へ") {
		t.Fatalf("second page must list carol only and be the last:\n%s", second)
	}

	// 連携の解除: Grant が失効し、配下のトークンも使えなくなる
	u, page := e.post(t, "/clients/demo-cli/grants/revoke", url.Values{"subject": {"alice"}})
	if u.Path != "/clients/demo-cli" || !strings.Contains(page, "alice との連携を解除した") || !strings.Contains(page, "revoked（") {
		t.Fatalf("revocation ended at %s:\n%s", u, page)
	}
	if g, err := e.store.FindGrant(t.Context(), "demo-cli", "alice"); err != nil || g.Active() {
		t.Fatalf("alice's grant must be revoked: %+v, %v", g, err)
	}
	if g, err := e.store.FindGrant(t.Context(), "demo-cli", "bob"); err != nil || !g.Active() {
		t.Fatalf("bob's grant must stay active: %+v, %v", g, err)
	}
	_, page = e.post(t, flowURL.Path+"/userinfo", nil)
	if !strings.Contains(page, "invalid_token") {
		t.Fatalf("the access token must be rejected after the grant is revoked:\n%s", page)
	}

	status, body := e.postStatus(t, "/clients/demo-cli/grants/revoke", url.Values{"subject": {"nobody"}})
	if status != http.StatusNotFound || !strings.Contains(body, "Grant はない") {
		t.Fatalf("revoking an unknown grant: %d\n%s", status, body)
	}
	status, _ = e.postStatus(t, "/clients/demo-cli/grants/revoke", url.Values{})
	if status != http.StatusBadRequest {
		t.Fatalf("revoking without a subject: %d", status)
	}
}

// 編集は開放項目だけを置き換え、Profile の規則に反する値は保存しない（ADR-0004 §2、§4）。
func TestEditClient(t *testing.T) {
	e := newEnv(t)
	_, form := e.get(t, e.console.URL+"/clients/demo-cli/edit")
	if !strings.Contains(form, "http://127.0.0.1/callback") {
		t.Fatalf("edit form must show the current redirect URI:\n%s", form)
	}
	u, page := e.post(t, "/clients/demo-cli", url.Values{
		"name": {"Renamed CLI"}, "redirect_uris": {"http://127.0.0.1/callback\ncom.example.app:/cb"},
		"scopes": {"openid profile email"}, "access_token_ttl": {"15m"}, "id_token_alg": {"ES256"},
	})
	if u.Path != "/clients/demo-cli" || !strings.Contains(page, "変更を保存した") {
		t.Fatalf("update ended at %s:\n%s", u, page)
	}
	got, err := e.store.GetClient(t.Context(), "demo-cli")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Renamed CLI" || len(got.RedirectURIs) != 2 || len(got.Scopes) != 3 || got.AccessTokenTTL != 15*time.Minute ||
		got.IDTokenAlg != client.AlgES256 || got.Profile != client.ProfileNative {
		t.Fatalf("stored client: %+v", got)
	}

	// Native に http の非 loopback redirect URI は登録できない。保存されず、入力は残る
	status, body := e.postStatus(t, "/clients/demo-cli", url.Values{
		"name": {"Broken"}, "redirect_uris": {"http://example.com/cb"}, "scopes": {"openid"}})
	if status != http.StatusBadRequest || !strings.Contains(body, "保存できない") || !strings.Contains(body, "http://example.com/cb") {
		t.Fatalf("invalid update: %d\n%s", status, body)
	}
	status, body = e.postStatus(t, "/clients/demo-cli", url.Values{"name": {"X"}, "scopes": {"openid"}, "access_token_ttl": {"soon"}})
	if status != http.StatusBadRequest || !strings.Contains(body, "解釈できない") {
		t.Fatalf("invalid ttl: %d\n%s", status, body)
	}
	if got, _ := e.store.GetClient(t.Context(), "demo-cli"); got.Name != "Renamed CLI" {
		t.Fatalf("a rejected update must not be stored: %+v", got)
	}
}

// 削除は確認欄の client_id が一致したときだけ行い、Grant とトークンの失効は Store.DeleteClient に任せる。
func TestDeleteClient(t *testing.T) {
	e := newEnv(t)
	// フローを 1 回通して Access Token を持たせる
	flowURL, _ := e.runCodeFlow(t, url.Values{"client_id": {"demo-cli"}, "scope": {"openid profile"}})

	status, body := e.postStatus(t, "/clients/demo-cli/delete", url.Values{"confirm": {"demo"}})
	if status != http.StatusBadRequest || !strings.Contains(body, "削除していない") {
		t.Fatalf("delete without a matching confirmation: %d\n%s", status, body)
	}
	if _, err := e.store.GetClient(t.Context(), "demo-cli"); err != nil {
		t.Fatalf("client must survive a rejected delete: %v", err)
	}

	u, page := e.post(t, "/clients/demo-cli/delete", url.Values{"confirm": {"demo-cli"}})
	if u.Path != "/" || !strings.Contains(page, "demo-cli を削除した") {
		t.Fatalf("delete ended at %s:\n%s", u, page)
	}
	if _, err := e.store.GetClient(t.Context(), "demo-cli"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("client must be gone: %v", err)
	}
	// 発行済みの Access Token は失効している
	_, page = e.post(t, flowURL.Path+"/userinfo", nil)
	if !strings.Contains(page, "invalid_token") {
		t.Fatalf("access token must be revoked with the client:\n%s", page)
	}
	if status, _ := e.postStatus(t, "/clients/demo-cli/delete", url.Values{"confirm": {"demo-cli"}}); status != http.StatusNotFound {
		t.Fatalf("deleting a missing client: %d", status)
	}
}

// client_id が URL の Client（事前登録した MCP Client）も、一覧のリンクから詳細・編集・削除まで辿れる。
func TestURLClientID(t *testing.T) {
	e := newEnv(t)
	const id = "https://mcp.example/oauth/client.json"
	mcp, err := client.NewMCP(client.MetadataDocument{ClientID: id, ClientName: "MCP App", RedirectURIs: []string{"http://localhost:3000/cb"}}, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateClient(t.Context(), mcp); err != nil {
		t.Fatal(err)
	}
	_, list := e.get(t, e.console.URL+"/?after=demo-cli")
	m := regexp.MustCompile(`<a href="(/clients/https[^"]+)"><code>`).FindStringSubmatch(list)
	if m == nil {
		t.Fatalf("no link to the url client:\n%s", list)
	}
	path := html.UnescapeString(m[1])
	_, detail := e.get(t, e.console.URL+path)
	if !strings.Contains(detail, "MCP App") || !strings.Contains(detail, "認可要求に必須") {
		t.Fatalf("detail of the url client:\n%s", detail)
	}
	_, page := e.post(t, path, url.Values{"name": {"MCP App 2"}, "redirect_uris": {"http://localhost:3000/cb"}})
	if !strings.Contains(page, "MCP App 2") {
		t.Fatalf("update of the url client:\n%s", page)
	}
	if u, _ := e.post(t, path+"/delete", url.Values{"confirm": {id}}); u.Path != "/" {
		t.Fatalf("delete ended at %s", u)
	}
	if _, err := e.store.GetClient(t.Context(), id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("url client must be gone: %v", err)
	}
}

// 認証のない管理画面なので、他のサイトからブラウザ経由で届く書き込みは拒否する（CSRF）。
func TestCrossOriginWritesAreRejected(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"confirm": {"demo-cli"}}
	req, err := http.NewRequest(http.MethodPost, e.console.URL+"/clients/demo-cli/delete", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if status, body := e.status(t, req); status != http.StatusForbidden {
		t.Fatalf("cross-site delete: %d\n%s", status, body)
	}
	if _, err := e.store.GetClient(t.Context(), "demo-cli"); err != nil {
		t.Fatalf("client must survive a cross-site request: %v", err)
	}
}
