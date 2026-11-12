package tour_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/u-masato/auth-engine/examples/standalone/tour"
)

// env は 5 つのコンポーネントを別々のポートで立てたツアーと、ブラウザ役の HTTP クライアント。
type env struct {
	t    *testing.T
	tour *tour.Tour
	cfg  tour.Config
	hc   *http.Client // Cookie を持ち、リダイレクトを辿る（ブラウザ役）
}

func start(t *testing.T, verify string) *env {
	t.Helper()
	// コンポーネントは互いを URL で呼ぶので、先にポートを確保してから組み立てる
	servers := make([]*httptest.Server, 5)
	urls := make([]string, 5)
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(nil)
		urls[i] = "http://" + servers[i].Listener.Addr().String()
	}
	cfg := tour.Config{ClientURL: urls[0], IssuerURL: urls[1], InteractionAPIURL: urls[2], LoginURL: urls[3], ResourceURL: urls[4],
		Verify: verify, Logger: slog.New(slog.DiscardHandler)}
	tr, err := tour.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range []http.Handler{tr.Client, tr.Public, tr.InteractionAPI, tr.Login, tr.Resource} {
		servers[i].Config.Handler = h
		servers[i].Start()
		t.Cleanup(servers[i].Close)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, tour: tr, cfg: cfg, hc: &http.Client{Jar: jar}}
}

// post はフォームを送り、リダイレクトを辿った先の URL と本文を返す。
func (e *env) post(rawURL string, form url.Values) (*url.URL, string) {
	e.t.Helper()
	res, err := e.hc.PostForm(rawURL, form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		e.t.Fatalf("POST %s ended at %s with %d: %s", rawURL, res.Request.URL, res.StatusCode, body)
	}
	return res.Request.URL, string(body)
}

// login は Client の「ログイン」から始め、Interaction App の画面で action を選び、Client に戻った画面を返す。
func (e *env) login(action string, scopes ...string) string {
	e.t.Helper()
	at, page := e.post(e.cfg.ClientURL+"/start", nil)
	// /start → auth-engine の /authorize → Interaction App の /login?txn=...
	if !strings.HasPrefix(at.String(), e.cfg.LoginURL+"/login?txn=") || !strings.Contains(page, "いまここは Interaction App") {
		e.t.Fatalf("the browser must land on the Interaction App, got %s", at)
	}
	at, page = e.post(e.cfg.LoginURL+"/login", url.Values{"txn": {at.Query().Get("txn")}, "username": {"alice"}, "scope": scopes, "action": {action}})
	// /login → auth-engine の /authorize/resume → Client の /callback → Client のトップ
	if at.String() != e.cfg.ClientURL+"/" {
		e.t.Fatalf("the browser must come back to the client, got %s", at)
	}
	return page
}

// act は Client のボタンを 1 つ押し、戻った画面を返す。
func (e *env) act(name string) string {
	e.t.Helper()
	_, page := e.post(e.cfg.ClientURL+"/actions/"+name, url.Values{"text": {"テストで書いたノート"}})
	return page
}

func mustContain(t *testing.T, page string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(page, w) {
			t.Fatalf("the page must contain %q:\n%s", w, page)
		}
	}
}

// hops は記録にある「送信元>宛先 対象」の集合。
func (e *env) hops() map[string]bool {
	out := map[string]bool{}
	for _, s := range e.tour.Steps() {
		for _, ev := range s.Events {
			out[string(ev.From)+">"+string(ev.To)] = true
			out[string(ev.From)+">"+string(ev.To)+" "+ev.Target] = true
		}
	}
	return out
}

// ログインから業務 API の呼び出しまでを通し、境界図のすべての線を 1 回以上通ることを確かめる。
// 同意画面で notes:write を外したので、書き込みは scope 不足になる。
func TestTourWithJWT(t *testing.T) {
	e := start(t, tour.VerifyJWT)

	mustContain(t, e.act("anonymous"), "401 Unauthorized", "resource_metadata=")
	mustContain(t, e.login("approve", tour.ScopeRead), "連携済み", "トークンを受け取った")
	mustContain(t, e.act("read"), "200 OK", "alice さんの最初のノート")
	mustContain(t, e.act("write"), "403 Forbidden", "insufficient_scope")
	mustContain(t, e.act("refresh"), "トークンを更新する", "200 OK")
	mustContain(t, e.act("read"), "200 OK", "alice さんの最初のノート")
	// JWT のローカル検証では、失効は exp まで Resource Server に伝わらない（docs/adr/0006 §1）
	mustContain(t, e.act("revoke"), "Access Token を失効させる", "200 OK")
	mustContain(t, e.act("read"), "200 OK")

	hops := e.hops()
	for _, want := range []string{
		"browser>client", "browser>engine /authorize", "browser>interaction /login", "interaction>engine",
		"browser>engine /authorize/resume", "browser>client /callback", "client>engine /token", "client>resource /notes",
		"resource>engine /jwks", "engine>store CreateTransaction", "engine>store ConsumeAuthorizationCode", "engine>store IssueTokens",
		"engine>store RotateRefreshToken", "engine>store RevokeAccessToken",
	} {
		if !hops[want] {
			t.Errorf("the trace must contain %q; got %v", want, hops)
		}
	}
	if hops["resource>engine /introspect"] {
		t.Error("the Notes API must not introspect when it verifies JWTs locally")
	}

	// 記録に出す秘密値は先頭だけにする
	for _, s := range e.tour.Steps() {
		for _, ev := range s.Events {
			for _, kv := range ev.Request {
				switch kv.K {
				case "code", "code_verifier", "refresh_token", "token", "client_secret":
					if !strings.Contains(kv.V, "…") {
						t.Errorf("%s %s: %s must be abbreviated, got %q", ev.Method, ev.Target, kv.K, kv.V)
					}
				}
			}
		}
	}
}

// Introspection で検証する構成では、失効が次の呼び出しから Resource Server に伝わる。
func TestTourWithIntrospection(t *testing.T) {
	e := start(t, tour.VerifyIntrospection)

	mustContain(t, e.login("approve", tour.ScopeRead, tour.ScopeWrite), "連携済み", "Access Token は Opaque")
	mustContain(t, e.act("write"), "201 Created", "テストで書いたノート")
	mustContain(t, e.act("read"), "200 OK", "テストで書いたノート")
	mustContain(t, e.act("revoke"), "200 OK")
	mustContain(t, e.act("read"), "401 Unauthorized", "invalid_token")
	// Refresh Token は生きているので、新しい Access Token を取れば通る
	mustContain(t, e.act("refresh"), "200 OK")
	mustContain(t, e.act("read"), "200 OK", "テストで書いたノート")

	hops := e.hops()
	if !hops["resource>engine /introspect"] || hops["resource>engine /jwks"] {
		t.Errorf("the Notes API must verify tokens by introspection only; got %v", hops)
	}
}

// Interaction App で拒否すると、Client には OAuth のエラーとして伝わり、トークンは発行されない。
func TestTourDenied(t *testing.T) {
	e := start(t, tour.VerifyJWT)

	mustContain(t, e.login("deny"), "未連携", "認可されなかった", "access_denied")
	hops := e.hops()
	if !hops["interaction>engine"] || hops["client>engine /token"] || hops["engine>store IssueTokens"] {
		t.Errorf("a denied request must reach the engine through the Interaction API and issue nothing; got %v", hops)
	}
	// scope をすべて外した承認も拒否として扱う
	mustContain(t, e.login("approve"), "未連携", "access_denied")
}

func TestNewRejectsUnknownVerify(t *testing.T) {
	_, err := tour.New(t.Context(), tour.Config{ClientURL: "http://127.0.0.1:1", IssuerURL: "http://127.0.0.1:2",
		InteractionAPIURL: "http://127.0.0.1:3", LoginURL: "http://127.0.0.1:4", ResourceURL: "http://127.0.0.1:5", Verify: "none"})
	if err == nil || !strings.Contains(err.Error(), "unknown Verify") {
		t.Fatalf("an unknown Verify must be rejected: %v", err)
	}
}

// セッション Cookie の Secure は Client の URL のスキームに従う。http://localhost のデモでは付けず、
// https で動かすときは付ける。
func TestSessionCookieSecureFollowsScheme(t *testing.T) {
	for scheme, want := range map[string]bool{"http": false, "https": true} {
		tr, err := tour.New(t.Context(), tour.Config{ClientURL: scheme + "://localhost:1", IssuerURL: scheme + "://localhost:2",
			InteractionAPIURL: "http://127.0.0.1:3", LoginURL: scheme + "://localhost:4", ResourceURL: scheme + "://localhost:5",
			Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		tr.Client.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Secure != want || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
			t.Errorf("%s: session cookie = %+v, want Secure=%v with HttpOnly and SameSite=Lax", scheme, cookies, want)
		}
	}
}
