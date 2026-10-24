package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/httpapi"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/storage/memory"
	"github.com/muno/auth-engine/token"
)

// exampleEngine は Example 用に、Web クライアントを 1 つ登録した Engine を組み立てる。
// 時刻は固定し、監査ログは捨てる。
func exampleEngine(now time.Time) (*authengine.Engine, client.Secret) {
	store := memory.New() // 本番では adapters/sqlite か adapters/postgres を使う
	web, secret, err := client.NewWeb(client.WebParams{
		ID: "web", Name: "Web App", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid", "profile"},
	}, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := store.CreateClient(context.Background(), web); err != nil {
		log.Fatal(err)
	}
	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, now)
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		log.Fatal(err)
	}
	engine, err := authengine.New(authengine.Config{
		Issuer: "https://as.example.com", Store: store, Keys: ks,
		Now: func() time.Time { return now }, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		log.Fatal(err)
	}
	return engine, secret
}

// ExampleNew は Engine から 2 つの http.Handler を作り、別々のリスナーで公開する配線を示す。
// 公開エンドポイントは Issuer の URL で到達できる場所に、Interaction API は Interaction App だけが
// 届く内部ネットワークに置く（ADR-0003 §4）。
func ExampleNew() {
	engine, _ := exampleEngine(time.Now())

	srv, err := httpapi.New(httpapi.Config{
		Engine:          engine,
		InteractionURL:  "https://login.example.com/login",
		InteractionAuth: httpapi.BearerAuthenticator{Token: "shared-secret-for-interaction-app"},
	})
	if err != nil {
		log.Fatal(err)
	}

	public := &http.Server{Addr: ":8080", Handler: srv.PublicHandler(), ReadHeaderTimeout: 5 * time.Second}
	internal := &http.Server{Addr: "10.0.0.5:8081", Handler: srv.InteractionHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { log.Fatal(internal.ListenAndServe()) }()
	log.Fatal(public.ListenAndServe())
}

// Example_authorizationCodeFlow は Authorization Code + PKCE のフロー全体を 1 プロセス内で通す。
// ブラウザ・Interaction App・Client の役をこの関数が順に演じ、各段階の HTTP のやり取りを出力する。
// 手順の番号は docs/interaction-api.md の「全体の流れ」に対応する。
func Example_authorizationCodeFlow() {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	engine, secret := exampleEngine(now)
	const apiToken = "shared-secret-for-interaction-app"
	srv, err := httpapi.New(httpapi.Config{
		Engine: engine, InteractionURL: "https://login.example.com/login", InteractionAuth: httpapi.BearerAuthenticator{Token: apiToken},
	})
	if err != nil {
		log.Fatal(err)
	}
	public, internal := srv.PublicHandler(), srv.InteractionHandler()
	serve := func(h http.Handler, req *http.Request) *http.Response {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result()
	}

	// 1〜2. ブラウザが /authorize に来る。エンジンは Txn を作り、Interaction App へ送る。
	// code_challenge は RFC 7636 Appendix B の例。
	const verifier, challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	q := url.Values{
		"response_type": {"code"}, "client_id": {"web"}, "redirect_uri": {"https://app.example.com/cb"}, "scope": {"openid profile"},
		"state": {"xyz"}, "nonce": {"n-0S6_WzA2Mj"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	res := serve(public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(res.Header.Get("Location"))
	cookies := res.Cookies() // ブラウザ結合 Cookie。ブラウザが保持し、手順 7 で送り返す
	txnID := loc.Query().Get("txn")
	fmt.Printf("1. GET /authorize -> %d, Location: %s://%s%s?txn=...\n", res.StatusCode, loc.Scheme, loc.Host, loc.Path)

	// 3. Interaction App が要求内容をバックチャネルで取得する。
	interactionReq := func(method, path string, body any) *http.Request {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	res = serve(internal, interactionReq(http.MethodGet, "/transactions/"+txnID, nil))
	var txn struct {
		Status string `json:"status"`
		Client struct {
			Name string `json:"name"`
		} `json:"client"`
		Request struct {
			Scopes []string `json:"scopes"`
		} `json:"request"`
	}
	_ = json.NewDecoder(res.Body).Decode(&txn)
	fmt.Printf("3. GET /transactions/{txn} -> %d, status=%s client=%q scopes=%v\n", res.StatusCode, txn.Status, txn.Client.Name, txn.Request.Scopes)

	// 4〜5. ログインと同意を済ませた（ことにする）Interaction App が結果を返し、resume_url を受け取る。
	res = serve(internal, interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{
		"subject": "alice", "authenticated_at": now.Add(-time.Minute), "granted_scopes": []string{"openid", "profile"},
		"amr": []string{"pwd"}, "claims": map[string]any{"name": "Alice"},
	}))
	var completed struct {
		ResumeURL string `json:"resume_url"`
	}
	_ = json.NewDecoder(res.Body).Decode(&completed)
	fmt.Printf("5. POST /transactions/{txn}/complete -> %d\n", res.StatusCode)

	// 6〜8. ブラウザが resume_url へ戻る。結合 Cookie が一致すれば Code 付きで Client へ戻される。
	ru, _ := url.Parse(completed.ResumeURL)
	req := httptest.NewRequest(http.MethodGet, ru.RequestURI(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res = serve(public, req)
	cb, _ := url.Parse(res.Header.Get("Location"))
	fmt.Printf("7. GET /authorize/resume -> %d, Location: %s://%s%s state=%s iss=%s\n",
		res.StatusCode, cb.Scheme, cb.Host, cb.Path, cb.Query().Get("state"), cb.Query().Get("iss"))

	// Client が Code を code_verifier と共にトークンへ交換する（client_secret_basic）。
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.example.com/cb"}, "code_verifier": {verifier}}
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("web", string(secret))
	res = serve(public, req)
	var tok token.Response
	_ = json.NewDecoder(res.Body).Decode(&tok)
	fmt.Printf("POST /token -> %d, token_type=%s expires_in=%d scope=%q id_token=%t refresh_token=%t\n",
		res.StatusCode, tok.TokenType, tok.ExpiresIn, tok.Scope, tok.IDToken != "", tok.RefreshToken != "")

	// Output:
	// 1. GET /authorize -> 302, Location: https://login.example.com/login?txn=...
	// 3. GET /transactions/{txn} -> 200, status=pending client="Web App" scopes=[openid profile]
	// 5. POST /transactions/{txn}/complete -> 200
	// 7. GET /authorize/resume -> 302, Location: https://app.example.com/cb state=xyz iss=https://as.example.com
	// POST /token -> 200, token_type=Bearer expires_in=3600 scope="openid profile" id_token=true refresh_token=true
}

// headerAuthenticator は、前段のゲートウェイが付ける内部ヘッダーで Interaction API の呼び出し元を
// 認証する例。mTLS で受けるなら r.TLS.PeerCertificates を見る実装にする。
type headerAuthenticator struct{ allowed string }

func (a headerAuthenticator) Authenticate(r *http.Request) error {
	if r.Header.Get("X-Internal-Caller") != a.allowed {
		return errors.New("unknown caller")
	}
	return nil
}

// ExampleInteractionAuthenticator は Interaction API の認証方式を差し替える。
// 既定の BearerAuthenticator の代わりに任意の実装を Config.InteractionAuth に渡せる。
// 認証に失敗した要求は Handler に届く前に 401 になる。
func ExampleInteractionAuthenticator() {
	engine, _ := exampleEngine(time.Now())
	srv, err := httpapi.New(httpapi.Config{
		Engine: engine, InteractionURL: "https://login.example.com/login",
		InteractionAuth: headerAuthenticator{allowed: "login-app"},
	})
	if err != nil {
		log.Fatal(err)
	}
	internal := srv.InteractionHandler()

	for _, caller := range []string{"login-app", "someone-else"} {
		req := httptest.NewRequest(http.MethodGet, "/transactions/unknown", nil)
		req.Header.Set("X-Internal-Caller", caller)
		rec := httptest.NewRecorder()
		internal.ServeHTTP(rec, req)
		fmt.Printf("%s: %d\n", caller, rec.Code)
	}

	// Output:
	// login-app: 404
	// someone-else: 401
}

// brandedErrorPage は自前のテンプレートでエラーページを描く ErrorRenderer の例。
type brandedErrorPage struct{ tmpl *template.Template }

func (p brandedErrorPage) RenderError(w http.ResponseWriter, _ *http.Request, status int, code, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = p.tmpl.Execute(w, struct{ Code, Description string }{code, description})
}

// ExampleErrorRenderer は、Client へリダイレクトできないエラーのページを差し替える。
// client_id が未登録だと redirect_uri を信用できないので、エンジンは Client へ戻さず
// ブラウザにエラーページを描く（RFC 6749 §4.1.2.1）。
func ExampleErrorRenderer() {
	engine, _ := exampleEngine(time.Now())
	page := brandedErrorPage{tmpl: template.Must(template.New("error").Parse(`<p class="error">{{.Code}}: {{.Description}}</p>`))}
	srv, err := httpapi.New(httpapi.Config{
		Engine: engine, InteractionURL: "https://login.example.com/login",
		InteractionAuth: httpapi.BearerAuthenticator{Token: "shared-secret-for-interaction-app"},
		ErrorRenderer:   page,
	})
	if err != nil {
		log.Fatal(err)
	}

	q := url.Values{"response_type": {"code"}, "client_id": {"no-such-client"}, "redirect_uri": {"https://evil.example/cb"}}
	rec := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	fmt.Println(rec.Code, rec.Header().Get("Location") == "")
	fmt.Println(rec.Body.String())

	// Output:
	// 400 true
	// <p class="error">invalid_request: unknown client_id</p>
}
