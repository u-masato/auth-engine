package resourceserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/httpapi"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/resourceserver"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

// as は httptest で動く認可サーバー（Engine + httpapi）。resourceserver は HTTP 越しにだけ触る。
type as struct {
	t         *testing.T
	srv       *httptest.Server
	keys      *keys.Set
	rsSecret  string // Introspection を呼ぶ Resource Server の資格情報（Machine Profile）
	svcSecret string // トークンを得るサービス（Machine Profile）
	jwksHits  atomic.Int32

	mu     sync.Mutex
	offset time.Duration // Engine の時計のずれ（期限切れトークンを作るため）
}

func (a *as) now() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().Add(a.offset)
}

func (a *as) shift(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.offset = d
}

func newAS(t *testing.T) *as {
	t.Helper()
	ctx := context.Background()
	a := &as{t: t, keys: keys.NewSet()}
	for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
		k, err := keys.Generate(alg, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := a.keys.AddSigning(k); err != nil {
			t.Fatal(err)
		}
	}
	store := memory.New()
	rs, rsSecret, err := client.NewMachine(client.MachineParams{ID: "rs", Name: "Resource Server", Scopes: []string{"introspect"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	svc, svcSecret, err := client.NewMachine(client.MachineParams{ID: "svc", Name: "Service", Scopes: []string{"files:read", "files:write"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*client.Client{rs, svc} {
		if err := store.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	a.rsSecret, a.svcSecret = string(rsSecret), string(svcSecret)

	var handler http.Handler
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == httpapi.PathJWKS {
			a.jwksHits.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(a.srv.Close)

	engine, err := authengine.New(authengine.Config{
		Issuer: a.srv.URL, Store: store, Keys: a.keys, Now: a.now, Logger: slog.New(slog.DiscardHandler),
		Resources: []resource.Resource{
			{URI: "https://mcp.example.com", Name: "MCP", Scopes: []string{"files:read", "files:write"}},
			{URI: "https://jwt.example.com/api", AccessTokenFormat: resource.FormatJWT},
			{URI: "https://es.example.com", AccessTokenFormat: resource.FormatJWT, AccessTokenAlg: resource.AlgES256},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := httpapi.New(httpapi.Config{Engine: engine, InteractionURL: "http://localhost:9/login", InteractionAuth: httpapi.BearerAuthenticator{Token: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	handler = api.PublicHandler()
	return a
}

// tokenFor は client_credentials で resource 向けの Access Token を得る。
func (a *as) tokenFor(resourceURI, scope string) string {
	a.t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {resourceURI}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+httpapi.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", a.svcSecret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		a.t.Fatalf("token: %d %s", res.StatusCode, body)
	}
	var tr token.Response
	_ = json.Unmarshal(body, &tr)
	return tr.AccessToken
}

func (a *as) revoke(tok string) {
	a.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, a.srv.URL+httpapi.PathRevoke, strings.NewReader(url.Values{"token": {tok}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", a.svcSecret)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		a.t.Fatalf("revoke: %v %v", res, err)
	}
	res.Body.Close()
}

func serve(p *resourceserver.Protector, scopes ...string) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle(p.MetadataPath(), p.MetadataHandler())
	mux.Handle("/mcp", p.Protect(http.HandlerFunc(echoPrincipal), scopes...))
	return httptest.NewServer(mux)
}

func get(t *testing.T, url, tok string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

// Opaque Access Token を Introspection で検証する。失効はすぐ伝わる。
func TestIntrospectionVerifier(t *testing.T) {
	a := newAS(t)
	p, err := resourceserver.New(resourceserver.Config{
		Resource: "https://mcp.example.com", AuthorizationServers: []string{a.srv.URL}, Scopes: []string{"files:read", "files:write"},
		Verifier: &resourceserver.IntrospectionVerifier{Issuer: a.srv.URL, ClientID: "rs", ClientSecret: a.rsSecret},
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := serve(p, "files:read")
	t.Cleanup(rs.Close)

	// メタデータは認可サーバーの issuer を指す（MCP「Authorization Server Location」）
	res, body := get(t, rs.URL+"/.well-known/oauth-protected-resource", "")
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"authorization_servers":["`+a.srv.URL+`"]`) {
		t.Fatalf("metadata: %d %s", res.StatusCode, body)
	}

	tok := a.tokenFor("https://mcp.example.com", "files:read")
	res, body = get(t, rs.URL+"/mcp", tok)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"ClientID":"svc"`) || !strings.Contains(body, `"Subject":"svc"`) {
		t.Fatalf("valid opaque token: %d %s", res.StatusCode, body)
	}
	// 他の resource（JWT 形式）向けのトークンは Introspection では active だが aud が合わない
	other := a.tokenFor("https://jwt.example.com/api", "")
	if res, _ := get(t, rs.URL+"/mcp", other); res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), "not intended for this resource") {
		t.Fatalf("other resource: %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	// scope 不足
	if res, _ := get(t, rs.URL+"/mcp", a.tokenFor("https://mcp.example.com", "files:write")); res.StatusCode != http.StatusForbidden {
		t.Fatalf("insufficient scope: %d", res.StatusCode)
	}
	// 失効後は invalid_token
	a.revoke(tok)
	if res, _ := get(t, rs.URL+"/mcp", tok); res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("revoked: %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	// でたらめ
	if res, _ := get(t, rs.URL+"/mcp", "at_garbage"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("garbage: %d", res.StatusCode)
	}
	// 認可サーバーが落ちたら 503
	a.srv.Close()
	if res, _ := get(t, rs.URL+"/mcp", tok); res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("as down: %d", res.StatusCode)
	}
}

// Introspection 応答の形に対する防御: token_type が Bearer でない（Refresh Token など）は拒否、aud は文字列でもよい。
func TestIntrospectionVerifierResponses(t *testing.T) {
	var response string
	ep := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, pw, ok := r.BasicAuth(); !ok || u != "rs" || pw != "s3cret" || r.FormValue("token") == "" || r.FormValue("token_type_hint") != "access_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(ep.Close)
	v := &resourceserver.IntrospectionVerifier{Endpoint: ep.URL, ClientID: "rs", ClientSecret: "s3cret"}
	ctx := context.Background()

	response = `{"active":true,"token_type":"Bearer","scope":"a b","client_id":"c","sub":"u","aud":"https://mcp.example.com","exp":4102444800}`
	p, err := v.Verify(ctx, "t")
	if err != nil || p.Audience[0] != "https://mcp.example.com" || len(p.Scopes) != 2 || p.ExpiresAt.Year() != 2100 {
		t.Fatalf("string aud: %+v %v", p, err)
	}
	for name, resp := range map[string]string{
		"inactive":              `{"active":false}`,
		"refresh token":         `{"active":true,"scope":"a","client_id":"c","sub":"u","aud":["https://mcp.example.com"]}`, // token_type なし
		"token_type not bearer": `{"active":true,"token_type":"refresh_token","aud":["https://mcp.example.com"]}`,
	} {
		response = resp
		if _, err := v.Verify(ctx, "t"); !errors.Is(err, resourceserver.ErrInvalidToken) {
			t.Errorf("%s: want ErrInvalidToken, got %v", name, err)
		}
	}
	response = `not json`
	if _, err := v.Verify(ctx, "t"); err == nil || errors.Is(err, resourceserver.ErrInvalidToken) {
		t.Errorf("malformed response must be a non-invalid_token error: %v", err)
	}
	// 資格情報が違えば 401 → 一時的な障害として扱う（設定ミスを invalid_token に見せない）
	wrong := &resourceserver.IntrospectionVerifier{Endpoint: ep.URL, ClientID: "rs", ClientSecret: "wrong"}
	if _, err := wrong.Verify(ctx, "t"); err == nil || errors.Is(err, resourceserver.ErrInvalidToken) {
		t.Errorf("auth failure: %v", err)
	}
}

// JWT Access Token を JWKS でローカル検証する（RFC 9068 §4）。
func TestJWTVerifier(t *testing.T) {
	a := newAS(t)
	var vnow atomic.Int64 // 検証側の時計のずれ（秒）。鍵ローテーション後の再取得間隔を進めるため
	verifier := &resourceserver.JWTVerifier{Issuer: a.srv.URL, Now: func() time.Time { return time.Now().Add(time.Duration(vnow.Load()) * time.Second) }}
	p, err := resourceserver.New(resourceserver.Config{
		Resource: "https://jwt.example.com/api", AuthorizationServers: []string{a.srv.URL}, Verifier: verifier,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := serve(p)
	t.Cleanup(rs.Close)

	// path を持つ resource の well-known（RFC 9728 §3）
	if res, body := get(t, rs.URL+"/.well-known/oauth-protected-resource/api", ""); res.StatusCode != http.StatusOK || !strings.Contains(body, `"resource":"https://jwt.example.com/api"`) {
		t.Fatalf("metadata: %d %s", res.StatusCode, body)
	}

	tok := a.tokenFor("https://jwt.example.com/api", "")
	res, body := get(t, rs.URL+"/mcp", tok)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"ClientID":"svc"`) || !strings.Contains(body, `"Audience":["https://jwt.example.com/api"]`) {
		t.Fatalf("valid jwt: %d %s", res.StatusCode, body)
	}
	if a.jwksHits.Load() != 1 {
		t.Fatalf("jwks fetched %d times", a.jwksHits.Load())
	}
	// 2 本目はキャッシュした JWKS で検証する
	if res, _ := get(t, rs.URL+"/mcp", a.tokenFor("https://jwt.example.com/api", "")); res.StatusCode != http.StatusOK || a.jwksHits.Load() != 1 {
		t.Fatalf("cached jwks: %d hits=%d", res.StatusCode, a.jwksHits.Load())
	}
	// 失効はローカル検証に伝播しない（ADR-0008 §3）
	a.revoke(tok)
	if res, _ := get(t, rs.URL+"/mcp", tok); res.StatusCode != http.StatusOK {
		t.Fatalf("revoked jwt must still verify locally: %d", res.StatusCode)
	}
	// Opaque トークン、他 resource 向け JWT、ID Token（typ=JWT）、iss 違いは拒否
	reject := func(name, tok, wantMsg string) {
		t.Helper()
		res, _ := get(t, rs.URL+"/mcp", tok)
		if res.StatusCode != http.StatusUnauthorized || !strings.Contains(res.Header.Get("WWW-Authenticate"), wantMsg) {
			t.Fatalf("%s: %d %q", name, res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
	}
	reject("opaque", a.tokenFor("https://mcp.example.com", ""), `error="invalid_token"`)
	reject("other audience", a.tokenFor("https://es.example.com", ""), "not intended for this resource")
	claims := map[string]any{"iss": a.srv.URL, "sub": "alice", "aud": []string{"https://jwt.example.com/api"}, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "client_id": "c", "scope": "x"}
	idToken, _ := a.keys.SignTyped(keys.AlgRS256, "JWT", claims)
	reject("id token", idToken, `typ \"JWT\" is not at+jwt`)
	claims["iss"] = "https://evil.example.com"
	foreign, _ := a.keys.SignTyped(keys.AlgRS256, "at+jwt", claims)
	reject("issuer mismatch", foreign, "issuer")
	claims["iss"] = a.srv.URL
	// 期限切れ: Engine の時計を 2 時間戻して発行（TTL 1 時間）
	a.shift(-2 * time.Hour)
	expired := a.tokenFor("https://jwt.example.com/api", "")
	a.shift(0)
	reject("expired", expired, "expired")
	// alg 許可リスト（RFC 8725 §3.1）: ES256 で署名された正当なトークンも RS256 だけの Resource Server は拒否
	strict := &resourceserver.JWTVerifier{Issuer: a.srv.URL, Algorithms: []string{keys.AlgRS256}}
	esToken, _ := a.keys.SignTyped(keys.AlgES256, "at+jwt", claims)
	if _, err := strict.Verify(context.Background(), esToken); !errors.Is(err, resourceserver.ErrInvalidToken) || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("alg allowlist: %v", err)
	}
	if _, err := strict.Verify(context.Background(), a.tokenFor("https://jwt.example.com/api", "")); err != nil {
		t.Fatalf("rs256 with strict verifier: %v", err)
	}

	// 鍵ローテーション: 新しい署名鍵の kid は未知なので JWKS を再取得する（MinRefresh を過ぎていれば）
	rotated, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.keys.AddSigning(rotated); err != nil {
		t.Fatal(err)
	}
	fresh := a.tokenFor("https://jwt.example.com/api", "")
	before := a.jwksHits.Load()                                             // strict verifier も 1 回取得している
	reject("unknown kid within MinRefresh", fresh, `error="invalid_token"`) // 直前に取得したばかりなので再取得しない
	if a.jwksHits.Load() != before {
		t.Fatalf("jwks must not be refetched within MinRefresh: hits=%d", a.jwksHits.Load())
	}
	vnow.Store(120) // 2 分進める
	if res, _ := get(t, rs.URL+"/mcp", fresh); res.StatusCode != http.StatusOK || a.jwksHits.Load() != before+1 {
		t.Fatalf("after rotation: %d hits=%d (before %d)", res.StatusCode, a.jwksHits.Load(), before)
	}
	// 古い鍵で署名されたトークンも、旧鍵が JWKS に残っている間は通る
	if res, _ := get(t, rs.URL+"/mcp", tok); res.StatusCode != http.StatusOK {
		t.Fatalf("old key still published: %d", res.StatusCode)
	}
}

func TestJWTVerifierRequiresIssuer(t *testing.T) {
	v := &resourceserver.JWTVerifier{}
	if _, err := v.Verify(context.Background(), "x.y.z"); err == nil {
		t.Fatal("issuer is required")
	}
}
