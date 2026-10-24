package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/cimd"
	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/resourceserver"
)

// mcpSystem は MCP 連携（M3）の結合環境。system に加えて、CIMD 文書を配る TLS サーバー（MCP クライアントの
// 提供者に相当）と、resourceserver で守った 2 つの MCP サーバー（JWT をローカル検証するものと Introspection するもの）を持つ。
type mcpSystem struct {
	*system

	// docs は CIMD 文書サーバー。client_id は docs.URL + "/client.json"。文書の中身は doc で差し替えられる。
	docs     *httptest.Server
	docMu    sync.Mutex
	doc      map[string]any
	clientID string

	// jwtRS は JWT Access Token（RFC 9068）をローカル検証する MCP サーバー、introRS は Opaque を Introspection（RFC 7662）で
	// 検証する MCP サーバー。resource URI はそれぞれのサーバーの URL + "/mcp"。
	jwtRS, introRS *httptest.Server
	jwtURI         string
	introURI       string
}

// newMCPSystem は認可サーバーに 2 つの resource（jwt / opaque）と CIMD を設定し、各 MCP サーバーを立てる。
func newMCPSystem(t *testing.T, autoApprove bool, redirectURIs ...string) *mcpSystem {
	t.Helper()
	m := &mcpSystem{}

	// CIMD 文書サーバー（loopback の TLS）。認可サーバーには cimd.NewTransport(true) にこのサーバーの証明書を足した HTTP クライアントを渡す。
	m.docs = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.docMu.Lock()
		defer m.docMu.Unlock()
		if r.URL.Path != "/client.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.doc)
	}))
	m.docs.Config.ErrorLog = log.New(io.Discard, "", 0)
	m.docs.StartTLS()
	t.Cleanup(m.docs.Close)
	m.clientID = m.docs.URL + "/client.json"
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"http://127.0.0.1/callback"} // loopback はポートを無視して照合（RFC 8252 §7.3）
	}
	m.setDocument(redirectURIs...)

	// MCP サーバーの URL は先に決めたいが httptest は起動時に決まるので、ハンドラを後から差し込む
	var jwtHandler, introHandler http.Handler
	m.jwtRS = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jwtHandler.ServeHTTP(w, r) }))
	m.introRS = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { introHandler.ServeHTTP(w, r) }))
	t.Cleanup(m.jwtRS.Close)
	t.Cleanup(m.introRS.Close)
	m.jwtURI, m.introURI = m.jwtRS.URL+"/mcp", m.introRS.URL+"/mcp"

	tr := cimd.NewTransport(true)
	tr.TLSClientConfig = m.docs.Client().Transport.(*http.Transport).TLSClientConfig
	m.system = newSystemWith(t, autoApprove, func(cfg *authengine.Config) {
		cfg.Resources = []resource.Resource{
			{URI: m.jwtURI, Name: "JWT MCP Server", AccessTokenFormat: resource.FormatJWT, Scopes: []string{"mcp:read", "mcp:write"}},
			{URI: m.introURI, Name: "Opaque MCP Server", Scopes: []string{"mcp:read"}},
		}
		cfg.CIMD = &cimd.Config{HTTPClient: &http.Client{Transport: tr, Timeout: 2 * time.Second}, AllowLoopback: true}
	})

	// Introspection 用の Machine Client（Resource Server の資格情報）
	rsClient, rsSecret := m.registerMachine(t, "mcp-rs", []string{"mcp:read"})
	quiet := slog.New(slog.DiscardHandler)
	jwtP, err := resourceserver.New(resourceserver.Config{Resource: m.jwtURI, Name: "JWT MCP Server", AuthorizationServers: []string{m.public.URL}, Scopes: []string{"mcp:read", "mcp:write"},
		Verifier: &resourceserver.JWTVerifier{Issuer: m.public.URL, Now: m.clock}, Now: m.clock, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	introP, err := resourceserver.New(resourceserver.Config{Resource: m.introURI, Name: "Opaque MCP Server", AuthorizationServers: []string{m.public.URL}, Scopes: []string{"mcp:read"},
		Verifier: &resourceserver.IntrospectionVerifier{Issuer: m.public.URL, ClientID: rsClient, ClientSecret: rsSecret}, Now: m.clock, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	jwtHandler, introHandler = mcpMux(jwtP), mcpMux(introP)
	return m
}

// mcpMux は examples/standalone/cmd/mcp-server と同じ形: /mcp は mcp:read、/mcp/admin は mcp:write。
func mcpMux(p *resourceserver.Protector) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(p.MetadataPath(), p.MetadataHandler())
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr, _ := resourceserver.FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(pr)
	})
	mux.Handle("/mcp", p.Protect(echo, "mcp:read"))
	mux.Handle("/mcp/admin", p.Protect(echo, "mcp:write"))
	return mux
}

// setDocument は CIMD 文書を書き換える（提供者が文書を更新した状況）。認可サーバーのキャッシュが切れるまでは古い内容が効く。
func (m *mcpSystem) setDocument(redirectURIs ...string) {
	m.docMu.Lock()
	defer m.docMu.Unlock()
	m.doc = map[string]any{
		"client_id": m.clientID, "client_name": "E2E MCP Client", "client_uri": "https://mcp-client.example",
		"redirect_uris": redirectURIs, "token_endpoint_auth_method": "none",
	}
}

// startMCPFlow は MCP クライアントの手順で始める: Resource Server にトークンなしで当たり、401 の WWW-Authenticate から
// RFC 9728 のメタデータを取り、authorization_servers の認可サーバーに resource 付きで認可要求を組む。
// scopes が nil なら 401 の scope（MCP「Scope Selection Strategy」）を使う。
func (m *mcpSystem) startMCPFlow(t *testing.T, resourceURL string, scopes []string) (*oauthclient.CodeFlow, <-chan url.Values, *oauthclient.Discovery) {
	t.Helper()
	ctx := context.Background()
	d, err := oauthclient.DiscoverResource(ctx, http.DefaultClient, resourceURL)
	if err != nil {
		t.Fatal(err)
	}
	if d.Metadata.AuthorizationServers[0] != m.public.URL {
		t.Fatalf("authorization_servers: %v", d.Metadata.AuthorizationServers)
	}
	if scopes == nil {
		scopes = strings.Fields(d.Challenge.Scope)
	}
	flow, cb := m.startFlow(t, m.clientID, "", scopes)
	flow.Resources = []string{d.Metadata.Resource}
	return flow, cb, d
}

// approve はブラウザで認可 URL を開き（自動承認）、Code を交換してトークンを返す。
func (m *mcpSystem) approve(t *testing.T, b *http.Client, flow *oauthclient.CodeFlow, cb <-chan url.Values) *oauthclient.TokenResponse {
	t.Helper()
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	code, err := flow.HandleCallback(waitCallback(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := flow.Exchange(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// call は Access Token で Resource Server を呼び、ステータスと WWW-Authenticate を返す。
func call(t *testing.T, rawURL, accessToken string) (int, oauthclient.Challenge) {
	t.Helper()
	res, err := oauthclient.CallResource(context.Background(), http.DefaultClient, http.MethodPost, rawURL, accessToken)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode, oauthclient.ParseChallenge(res.Header.Values("WWW-Authenticate"))
}

// TestMCPClientJWTAndOpaque は到達点そのもの: CIMD で識別される MCP クライアントが resource 付きで認可を受け、
// JWT / Opaque 各形式の Access Token が対応する MCP サーバーで受理され、別の MCP サーバーでは拒否される。
func TestMCPClientJWTAndOpaque(t *testing.T) {
	m := newMCPSystem(t, true)
	b := browser(t)

	// Discovery は CIMD 対応を広告する（CIMD §6）
	res, err := http.Get(m.public.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var md map[string]any
	_ = json.NewDecoder(res.Body).Decode(&md)
	res.Body.Close()
	if md["client_id_metadata_document_supported"] != true {
		t.Fatalf("client_id_metadata_document_supported: %v", md["client_id_metadata_document_supported"])
	}

	// JWT の MCP サーバー: 401 の scope は mcp:read
	flow, cb, d := m.startMCPFlow(t, m.jwtURI, nil)
	if d.Challenge.Scope != "mcp:read" || d.Metadata.ResourceName != "JWT MCP Server" {
		t.Fatalf("discovery: %+v %+v", d.Challenge, d.Metadata)
	}
	jwtTok := m.approve(t, b, flow, cb)
	if !strings.HasPrefix(jwtTok.AccessToken, "eyJ") || jwtTok.Scope != "mcp:read" || jwtTok.RefreshToken == "" {
		t.Fatalf("jwt token: %+v", jwtTok)
	}
	if code, _ := call(t, m.jwtURI, jwtTok.AccessToken); code != http.StatusOK {
		t.Fatalf("jwt rs: %d", code)
	}
	// 別の MCP サーバー向けには使えない（aud 不一致。MCP「Token Handling」）
	if code, ch := call(t, m.introURI, jwtTok.AccessToken); code != http.StatusUnauthorized || ch.Error != "invalid_token" {
		t.Fatalf("jwt token at opaque rs: %d %+v", code, ch)
	}

	// Opaque の MCP サーバー: Introspection で検証される
	flow, cb, _ = m.startMCPFlow(t, m.introURI, nil)
	opaqueTok := m.approve(t, b, flow, cb)
	if !strings.HasPrefix(opaqueTok.AccessToken, "at_") {
		t.Fatalf("opaque token: %+v", opaqueTok)
	}
	if code, _ := call(t, m.introURI, opaqueTok.AccessToken); code != http.StatusOK {
		t.Fatalf("opaque rs: %d", code)
	}
	if code, ch := call(t, m.jwtURI, opaqueTok.AccessToken); code != http.StatusUnauthorized || ch.Error != "invalid_token" {
		t.Fatalf("opaque token at jwt rs: %d %+v", code, ch)
	}

	// 同じ MCP クライアントの 2 回の認可は 1 つの Grant にまとまる（client_id は CIMD の URL）
	g, err := m.store.FindGrant(context.Background(), m.clientID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if g.ClientID != m.clientID || !g.Active() {
		t.Fatalf("grant: %+v", g)
	}

	// Revocation は Introspection には即時反映されるが、JWT のローカル検証には伝播しない（ADR-0006 §1 の帰結）
	if err := flow.Revoke(context.Background(), opaqueTok.AccessToken, "access_token"); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, m.introURI, opaqueTok.AccessToken); code != http.StatusUnauthorized {
		t.Fatalf("revoked opaque token must be rejected: %d", code)
	}
	if err := flow.Revoke(context.Background(), jwtTok.AccessToken, "access_token"); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, m.jwtURI, jwtTok.AccessToken); code != http.StatusOK {
		t.Fatalf("revoked jwt is still valid for local validation until exp: %d", code)
	}
}

// TestMCPStepUpAuthorization は insufficient_scope からの再認可。403 の scope を足して認可し直すと
// Grant の scope が和集合に広がり、新しいトークンで通る。
func TestMCPStepUpAuthorization(t *testing.T) {
	m := newMCPSystem(t, true)
	b := browser(t)
	ctx := context.Background()

	flow, cb, _ := m.startMCPFlow(t, m.jwtURI, []string{"mcp:read"})
	tok := m.approve(t, b, flow, cb)
	code, ch := call(t, m.jwtURI+"/admin", tok.AccessToken)
	if code != http.StatusForbidden || ch.Error != "insufficient_scope" || ch.Scope != "mcp:write" || !strings.HasSuffix(ch.ResourceMetadata, "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("admin with read token: %d %+v", code, ch)
	}

	// MCP「Runtime Insufficient Scope Errors」: 403 の scope を既存の scope に足して再認可する
	have := strings.Fields(tok.Scope)
	want := append(have, strings.Fields(ch.Scope)...)
	flow2, cb2, _ := m.startMCPFlow(t, m.jwtURI, want)
	tok2 := m.approve(t, b, flow2, cb2)
	if tok2.Scope != "mcp:read mcp:write" {
		t.Fatalf("step-up token scope: %q", tok2.Scope)
	}
	if code, _ := call(t, m.jwtURI+"/admin", tok2.AccessToken); code != http.StatusOK {
		t.Fatalf("admin with step-up token: %d", code)
	}
	g, err := m.store.FindGrant(ctx, m.clientID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(g.Scopes, " ") != "mcp:read mcp:write" {
		t.Fatalf("grant scopes must be the union: %v", g.Scopes)
	}
	// 最初のトークンは mcp:read のままで、Grant が広がっても権限は増えない
	if code, _ := call(t, m.jwtURI+"/admin", tok.AccessToken); code != http.StatusForbidden {
		t.Fatalf("old token must keep its scope: %d", code)
	}
	// Refresh でも Audience は変わらない（Family の Audience の範囲内）
	refreshed, err := flow2.Refresh(ctx, tok2.RefreshToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, m.jwtURI+"/admin", refreshed.AccessToken); code != http.StatusOK {
		t.Fatalf("refreshed token: %d", code)
	}
	// Refresh で別の resource に乗り換えることはできない（RFC 8707 §2.2、invalid_target）
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}, "resource": {m.introURI}, "client_id": {m.clientID}}
	res, err := http.PostForm(m.public.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	var terr oauthclient.TokenError
	_ = json.NewDecoder(res.Body).Decode(&terr)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || terr.Code != "invalid_target" {
		t.Fatalf("refresh to another resource: %d %+v", res.StatusCode, terr)
	}
}

// TestMCPInvalidRequests は MCP クライアント特有の失敗: resource なし、未設定の resource、resource の scope 上限超過。
func TestMCPInvalidRequests(t *testing.T) {
	m := newMCPSystem(t, true)
	b := browser(t)
	authorize := func(flow *oauthclient.CodeFlow, cb <-chan url.Values) error {
		t.Helper()
		res, err := b.Get(flow.AuthorizationURL())
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		_, err = flow.HandleCallback(waitCallback(t, cb))
		return err
	}
	var aerr *oauthclient.AuthorizationError

	// 設定にない resource は invalid_target（RFC 8707 §2。redirect URI は検証済みなのでリダイレクトして返す）
	flow, cb := m.startFlow(t, m.clientID, "", []string{"mcp:read"})
	flow.Resources = []string{"https://unknown.example.com/mcp"}
	if err := authorize(flow, cb); !errors.As(err, &aerr) || aerr.Code != "invalid_target" {
		t.Fatalf("unknown resource: %v", err)
	}
	// MCP Client は resource が必須（ADR-0008 §4）
	flow, cb = m.startFlow(t, m.clientID, "", []string{"mcp:read"})
	if err := authorize(flow, cb); !errors.As(err, &aerr) || aerr.Code != "invalid_request" || !strings.Contains(aerr.Description, "resource") {
		t.Fatalf("missing resource: %v", err)
	}
	// resource の scope 上限（Opaque サーバーは mcp:read だけ）を超える要求は invalid_scope
	flow, cb = m.startFlow(t, m.clientID, "", []string{"mcp:read", "mcp:write"})
	flow.Resources = []string{m.introURI}
	if err := authorize(flow, cb); !errors.As(err, &aerr) || aerr.Code != "invalid_scope" {
		t.Fatalf("scope beyond resource: %v", err)
	}
	// 2 つの resource の形式が揃っていない（jwt と opaque）要求は invalid_target（ADR-0008 §3）
	flow, cb = m.startFlow(t, m.clientID, "", []string{"mcp:read"})
	flow.Resources = []string{m.jwtURI, m.introURI}
	if err := authorize(flow, cb); !errors.As(err, &aerr) || aerr.Code != "invalid_target" {
		t.Fatalf("mixed formats: %v", err)
	}
	// 文書にない redirect URI はリダイレクトせずエラーページ
	flow, _ = m.startFlow(t, m.clientID, "", []string{"mcp:read"})
	flow.RedirectURI = "http://localhost:9/evil"
	flow.Resources = []string{m.jwtURI}
	res, err := b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "redirect_uri") {
		t.Fatalf("bad redirect: %d %s", res.StatusCode, body)
	}
	// 取得できない文書（404）の client_id は理由付きの invalid_request で、リダイレクトしない
	flow, _ = m.startFlow(t, m.docs.URL+"/missing.json", "", []string{"mcp:read"})
	flow.Resources = []string{m.jwtURI}
	res, err = b.Get(flow.AuthorizationURL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "metadata document") {
		t.Fatalf("unresolvable client: %d %s", res.StatusCode, body)
	}
}

// TestMCPDocumentChange は CIMD 文書の差し替え。提供者が redirect_uris を変えても、認可サーバーはキャッシュが
// 切れるまで古い文書で照合し（CIMD §5.2）、切れたあとは新しい文書で照合する。
func TestMCPDocumentChange(t *testing.T) {
	m := newMCPSystem(t, true, "http://localhost:3000/callback") // http://localhost はポートまで完全一致
	b := browser(t)
	ctx := context.Background()

	// start は redirectURI で認可要求を始め、自動承認の loginapp を経た最終応答を返す。文書どおりの redirect URI なら
	// 照合に通って Code がブラウザへ返るが、localhost:3000 / 4000 では誰も待ち受けていないので接続エラーになる。
	// その url.Error の URL に code= が付いていることを「照合に通った」証拠として見る。
	start := func(redirectURI string) (*http.Response, error) {
		md, err := oauthclient.Discover(ctx, http.DefaultClient, m.public.URL)
		if err != nil {
			t.Fatal(err)
		}
		flow, err := oauthclient.NewCodeFlow(md, m.clientID, redirectURI, []string{"mcp:read"})
		if err != nil {
			t.Fatal(err)
		}
		flow.Resources = []string{m.jwtURI}
		return b.Get(flow.AuthorizationURL())
	}
	res, err := start("http://localhost:3000/callback")
	if err == nil {
		res.Body.Close()
	}
	var uerr *url.Error
	if !errors.As(err, &uerr) || !strings.Contains(uerr.URL, "localhost:3000/callback") || !strings.Contains(uerr.URL, "code=") {
		t.Fatalf("v1 redirect: %v", err)
	}

	// 提供者が文書を更新した。キャッシュが生きている間は新しい redirect URI は通らない
	m.setDocument("http://localhost:4000/callback")
	res, err = start("http://localhost:4000/callback")
	if err != nil {
		t.Fatalf("expected an error page, got %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "redirect_uri") {
		t.Fatalf("v2 before cache expiry: %d %s", res.StatusCode, body)
	}

	// キャッシュ切れ（下限 1 分）のあとは新しい文書で照合する
	m.advance(2 * time.Minute)
	res, err = start("http://localhost:4000/callback")
	if err == nil {
		res.Body.Close()
	}
	if !errors.As(err, &uerr) || !strings.Contains(uerr.URL, "localhost:4000/callback") || !strings.Contains(uerr.URL, "code=") {
		t.Fatalf("v2 after cache expiry: %v", err)
	}
	res, err = start("http://localhost:3000/callback")
	if err != nil {
		t.Fatalf("expected an error page for the old redirect uri, got %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("v1 after change: %d", res.StatusCode)
	}
}
