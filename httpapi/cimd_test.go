package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/cimd"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/token"
)

// cimdEnv は CIMD 文書を TLS で配信するテストサーバーと、CIMD を有効にしたエンジン。
type cimdEnv struct {
	*env
	docs *httptest.Server
	// status が 0 以外なら文書の代わりにそのステータスを返す
	status int
}

func newCIMDEnv(t *testing.T) *cimdEnv {
	t.Helper()
	ce := &cimdEnv{}
	ce.docs = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ce.status != 0 {
			w.WriteHeader(ce.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id": ce.docs.URL + r.URL.Path, "client_name": "Example MCP Client", "client_uri": "https://mcp-client.example",
			"redirect_uris": []string{"http://localhost:3000/callback"},
		})
	}))
	ce.docs.Config.ErrorLog = log.New(io.Discard, "", 0)
	ce.docs.StartTLS()
	t.Cleanup(ce.docs.Close)

	tr := cimd.NewTransport(true) // 文書サーバーは loopback なので開発用の緩和が要る
	tr.TLSClientConfig = ce.docs.Client().Transport.(*http.Transport).TLSClientConfig
	ce.env = newEnvWith(t, func(cfg *authengine.Config) {
		cfg.CIMD = &cimd.Config{HTTPClient: &http.Client{Transport: tr, Timeout: 2 * time.Second}, AllowLoopback: true}
	})
	return ce
}

func (ce *cimdEnv) clientID() string { return ce.docs.URL + "/client.json" }

func (ce *cimdEnv) authorizeQuery() url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {ce.clientID()}, "redirect_uri": {"http://localhost:3000/callback"},
		"scope": {"openid files:read"}, "state": {"s1"}, "code_challenge": {rfcChallenge}, "code_challenge_method": {"S256"},
		"nonce": {"n1"}, "resource": {"https://mcp.example.com"},
	}
}

// CIMD の client_id で Authorization Code + PKCE を完走する（ADR-0008 §4、§5、§6）。
func TestCIMDClientFlow(t *testing.T) {
	ce := newCIMDEnv(t)
	e := ce.env

	// Discovery に client_id_metadata_document_supported: true（CIMD §6）
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		rec := e.do(e.public, httptest.NewRequest(http.MethodGet, path, nil))
		if !strings.Contains(rec.Body.String(), `"client_id_metadata_document_supported":true`) {
			t.Fatalf("%s: %s", path, rec.Body)
		}
	}

	cookie, txnID, _ := e.authorize(ce.authorizeQuery())

	// Interaction API: profile=mcp、client_uri、redirect_uri が見える（ADR-0008 §6）
	rec := e.do(e.internal, e.interactionReq(http.MethodGet, "/transactions/"+txnID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get txn: %d %s", rec.Code, rec.Body)
	}
	var view struct {
		Client struct {
			ClientID  string `json:"client_id"`
			Name      string `json:"name"`
			Profile   string `json:"profile"`
			ClientURI string `json:"client_uri"`
		} `json:"client"`
		Request struct {
			RedirectURI string   `json:"redirect_uri"`
			Scopes      []string `json:"scopes"`
			Resource    []string `json:"resource"`
		} `json:"request"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Client.ClientID != ce.clientID() || view.Client.Profile != "mcp" || view.Client.Name != "Example MCP Client" ||
		view.Client.ClientURI != "https://mcp-client.example" || view.Request.RedirectURI != "http://localhost:3000/callback" ||
		view.Request.Resource[0] != "https://mcp.example.com" {
		t.Fatalf("txn view: %s", rec.Body)
	}

	// Complete（文書に scope がないので files:read も付与できる）→ Resume → localhost へ code
	rec = e.do(e.internal, e.interactionReq(http.MethodPost, "/transactions/"+txnID+"/complete", map[string]any{
		"subject": "alice", "authenticated_at": now.Add(-time.Minute).Format(time.RFC3339), "granted_scopes": []string{"openid", "files:read"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ResumeURL string `json:"resume_url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	rec = e.resume(out.ResumeURL, cookie)
	cb, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || cb.Host != "localhost:3000" || cb.Path != "/callback" || cb.Query().Get("code") == "" || cb.Query().Get("state") != "s1" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// /token: public クライアントなので client_id はフォーム、認証方式は none
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {"http://localhost:3000/callback"},
		"code_verifier": {rfcVerifier}, "client_id": {ce.clientID()}}
	rec = e.do(e.public, e.tokenReq(form, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	var res token.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.AccessToken == "" || res.RefreshToken == "" || res.IDToken == "" || res.Scope != "openid files:read" {
		t.Fatalf("token response: %s", rec.Body)
	}
	var idc struct {
		Aud []string `json:"aud"`
		Sub string   `json:"sub"`
	}
	if _, err := e.keys.Verify(res.IDToken, &idc); err != nil || idc.Aud[0] != ce.clientID() || idc.Sub != "alice" {
		t.Fatalf("id token: %+v %v", idc, err)
	}

	// Refresh（Rotation）も URL の client_id で動く
	rec = e.do(e.public, e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {res.RefreshToken}, "client_id": {ce.clientID()}}, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body)
	}

	// Introspection: client_id は URL、aud は resource
	rs, secret, err := client.NewMachine(client.MachineParams{ID: "rs", Name: "Resource Server", Scopes: []string{"api"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateClient(context.Background(), rs); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(url.Values{"token": {res.AccessToken}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("rs", string(secret))
	rec = e.do(e.public, req)
	var in map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &in)
	if in["active"] != true || in["client_id"] != ce.clientID() || in["aud"].([]any)[0] != "https://mcp.example.com" {
		t.Fatalf("introspection: %s", rec.Body)
	}
}

// resource がない MCP の要求は invalid_request でリダイレクト（ADR-0008 §4）。
func TestCIMDClientRequiresResource(t *testing.T) {
	ce := newCIMDEnv(t)
	q := ce.authorizeQuery()
	q.Del("resource")
	rec := ce.do(ce.public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Host != "localhost:3000" || loc.Query().Get("error") != "invalid_request" ||
		!strings.Contains(loc.Query().Get("error_description"), "resource is required") || loc.Query().Get("state") != "s1" {
		t.Fatalf("missing resource: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// 文書を取得できない client_id は、理由付きの invalid_request をエラーページで返す（リダイレクトしない）。
func TestCIMDFetchFailureIsNotRedirected(t *testing.T) {
	ce := newCIMDEnv(t)
	ce.status = http.StatusInternalServerError
	rec := ce.do(ce.public, httptest.NewRequest(http.MethodGet, "/authorize?"+ce.authorizeQuery().Encode(), nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") || !strings.Contains(rec.Body.String(), "status 500") {
		t.Fatalf("fetch failure: %d %s", rec.Code, rec.Body)
	}
	// トークン要求では invalid_client
	rec = ce.do(ce.public, ce.tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {ce.clientID()}}, "", ""))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("token with unresolvable client: %d %s", rec.Code, rec.Body)
	}
}

// CIMD を有効にしていなければ URL の client_id は不明な Client。
func TestURLClientIDWithoutCIMD(t *testing.T) {
	e := newEnv(t)
	q := authorizeQuery()
	q.Set("client_id", "https://mcp-client.example/client.json")
	rec := e.do(e.public, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown client_id") {
		t.Fatalf("without cimd: %d %s", rec.Code, rec.Body)
	}
}
