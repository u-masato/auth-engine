package adminapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/adminapi"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/httpapi"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/storage/memory"
	"github.com/u-masato/auth-engine/token"
)

const adminToken = "admin-test-token-0123456789abcdef0123456789"

// env は In-Memory Store のエンジンと、その上の管理 API を httptest で立てた環境。
type env struct {
	api    *httptest.Server
	store  *memory.Store
	engine *authengine.Engine
}

func newEnv(t *testing.T) *env {
	t.Helper()
	discard := slog.New(slog.DiscardHandler)
	store := memory.New()
	ks := keys.NewSet()
	k, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.AddSigning(k); err != nil {
		t.Fatal(err)
	}
	engine, err := authengine.New(authengine.Config{Issuer: "https://as.example.com", Store: store, Keys: ks, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	api, err := adminapi.New(adminapi.Config{Store: store, Grants: engine.Grants,
		Auth: httpapi.BearerAuthenticator{Token: adminToken}, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &env{api: srv, store: store, engine: engine}
}

// call は管理 API を呼び、ステータスと本文を返す。body が nil でなければ JSON にして送る。
func (e *env) call(t *testing.T, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	return e.callWith(t, adminToken, method, path, body)
}

func (e *env) callWith(t *testing.T, bearer, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string: // 生の本文（壊れた JSON の確認用）
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, e.api.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, data
}

func decode[T any](t *testing.T, data []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return v
}

// wantError は応答がエラーの形（error と error_description）で、期待したステータスとコードであることを確かめる。
func wantError(t *testing.T, res *http.Response, data []byte, status int, code string) {
	t.Helper()
	body := decode[struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}](t, data)
	if res.StatusCode != status || body.Error != code || body.Description == "" {
		t.Fatalf("got %d %s, want %d %s", res.StatusCode, data, status, code)
	}
}

type clientsBody struct {
	Clients   []adminapi.ClientSpec `json:"clients"`
	NextAfter string                `json:"next_after"`
}

type grantsBody struct {
	Grants []struct {
		ClientID  string     `json:"client_id"`
		Subject   string     `json:"subject"`
		Scopes    []string   `json:"scopes"`
		Status    string     `json:"status"`
		RevokedAt *time.Time `json:"revoked_at"`
	} `json:"grants"`
	NextAfter string `json:"next_after"`
}

func webSpec(id string) adminapi.ClientSpec {
	return adminapi.ClientSpec{ClientID: id, Profile: "web", Name: "Web " + id,
		RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid", "profile"}}
}

// 認証のない要求はどのルートにも届かない。設定で認証を外すこともできない（fail-closed）。
func TestAuthenticationIsRequired(t *testing.T) {
	e := newEnv(t)
	for _, bearer := range []string{"", "wrong-token", adminToken + "x"} {
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/clients"}, {http.MethodPost, "/clients"}, {http.MethodDelete, "/clients/any"},
			{http.MethodPost, "/clients/any/secret"}, {http.MethodGet, "/clients/any/grants"},
		} {
			res, data := e.callWith(t, bearer, route.method, route.path, webSpec("w1"))
			wantError(t, res, data, http.StatusUnauthorized, "unauthorized")
			if !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("%s %s: missing WWW-Authenticate", route.method, route.path)
			}
		}
	}
	if _, err := e.store.GetClient(t.Context(), "w1"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("an unauthenticated request must not create a client: %v", err)
	}
	if _, err := adminapi.New(adminapi.Config{Store: e.store, Grants: e.engine.Grants}); err == nil {
		t.Fatal("New must reject a config without Auth")
	}
}

func TestClientLifecycle(t *testing.T) {
	e := newEnv(t)

	// 登録: 201、Location、生成したシークレット
	res, data := e.call(t, http.MethodPost, "/clients", webSpec("w1"))
	if res.StatusCode != http.StatusCreated || res.Header.Get("Location") != "/clients/w1" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %v %s", res.StatusCode, res.Header, data)
	}
	created := decode[adminapi.ClientSpec](t, data)
	if created.ClientID != "w1" || created.Profile != "web" || len(created.ClientSecret) < client.MinSecretLength ||
		created.IDTokenAlg != client.AlgRS256 || created.CreatedAt == nil {
		t.Fatalf("created client: %+v", created)
	}
	stored, err := e.store.GetClient(t.Context(), "w1")
	if err != nil || !stored.VerifySecret(created.ClientSecret) {
		t.Fatalf("the returned secret must verify against the store: %+v, %v", stored, err)
	}
	if strings.Contains(string(data), stored.SecretHash) {
		t.Fatal("the response must not contain the secret hash")
	}

	// 取得: シークレットは返らない。空の配列は [] で返る
	res, data = e.call(t, http.MethodGet, "/clients/w1", nil)
	got := decode[adminapi.ClientSpec](t, data)
	if res.StatusCode != http.StatusOK || got.ClientSecret != "" || got.Name != "Web w1" || !strings.Contains(string(data), `"resources":[]`) {
		t.Fatalf("get: %d %s", res.StatusCode, data)
	}

	// 更新: GET の結果を書き換えてそのまま PUT に渡せる（created_at は無視される）
	got.Name, got.Scopes, got.AccessTokenTTL = "Renamed", []string{"openid"}, 300
	res, data = e.call(t, http.MethodPut, "/clients/w1", got)
	updated := decode[adminapi.ClientSpec](t, data)
	if res.StatusCode != http.StatusOK || updated.Name != "Renamed" || updated.AccessTokenTTL != 300 || updated.ClientSecret != "" {
		t.Fatalf("update: %d %s", res.StatusCode, data)
	}
	stored, err = e.store.GetClient(t.Context(), "w1")
	if err != nil || stored.Name != "Renamed" || stored.AccessTokenTTL != 5*time.Minute || len(stored.Scopes) != 1 ||
		!stored.VerifySecret(created.ClientSecret) || !stored.CreatedAt.Equal(*created.CreatedAt) {
		t.Fatalf("stored client after update: %+v, %v", stored, err)
	}

	// 変えられない項目と、Profile の規則に反する値は保存しない
	for name, mutate := range map[string]func(*adminapi.ClientSpec){
		"client_id":     func(sp *adminapi.ClientSpec) { sp.ClientID = "other" },
		"profile":       func(sp *adminapi.ClientSpec) { sp.Profile = "native" },
		"client_secret": func(sp *adminapi.ClientSpec) { sp.ClientSecret = strings.Repeat("s", 40) },
		"client_uri":    func(sp *adminapi.ClientSpec) { sp.ClientURI = "https://app.example.com" },
		"redirect_uris": func(sp *adminapi.ClientSpec) { sp.RedirectURIs = []string{"http://example.com/cb"} },
		"ttl":           func(sp *adminapi.ClientSpec) { sp.AccessTokenTTL = 1 << 40 },
	} {
		sp := updated
		mutate(&sp)
		res, data = e.call(t, http.MethodPut, "/clients/w1", sp)
		wantError(t, res, data, http.StatusBadRequest, "invalid_client_metadata")
		if after, err := e.store.GetClient(t.Context(), "w1"); err != nil || after.Name != "Renamed" || after.Profile != client.ProfileWeb ||
			!after.VerifySecret(created.ClientSecret) || after.RedirectURIs[0] != "https://app.example.com/cb" {
			t.Fatalf("%s: a rejected update must not change the client: %+v, %v", name, after, err)
		}
	}

	// 削除: 204。以後は 404
	res, data = e.call(t, http.MethodDelete, "/clients/w1", nil)
	if res.StatusCode != http.StatusNoContent || len(data) != 0 {
		t.Fatalf("delete: %d %s", res.StatusCode, data)
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/clients/w1"}, {http.MethodDelete, "/clients/w1"}, {http.MethodPost, "/clients/w1/secret"},
	} {
		res, data = e.call(t, route.method, route.path, nil)
		wantError(t, res, data, http.StatusNotFound, "not_found")
	}
	res, data = e.call(t, http.MethodPut, "/clients/w1", updated)
	wantError(t, res, data, http.StatusNotFound, "not_found")
}

func TestCreateClientErrors(t *testing.T) {
	e := newEnv(t)
	if res, data := e.call(t, http.MethodPost, "/clients", webSpec("w1")); res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", res.StatusCode, data)
	}
	res, data := e.call(t, http.MethodPost, "/clients", webSpec("w1"))
	wantError(t, res, data, http.StatusConflict, "conflict")

	invalid := map[string]adminapi.ClientSpec{
		"unknown profile":        {ClientID: "x", Profile: "custom", Name: "x"},
		"web with http redirect": {ClientID: "x", Profile: "web", Name: "x", RedirectURIs: []string{"http://example.com/cb"}, Scopes: []string{"openid"}},
		"web with short secret":  {ClientID: "x", Profile: "web", Name: "x", RedirectURIs: []string{"https://example.com/cb"}, Scopes: []string{"openid"}, ClientSecret: "short"},
		"native with secret": {ClientID: "x", Profile: "native", Name: "x", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"},
			ClientSecret: strings.Repeat("s", 40)},
		"machine with redirect": {ClientID: "x", Profile: "machine", Name: "x", RedirectURIs: []string{"https://example.com/cb"}, Scopes: []string{"api.read"}},
		"web with client_uri":   {ClientID: "x", Profile: "web", Name: "x", RedirectURIs: []string{"https://example.com/cb"}, Scopes: []string{"openid"}, ClientURI: "https://example.com"},
		"negative ttl":          {ClientID: "x", Profile: "machine", Name: "x", Scopes: []string{"api.read"}, AccessTokenTTL: -1},
		"mcp without url id":    {ClientID: "x", Profile: "mcp", Name: "x", RedirectURIs: []string{"http://localhost:3000/cb"}},
		"mcp scope with space": {ClientID: "https://x.example/c.json", Profile: "mcp", Name: "x", RedirectURIs: []string{"http://localhost:3000/cb"},
			Scopes: []string{"mcp:read mcp:write"}},
	}
	for name, sp := range invalid {
		res, data := e.call(t, http.MethodPost, "/clients", sp)
		if res.StatusCode != http.StatusBadRequest || decode[map[string]string](t, data)["error"] != "invalid_client_metadata" {
			t.Errorf("%s: got %d %s", name, res.StatusCode, data)
		}
	}
	// 本文の誤り: 壊れた JSON、未知の項目（打ち間違い）、余分なデータ
	for _, raw := range []string{`{"profile":`, `{"profile":"machine","name":"x","scope":["api.read"]}`, `{"profile":"machine","name":"x","scopes":["a"]} {}`} {
		res, data := e.call(t, http.MethodPost, "/clients", raw)
		wantError(t, res, data, http.StatusBadRequest, "invalid_request")
	}
	if _, err := e.store.GetClient(t.Context(), "x"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a rejected request must not create a client: %v", err)
	}

	// client_id を省略すると生成する。指定したシークレットはそのまま使う
	secret := strings.Repeat("m", 40)
	res, data = e.call(t, http.MethodPost, "/clients", adminapi.ClientSpec{Profile: "machine", Name: "Batch", Scopes: []string{"api.read"}, ClientSecret: secret})
	created := decode[adminapi.ClientSpec](t, data)
	if res.StatusCode != http.StatusCreated || created.ClientID == "" || created.ClientSecret != secret || created.IDTokenAlg != "" {
		t.Fatalf("machine client: %d %s", res.StatusCode, data)
	}
}

func TestListClientsPaging(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"b", "c", "a"} {
		if res, data := e.call(t, http.MethodPost, "/clients", webSpec(id)); res.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: %d %s", id, res.StatusCode, data)
		}
	}
	ids := func(b clientsBody) string {
		out := []string{}
		for _, c := range b.Clients {
			if c.ClientSecret != "" {
				t.Fatalf("a listed client must not carry a secret: %+v", c)
			}
			out = append(out, c.ClientID)
		}
		return strings.Join(out, ",")
	}
	_, data := e.call(t, http.MethodGet, "/clients?limit=2", nil)
	first := decode[clientsBody](t, data)
	if ids(first) != "a,b" || first.NextAfter != "b" {
		t.Fatalf("first page: %s", data)
	}
	_, data = e.call(t, http.MethodGet, "/clients?limit=2&after="+first.NextAfter, nil)
	if second := decode[clientsBody](t, data); ids(second) != "c" || second.NextAfter != "" {
		t.Fatalf("second page: %s", data)
	}
	_, data = e.call(t, http.MethodGet, "/clients", nil)
	if all := decode[clientsBody](t, data); ids(all) != "a,b,c" || all.NextAfter != "" {
		t.Fatalf("default page: %s", data)
	}
	_, data = e.call(t, http.MethodGet, "/clients?after=z", nil)
	if !strings.Contains(string(data), `"clients":[]`) {
		t.Fatalf("an empty page must be an empty array: %s", data)
	}
	for _, q := range []string{"limit=0", "limit=abc", "limit=201", "limit=-1"} {
		res, data := e.call(t, http.MethodGet, "/clients?"+q, nil)
		wantError(t, res, data, http.StatusBadRequest, "invalid_request")
	}
}

// exchange は client_credentials でトークンを取る（シークレットが通るかの確認用）。
func (e *env) exchange(t *testing.T, id, secret string) error {
	t.Helper()
	_, err := e.engine.Token.Exchange(t.Context(), token.Request{GrantType: "client_credentials",
		Credentials: token.Credentials{ClientID: id, Secret: secret, Method: client.AuthClientSecretBasic}})
	return err
}

// 再発行すると新しいシークレットだけが通る。再発行より前に取得した内容で更新しても、旧シークレットは戻らない。
func TestRotateSecret(t *testing.T) {
	e := newEnv(t)
	_, data := e.call(t, http.MethodPost, "/clients", adminapi.ClientSpec{ClientID: "batch", Profile: "machine", Name: "Batch", Scopes: []string{"api.read"}})
	created := decode[adminapi.ClientSpec](t, data)
	if err := e.exchange(t, "batch", created.ClientSecret); err != nil {
		t.Fatalf("the initial secret must work: %v", err)
	}
	_, data = e.call(t, http.MethodGet, "/clients/batch", nil)
	stale := decode[adminapi.ClientSpec](t, data)

	res, data := e.call(t, http.MethodPost, "/clients/batch/secret", nil)
	rotated := decode[adminapi.ClientSpec](t, data)
	if res.StatusCode != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" || rotated.ClientID != "batch" ||
		len(rotated.ClientSecret) < client.MinSecretLength || rotated.ClientSecret == created.ClientSecret {
		t.Fatalf("rotate: %d %s", res.StatusCode, data)
	}
	var terr *token.Error
	if err := e.exchange(t, "batch", created.ClientSecret); !errors.As(err, &terr) || terr.Code != "invalid_client" {
		t.Fatalf("the old secret must be rejected with invalid_client: %v", err)
	}
	if err := e.exchange(t, "batch", rotated.ClientSecret); err != nil {
		t.Fatalf("the new secret must work: %v", err)
	}

	stale.Name = "Renamed"
	if res, data := e.call(t, http.MethodPut, "/clients/batch", stale); res.StatusCode != http.StatusOK {
		t.Fatalf("stale update: %d %s", res.StatusCode, data)
	}
	if err := e.exchange(t, "batch", created.ClientSecret); err == nil {
		t.Fatal("a stale update must not bring the old secret back")
	}
	if err := e.exchange(t, "batch", rotated.ClientSecret); err != nil {
		t.Fatalf("the new secret must survive an update: %v", err)
	}

	// public クライアントはシークレットを持たない
	native := adminapi.ClientSpec{ClientID: "cli", Profile: "native", Name: "CLI", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}
	if res, data := e.call(t, http.MethodPost, "/clients", native); res.StatusCode != http.StatusCreated || strings.Contains(string(data), "client_secret") {
		t.Fatalf("create native: %d %s", res.StatusCode, data)
	}
	res, data = e.call(t, http.MethodPost, "/clients/cli/secret", nil)
	wantError(t, res, data, http.StatusBadRequest, "invalid_request")
}

func TestClientGrants(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.call(t, http.MethodPost, "/clients", webSpec("w1"))
	now := time.Now()
	for _, sub := range []string{"carol", "alice", "bob"} {
		if _, err := e.store.UpsertGrant(ctx, &grant.Grant{ID: "g-" + sub, ClientID: "w1", Subject: sub, Scopes: []string{"openid"},
			Claims: map[string]any{"email": sub + "@example.com"}, Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.store.UpsertGrant(ctx, &grant.Grant{ID: "g-other", ClientID: "w2", Subject: "alice", Scopes: []string{"openid"},
		Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	subjects := func(b grantsBody) string {
		out := []string{}
		for _, g := range b.Grants {
			if g.ClientID != "w1" {
				t.Fatalf("grant of another client: %+v", g)
			}
			out = append(out, g.Subject+":"+g.Status)
		}
		return strings.Join(out, ",")
	}

	res, data := e.call(t, http.MethodGet, "/clients/w1/grants?limit=2", nil)
	first := decode[grantsBody](t, data)
	if res.StatusCode != http.StatusOK || subjects(first) != "alice:active,bob:active" || first.NextAfter != "bob" {
		t.Fatalf("first page: %d %s", res.StatusCode, data)
	}
	if strings.Contains(string(data), "example.com") {
		t.Fatalf("claims must not be exposed: %s", data)
	}
	_, data = e.call(t, http.MethodGet, "/clients/w1/grants?limit=2&after=bob", nil)
	if second := decode[grantsBody](t, data); subjects(second) != "carol:active" || second.NextAfter != "" {
		t.Fatalf("second page: %s", data)
	}

	// 連携の解除: 204、冪等。一覧には revoked として残る
	for range 2 {
		res, data = e.call(t, http.MethodDelete, "/clients/w1/grants?subject=alice", nil)
		if res.StatusCode != http.StatusNoContent || len(data) != 0 {
			t.Fatalf("revoke: %d %s", res.StatusCode, data)
		}
	}
	_, data = e.call(t, http.MethodGet, "/clients/w1/grants", nil)
	all := decode[grantsBody](t, data)
	if subjects(all) != "alice:revoked,bob:active,carol:active" || all.Grants[0].RevokedAt == nil || all.Grants[1].RevokedAt != nil {
		t.Fatalf("after revoke: %s", data)
	}
	// 他の Client の同じ subject には触れない
	if g, err := e.store.FindGrant(ctx, "w2", "alice"); err != nil || !g.Active() {
		t.Fatalf("the grant of another client must stay active: %+v, %v", g, err)
	}

	res, data = e.call(t, http.MethodDelete, "/clients/w1/grants?subject=nobody", nil)
	wantError(t, res, data, http.StatusNotFound, "not_found")
	res, data = e.call(t, http.MethodDelete, "/clients/w1/grants", nil)
	wantError(t, res, data, http.StatusBadRequest, "invalid_request")
	if g, err := e.store.FindGrant(ctx, "w1", "bob"); err != nil || !g.Active() {
		t.Fatalf("a request without subject must not revoke anything: %+v, %v", g, err)
	}

	// Store にない client_id（CIMD で解決した Client）の Grant も引ける。なければ空の一覧
	const cimdID = "https://mcp-client.example/oauth/client.json"
	if _, err := e.store.UpsertGrant(ctx, &grant.Grant{ID: "g-cimd", ClientID: cimdID, Subject: "dave", Scopes: []string{"mcp:read"},
		Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_, data = e.call(t, http.MethodGet, adminapi.ClientPath(cimdID)+"/grants", nil)
	if b := decode[grantsBody](t, data); len(b.Grants) != 1 || b.Grants[0].Subject != "dave" || b.Grants[0].ClientID != cimdID {
		t.Fatalf("grants of a client that is not in the store: %s", data)
	}
	_, data = e.call(t, http.MethodGet, "/clients/unknown/grants", nil)
	if !strings.Contains(string(data), `"grants":[]`) {
		t.Fatalf("an unknown client must yield an empty array: %s", data)
	}
}

// 事前登録した MCP Client（CIMD §7）は client_id が URL なので、パスではエスケープして指定する。
func TestURLClientID(t *testing.T) {
	e := newEnv(t)
	const id = "https://mcp-client.example/oauth/client.json"
	res, data := e.call(t, http.MethodPost, "/clients", adminapi.ClientSpec{ClientID: id, Profile: "mcp", Name: "MCP Client",
		ClientURI: "https://mcp-client.example", RedirectURIs: []string{"http://localhost:3000/callback"},
		Resources: []string{"https://mcp.example.com/mcp"}, AccessTokenTTL: 600})
	if res.StatusCode != http.StatusCreated || res.Header.Get("Location") != adminapi.ClientPath(id) {
		t.Fatalf("create: %d %v %s", res.StatusCode, res.Header, data)
	}
	res, data = e.call(t, http.MethodGet, adminapi.ClientPath(id), nil)
	got := decode[adminapi.ClientSpec](t, data)
	if res.StatusCode != http.StatusOK || got.ClientID != id || got.Profile != "mcp" || got.ClientURI != "https://mcp-client.example" ||
		got.AccessTokenTTL != 600 || len(got.Resources) != 1 || got.ClientSecret != "" {
		t.Fatalf("get: %d %s", res.StatusCode, data)
	}
	// client_uri は現在値と同じなら PUT に含めてよい（GET の結果をそのまま渡せる）
	got.Name = "Renamed MCP"
	if res, data := e.call(t, http.MethodPut, adminapi.ClientPath(id), got); res.StatusCode != http.StatusOK {
		t.Fatalf("update: %d %s", res.StatusCode, data)
	}
	if res, data := e.call(t, http.MethodDelete, adminapi.ClientPath(id), nil); res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d %s", res.StatusCode, data)
	}
}
