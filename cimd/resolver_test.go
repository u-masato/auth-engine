package cimd_test

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/cimd"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

var base = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// docServer は CIMD 文書を TLS で配信する httptest サーバー。文書の内容と応答は差し替えられる。
type docServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	doc   map[string]any
	hooks func(w http.ResponseWriter) bool // true を返したら文書を書かない
	hits  atomic.Int32
}

func newDocServer(t *testing.T) *docServer {
	t.Helper()
	d := &docServer{}
	d.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.hits.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected request: %s accept=%q", r.Method, r.Header.Get("Accept"))
		}
		d.mu.Lock()
		doc, hooks := d.doc, d.hooks
		d.mu.Unlock()
		if hooks != nil && hooks(w) {
			return
		}
		if r.URL.Path != "/client.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	d.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // テスト終了時の TLS handshake エラーを出さない
	d.srv.StartTLS()
	t.Cleanup(d.srv.Close)
	d.doc = map[string]any{
		"client_id": d.srv.URL + "/client.json", "client_name": "MCP Client", "client_uri": "https://mcp-client.example",
		"redirect_uris": []string{"http://localhost:3000/callback"}, "scope": "files:read",
	}
	return d
}

func (d *docServer) id() string { return d.srv.URL + "/client.json" }

func (d *docServer) set(f func(doc map[string]any)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d.doc)
}

func (d *docServer) respond(h func(w http.ResponseWriter) bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hooks = h
}

// httpClient は SSRF 対策付きの Transport にテストサーバーの証明書を信頼させたもの。
func (d *docServer) httpClient(allowLoopback bool) *http.Client {
	tr := cimd.NewTransport(allowLoopback)
	tr.TLSClientConfig = d.srv.Client().Transport.(*http.Transport).TLSClientConfig
	return &http.Client{Transport: tr, Timeout: 2 * time.Second}
}

type fixture struct {
	*docServer
	res *cimd.Resolver
	now time.Time
	mu  sync.Mutex
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func newFixture(t *testing.T, mod func(c *cimd.Config)) *fixture {
	t.Helper()
	f := &fixture{docServer: newDocServer(t), now: base}
	cfg := cimd.Config{HTTPClient: f.httpClient(true), Now: f.clock, Logger: slog.New(slog.DiscardHandler)}
	if mod != nil {
		mod(&cfg)
	}
	res, err := cimd.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.res = res
	return f
}

func TestResolveAndCache(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()

	c, err := f.res.GetClient(ctx, f.id())
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != f.id() || c.Profile != client.ProfileMCP || c.Name != "MCP Client" || c.ClientURI != "https://mcp-client.example" ||
		c.RedirectURIs[0] != "http://localhost:3000/callback" || c.Scopes[0] != "files:read" || !c.CreatedAt.Equal(base) {
		t.Fatalf("client = %+v", c)
	}
	// 2 回目はキャッシュ（ヘッダーなし → 下限 1 分）
	if _, err := f.res.GetClient(ctx, f.id()); err != nil || f.hits.Load() != 1 {
		t.Fatalf("second call must hit the cache: hits=%d err=%v", f.hits.Load(), err)
	}
	// 文書を差し替えても期限内は古いまま
	f.set(func(doc map[string]any) { doc["redirect_uris"] = []string{"http://localhost:4000/callback"} })
	f.advance(59 * time.Second)
	if c, _ := f.res.GetClient(ctx, f.id()); c.RedirectURIs[0] != "http://localhost:3000/callback" {
		t.Fatal("cached document must be used until it expires")
	}
	// 期限切れ後は再取得して新しい文書に置き換わる
	f.advance(2 * time.Second)
	c, err = f.res.GetClient(ctx, f.id())
	if err != nil || c.RedirectURIs[0] != "http://localhost:4000/callback" || f.hits.Load() != 2 {
		t.Fatalf("after expiry: %+v hits=%d err=%v", c, f.hits.Load(), err)
	}
	// Invalidate で即時に再取得
	f.res.Invalidate(f.id())
	if _, err := f.res.GetClient(ctx, f.id()); err != nil || f.hits.Load() != 3 {
		t.Fatalf("after invalidate: hits=%d err=%v", f.hits.Load(), err)
	}
}

func TestCacheControlIsRespectedWithinBounds(t *testing.T) {
	f := newFixture(t, func(c *cimd.Config) { c.MaxCacheTTL = 2 * time.Hour })
	ctx := context.Background()
	f.respond(func(w http.ResponseWriter) bool { w.Header().Set("Cache-Control", "public, max-age=600"); return false })
	if _, err := f.res.GetClient(ctx, f.id()); err != nil {
		t.Fatal(err)
	}
	f.advance(9 * time.Minute)
	_, _ = f.res.GetClient(ctx, f.id())
	if f.hits.Load() != 1 {
		t.Fatalf("max-age=600 must keep the entry for 10 minutes: hits=%d", f.hits.Load())
	}
	f.advance(2 * time.Minute)
	_, _ = f.res.GetClient(ctx, f.id())
	if f.hits.Load() != 2 {
		t.Fatalf("entry must expire after max-age: hits=%d", f.hits.Load())
	}

	// 上限 2 時間を超える max-age は 2 時間に丸める
	f.respond(func(w http.ResponseWriter) bool { w.Header().Set("Cache-Control", "max-age=86400"); return false })
	f.res.Invalidate(f.id())
	_, _ = f.res.GetClient(ctx, f.id())
	f.advance(2*time.Hour + time.Second)
	_, _ = f.res.GetClient(ctx, f.id())
	if f.hits.Load() != 4 {
		t.Fatalf("max-age must be clamped to MaxCacheTTL: hits=%d", f.hits.Load())
	}
}

// エラー応答と不正な文書はキャッシュしない（CIMD §5.2）。直後の成功はすぐ反映される。
func TestErrorsAreNotCached(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	f.respond(func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusServiceUnavailable); return true })
	_, err := f.res.GetClient(ctx, f.id())
	if !errors.Is(err, client.ErrUnresolvable) || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("want ErrUnresolvable with status, got %v", err)
	}
	f.respond(nil)
	if _, err := f.res.GetClient(ctx, f.id()); err != nil || f.hits.Load() != 2 {
		t.Fatalf("success right after an error: hits=%d err=%v", f.hits.Load(), err)
	}
}

func TestRejections(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(f *fixture)
		wantMsg string
	}{
		{"client_id mismatch", func(f *fixture) {
			f.set(func(doc map[string]any) { doc["client_id"] = "https://other.example/client.json" })
		}, "does not match"},
		{"redirect response", func(f *fixture) {
			f.respond(func(w http.ResponseWriter) bool {
				w.Header().Set("Location", "https://elsewhere.example/client.json")
				w.WriteHeader(http.StatusFound)
				return true
			})
		}, "redirects are not followed"},
		{"not found", func(f *fixture) {
			f.respond(func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusNotFound); return true })
		}, "status 404"},
		{"too large", func(f *fixture) {
			f.set(func(doc map[string]any) { doc["client_name"] = strings.Repeat("x", 6<<10) })
		}, "exceeds 5120 bytes"},
		{"invalid json", func(f *fixture) {
			f.respond(func(w http.ResponseWriter) bool { _, _ = io.WriteString(w, "{not json"); return true })
		}, "not valid JSON"},
		{"client_secret in document", func(f *fixture) {
			f.set(func(doc map[string]any) { doc["client_secret"] = "s3cret" })
		}, "client_secret"},
		{"client_secret_basic", func(f *fixture) {
			f.set(func(doc map[string]any) { doc["token_endpoint_auth_method"] = "client_secret_basic" })
		}, "token_endpoint_auth_method"},
		{"missing redirect_uris", func(f *fixture) {
			f.set(func(doc map[string]any) { delete(doc, "redirect_uris") })
		}, "redirect URI"},
		{"missing client_name", func(f *fixture) {
			f.set(func(doc map[string]any) { delete(doc, "client_name") })
		}, "name is required"},
		{"timeout", func(f *fixture) {
			f.respond(func(w http.ResponseWriter) bool { time.Sleep(3 * time.Second); return true })
		}, "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, nil)
			tt.setup(f)
			_, err := f.res.GetClient(context.Background(), f.id())
			if !errors.Is(err, client.ErrUnresolvable) || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("want ErrUnresolvable containing %q, got %v", tt.wantMsg, err)
			}
			// 失敗はキャッシュされない: 文書を直せば次は成功する
			f.respond(nil)
			f.set(func(doc map[string]any) {
				doc["client_id"], doc["client_name"], doc["redirect_uris"] = f.id(), "MCP Client", []string{"http://localhost:3000/callback"}
				delete(doc, "client_secret")
				delete(doc, "token_endpoint_auth_method")
			})
			if _, err := f.res.GetClient(context.Background(), f.id()); err != nil {
				t.Fatalf("after fixing the document: %v", err)
			}
		})
	}
}

// 既定の Transport は loopback を含む特殊用途アドレスへ接続しない（CIMD §8.6）。
func TestLoopbackIsRefusedUnlessAllowed(t *testing.T) {
	f := newFixture(t, func(c *cimd.Config) { c.HTTPClient = nil; c.AllowLoopback = false })
	_, err := f.res.GetClient(context.Background(), f.id())
	if !errors.Is(err, client.ErrUnresolvable) || !errors.Is(err, cimd.ErrForbiddenAddress) {
		t.Fatalf("want ErrUnresolvable wrapping ErrForbiddenAddress, got %v", err)
	}
	if f.hits.Load() != 0 {
		t.Fatal("the document server must not be contacted")
	}
}

func TestNonMetadataURLIsNotFound(t *testing.T) {
	f := newFixture(t, nil)
	for _, id := range []string{"web-app", "http://mcp-client.example/client.json", "https://mcp-client.example", ""} {
		if _, err := f.res.GetClient(context.Background(), id); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("%q: want ErrNotFound, got %v", id, err)
		}
	}
	if f.hits.Load() != 0 {
		t.Fatal("no fetch for non-CIMD client ids")
	}
}

type denyAll struct{}

func (denyAll) Allow(_ context.Context, u *url.URL) error {
	return errors.New("denied by policy: " + u.Host)
}

func TestTrustPolicyIsConsultedBeforeFetch(t *testing.T) {
	f := newFixture(t, func(c *cimd.Config) { c.TrustPolicy = denyAll{} })
	_, err := f.res.GetClient(context.Background(), f.id())
	if !errors.Is(err, client.ErrUnresolvable) || !strings.Contains(err.Error(), "denied by policy") {
		t.Fatalf("got %v", err)
	}
	if f.hits.Load() != 0 {
		t.Fatal("policy must be checked before fetching")
	}
}

// Store にある client_id が優先される（ADR-0008 §5）。URL 形式の client_id を事前登録してもよい（CIMD §7）。
func TestChainPrefersStore(t *testing.T) {
	f := newFixture(t, nil)
	registered, err := client.NewMCP(client.MetadataDocument{ClientID: f.id(), ClientName: "Registered", RedirectURIs: []string{"https://registered.example/cb"}}, f.id(), base)
	if err != nil {
		t.Fatal(err)
	}
	store := staticResolver{registered.ID: registered}
	chain := client.ChainResolver{store, f.res}
	c, err := chain.GetClient(context.Background(), f.id())
	if err != nil || c.Name != "Registered" || f.hits.Load() != 0 {
		t.Fatalf("store must win: %+v hits=%d err=%v", c, f.hits.Load(), err)
	}
	// Store に無い URL は CIMD へ
	if _, err := chain.GetClient(context.Background(), "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown plain id: %v", err)
	}
}

type staticResolver map[string]*client.Client

func (s staticResolver) GetClient(_ context.Context, id string) (*client.Client, error) {
	if c, ok := s[id]; ok {
		return c, nil
	}
	return nil, storage.ErrNotFound
}

func TestConcurrentResolve(t *testing.T) {
	f := newFixture(t, nil)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := f.res.GetClient(context.Background(), f.id()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestNewValidation(t *testing.T) {
	bad := []cimd.Config{
		{Timeout: -time.Second},
		{MaxBodySize: -1},
		{MinCacheTTL: time.Hour, MaxCacheTTL: time.Minute},
	}
	for i, cfg := range bad {
		if _, err := cimd.New(cfg); err == nil {
			t.Errorf("config %d must be rejected", i)
		}
	}
	if _, err := cimd.New(cimd.Config{}); err != nil {
		t.Fatalf("zero config must be valid: %v", err)
	}
}
