package resourceserver_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/u-masato/auth-engine/resourceserver"
)

// Issuer だけを指定した IntrospectionVerifier は、メタデータ（RFC 8414）を 1 回だけ取得し、
// 並行に Verify してもデータ競合を起こさない（-race で確かめる）。
func TestIntrospectionVerifierConcurrentDiscovery(t *testing.T) {
	var metadataHits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			metadataHits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "introspection_endpoint": srv.URL + "/introspect"})
		case "/introspect":
			_, _ = io.WriteString(w, `{"active":true,"token_type":"Bearer","client_id":"c","sub":"u","aud":"https://mcp.example.com"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	v := &resourceserver.IntrospectionVerifier{Issuer: srv.URL, ClientID: "rs", ClientSecret: "s3cret"}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := v.Verify(context.Background(), "t"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := metadataHits.Load(); n != 1 {
		t.Fatalf("metadata must be fetched once, got %d", n)
	}
}
