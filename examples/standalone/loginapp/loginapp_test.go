package loginapp

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConsentPageShowsHosts は MCP Client の同意画面に client_id と redirect URI のホスト名、
// localhost の注意書きが出ることを確かめる（docs/interaction-api.md「profile が mcp のとき」）。
func TestConsentPageShowsHosts(t *testing.T) {
	txns := map[string]any{
		"mcp": map[string]any{
			"id": "mcp", "status": "pending",
			"client":  map[string]any{"client_id": "https://mcp-client.example/clients/demo.json", "name": "Example MCP Client", "profile": "mcp", "client_uri": "https://mcp-client.example"},
			"request": map[string]any{"redirect_uri": "http://localhost:3000/callback", "scopes": []string{"mcp:read"}, "resource": []string{"https://mcp.example.com/mcp"}},
		},
		"web": map[string]any{
			"id": "web", "status": "pending",
			"client":  map[string]any{"client_id": "web-app", "name": "Web App", "profile": "web"},
			"request": map[string]any{"redirect_uri": "https://app.example.com/cb", "scopes": []string{"openid"}},
		},
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/transactions/")
		_ = json.NewEncoder(w).Encode(txns[id])
	}))
	defer api.Close()
	app, err := New(Config{InteractionAPI: api.URL, APIToken: "t", Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}

	get := func(txn string) string {
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?txn="+txn, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", txn, rec.Code, rec.Body)
		}
		body, _ := io.ReadAll(rec.Body)
		return string(body)
	}
	mcp := get("mcp")
	for _, want := range []string{
		"published at <strong>mcp-client.example</strong>",         // client_id のホスト名（MUST）
		"sent to <strong>localhost:3000</strong>",                  // redirect URI のホスト名（MUST）
		"running on this computer",                                 // localhost の注意書き（SHOULD）
		"https://mcp-client.example/clients/demo.json",             // client_id 全体
		"website: <code>https://mcp-client.example</code>",         // client_uri は文字列として出す（リンクにしない）
		"valid only for: <code>https://mcp.example.com/mcp</code>", // resource
	} {
		if !strings.Contains(mcp, want) {
			t.Errorf("mcp page lacks %q:\n%s", want, mcp)
		}
	}
	if strings.Contains(mcp, `href="https://mcp-client.example"`) {
		t.Error("client_uri must not be a link")
	}
	web := get("web")
	if strings.Contains(web, "MCP client") || !strings.Contains(web, "sent to <strong>app.example.com</strong>") || strings.Contains(web, "running on this computer") {
		t.Errorf("web page:\n%s", web)
	}
}

func TestIsLocalHost(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true, "app.example.com": false, "10.0.0.1": false} {
		if got := isLocalHost(host); got != want {
			t.Errorf("isLocalHost(%q) = %v", host, got)
		}
	}
}
