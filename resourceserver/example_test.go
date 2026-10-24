package resourceserver_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/resourceserver"
)

// ExampleNew は MCP サーバー（Resource Server）にメタデータの配信と Bearer 検証を組み込む。
// 本番では Verifier に IntrospectionVerifier（Opaque Access Token）か JWTVerifier（JWT Access Token）を
// 使う。ここでは応答の形を見せるために固定の検証結果を返す VerifierFunc を使う。
func ExampleNew() {
	verifier := resourceserver.VerifierFunc(func(_ context.Context, token string) (*resourceserver.Principal, error) {
		if token != "valid" {
			return nil, fmt.Errorf("%w: unknown token", resourceserver.ErrInvalidToken)
		}
		return &resourceserver.Principal{
			Subject: "alice", ClientID: "https://mcp-client.example/client.json",
			Scopes:    []string{"files:read"},
			Audience:  []string{"https://mcp.example.com"}, // Protector が自分の resource を含むことを確認する
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil
	})
	p, err := resourceserver.New(resourceserver.Config{
		Resource:             "https://mcp.example.com",             // 認可サーバーの Config.Resources に登録した URI と同じ値
		AuthorizationServers: []string{"https://as.example.com"},    // クライアントはここから認可サーバーのメタデータを見つける
		Scopes:               []string{"files:read", "files:write"}, // scopes_supported
		Name:                 "Example MCP Server",
		Verifier:             verifier,
		Logger:               slog.New(slog.DiscardHandler),
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle(p.MetadataPath(), p.MetadataHandler()) // GET /.well-known/oauth-protected-resource
	mux.Handle("/mcp", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr, _ := resourceserver.FromContext(r.Context())
		fmt.Fprintf(w, "hello %s via %s", pr.Subject, pr.ClientID)
	}), "files:read")) // このルートに必要な scope

	call := func(auth string) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		fmt.Println(strings.TrimSpace(fmt.Sprint(rec.Code, " ", rec.Header().Get("WWW-Authenticate"))))
		fmt.Println(strings.TrimSpace(rec.Body.String()))
	}
	call("")               // トークンなし → 401 と resource_metadata（RFC 9728 §5.1）
	call("Bearer expired") // 無効 → 401 invalid_token
	call("Bearer valid")   // 成功

	// Output:
	// 401 Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read"
	//
	// 401 Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error="invalid_token", error_description="invalid token: unknown token", scope="files:read"
	// {"error":"invalid_token","error_description":"invalid token: unknown token"}
	// 200
	// hello alice via https://mcp-client.example/client.json
}
