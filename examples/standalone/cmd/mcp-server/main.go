// Command mcp-server は、resourceserver を組み込んだ最小の Resource Server（デモ MCP サーバー）である。
// 認可の部分を見せるのが目的で、MCP プロトコルは MCP クライアント（MCP Inspector、公式 SDK）が接続して
// ツールを 1 つ呼べる最小限（initialize / ping / tools/list / tools/call、mcp.go）だけを実装する。
//
//	go run ./cmd/mcp-server -issuer http://localhost:8080
//
// 立てるルート（既定 :8090、resource は http://localhost:8090/mcp）:
//   - GET /.well-known/oauth-protected-resource/mcp: RFC 9728 のメタデータ
//   - POST /mcp: scope mcp:read が要る。MCP の Streamable HTTP エンドポイント。whoami ツールが検証済みの主体を返す
//   - GET|POST /mcp/admin: scope mcp:write が要る（insufficient_scope の 403 を見せる用）
//
// トークンの検証は既定で JWT（RFC 9068）のローカル検証。認可サーバー側では、この resource を
// access_token_format=jwt で -resources に登録しておく（examples/standalone/resources.json）。
// -introspect を付けると Introspection（RFC 7662）で検証する。そのときは Machine Profile の Client の
// 資格情報（-client-id / -client-secret）が要り、resource は opaque でよい。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/u-masato/auth-engine/resourceserver"
)

func main() {
	var (
		addr         = flag.String("addr", ":8090", "listen address")
		resource     = flag.String("resource", "http://localhost:8090/mcp", "this server's resource URI (must be registered in the authorization server's -resources)")
		issuer       = flag.String("issuer", "http://localhost:8080", "issuer of the authorization server that protects this resource")
		name         = flag.String("name", "Demo MCP Server", "resource_name")
		scopes       = flag.String("scopes", "mcp:read mcp:write", "scopes_supported (space separated)")
		introspect   = flag.Bool("introspect", false, "verify tokens with RFC 7662 introspection instead of local JWT validation")
		clientID     = flag.String("client-id", "", "client_id of this server's Machine client (with -introspect)")
		clientSecret = flag.String("client-secret", "", "client_secret of this server's Machine client (with -introspect)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger, options{addr: *addr, resource: *resource, issuer: *issuer, name: *name, scopes: strings.Fields(*scopes),
		introspect: *introspect, clientID: *clientID, clientSecret: *clientSecret}); err != nil {
		logger.Error("mcp-server exited", "error", err)
		os.Exit(1)
	}
}

type options struct {
	addr, resource, issuer, name, clientID, clientSecret string
	scopes                                               []string
	introspect                                           bool
}

func run(ctx context.Context, logger *slog.Logger, o options) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var verifier resourceserver.TokenVerifier
	if o.introspect {
		if o.clientID == "" || o.clientSecret == "" {
			return errors.New("-introspect requires -client-id and -client-secret")
		}
		verifier = &resourceserver.IntrospectionVerifier{Issuer: o.issuer, ClientID: o.clientID, ClientSecret: o.clientSecret}
	} else {
		verifier = &resourceserver.JWTVerifier{Issuer: o.issuer}
	}
	p, err := resourceserver.New(resourceserver.Config{
		Resource:             o.resource,
		AuthorizationServers: []string{o.issuer},
		Scopes:               o.scopes,
		Name:                 o.name,
		Verifier:             verifier,
		Logger:               logger,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(p.MetadataPath(), p.MetadataHandler())
	mux.Handle("/mcp", p.Protect(http.HandlerFunc(mcpHandler), "mcp:read"))
	mux.Handle("/mcp/admin", p.Protect(http.HandlerFunc(hello), "mcp:write"))

	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", o.addr, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	verify := "jwt"
	if o.introspect {
		verify = "introspection"
	}
	logger.Info("ready", "addr", ln.Addr().String(), "resource", p.Resource(), "metadata_url", p.MetadataURL(), "issuer", o.issuer, "verify", verify)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// hello は検証済みの主体（resourceserver.Principal）をそのまま返す。実際の MCP サーバーならここで
// JSON-RPC を処理し、Principal の Subject / Scopes で認可する。
func hello(w http.ResponseWriter, r *http.Request) {
	pr, _ := resourceserver.FromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message":   "hello from the demo MCP server",
		"path":      r.URL.Path,
		"subject":   pr.Subject,
		"client_id": pr.ClientID,
		"scope":     pr.Scopes,
		"aud":       pr.Audience,
		"exp":       pr.ExpiresAt,
	})
}
