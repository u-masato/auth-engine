// Command server は、エンジン・Interaction API・デモ Interaction App を 1 プロセスで起動する。
//
//	go run ./cmd/server -db ./auth.db
//
// 起動すると 3 つのリスナーが立つ。
//   - 公開エンドポイント（既定 :8080）: /authorize, /token, /.well-known/oauth-authorization-server
//   - Interaction API（既定 127.0.0.1:8081）: Interaction App だけが使う。外部に公開しない
//   - デモ Interaction App（既定 :8082）: /login
//
// 初回起動時にデモ用クライアント demo-cli（Native、loopback redirect）を登録する。
// cmd/cli-client がこのクライアントでフローを実行できる。
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/adapters/sqlite"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/examples/standalone/loginapp"
	"github.com/muno/auth-engine/httpapi"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/storage"
)

func main() {
	var (
		dbPath          = flag.String("db", "auth.db", "SQLite database file")
		keysPath        = flag.String("keys", "keys.json", "signing key set file (created on first run; keep it secret)")
		issuer          = flag.String("issuer", "http://localhost:8080", "issuer URL (must match the public address)")
		publicAddr      = flag.String("public-addr", ":8080", "listen address for /authorize and /token")
		interactionAddr = flag.String("interaction-addr", "127.0.0.1:8081", "listen address for the Interaction API (keep private)")
		loginAddr       = flag.String("login-addr", ":8082", "listen address for the demo login app")
		loginURL        = flag.String("login-url", "http://localhost:8082/login", "public URL of the demo login app")
		autoApprove     = flag.Bool("auto-approve", false, "approve every request as demo-user without showing a form (tests only)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger, options{
		dbPath: *dbPath, keysPath: *keysPath, issuer: *issuer, publicAddr: *publicAddr, interactionAddr: *interactionAddr,
		loginAddr: *loginAddr, loginURL: *loginURL, autoApprove: *autoApprove,
	}); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

type options struct {
	dbPath, keysPath, issuer, publicAddr, interactionAddr, loginAddr, loginURL string
	autoApprove                                                                bool
}

func run(ctx context.Context, logger *slog.Logger, o options) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := sqlite.Open(ctx, o.dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	keySet, err := loadOrCreateKeys(o.keysPath, logger)
	if err != nil {
		return err
	}
	engine, err := authengine.New(authengine.Config{Issuer: o.issuer, Store: store, Keys: keySet, Logger: logger})
	if err != nil {
		return err
	}
	if err := registerDemoClients(ctx, store, logger); err != nil {
		return err
	}

	// Interaction API のトークンはプロセス内で生成し、同梱の loginapp にだけ渡す。
	apiToken, err := randomToken()
	if err != nil {
		return err
	}
	srv, err := httpapi.New(httpapi.Config{
		Engine:          engine,
		InteractionURL:  o.loginURL,
		InteractionAuth: httpapi.BearerAuthenticator{Token: apiToken},
		// http://localhost で動かすデモなので Secure Cookie を外す。本番では false のまま使う。
		InsecureCookies: true,
	})
	if err != nil {
		return err
	}
	login, err := loginapp.New(loginapp.Config{
		InteractionAPI: "http://" + o.interactionAddr,
		APIToken:       apiToken,
		AutoApprove:    o.autoApprove,
		Logger:         logger,
	})
	if err != nil {
		return err
	}

	servers := []*http.Server{
		{Addr: o.publicAddr, Handler: srv.PublicHandler(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: o.interactionAddr, Handler: srv.InteractionHandler(), ReadHeaderTimeout: 5 * time.Second},
		{Addr: o.loginAddr, Handler: login.Handler(), ReadHeaderTimeout: 5 * time.Second},
	}
	names := []string{"public", "interaction", "login"}
	errCh := make(chan error, len(servers))
	for i, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", s.Addr, err)
		}
		logger.Info("listening", "server", names[i], "addr", ln.Addr().String())
		go func(s *http.Server, ln net.Listener) {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(s, ln)
	}
	logger.Info("ready", "issuer", o.issuer, "login_url", o.loginURL, "auto_approve", o.autoApprove)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	return nil
}

// registerDemoClients はデモ用の Native クライアントを初回だけ登録する。
func registerDemoClients(ctx context.Context, store authengine.Store, logger *slog.Logger) error {
	const id = "demo-cli"
	if _, err := store.GetClient(ctx, id); err == nil {
		return nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	c, err := client.NewNative(client.NativeParams{
		ID:           id,
		Name:         "Demo CLI",
		RedirectURIs: []string{"http://127.0.0.1/callback"}, // RFC 8252 §7.3: ポートは任意
		Scopes:       []string{"openid", "profile", "email"},
	}, time.Now())
	if err != nil {
		return err
	}
	if err := store.CreateClient(ctx, c); err != nil {
		return err
	}
	logger.Info("registered demo client", "client_id", id, "profile", c.Profile)
	return nil
}

// loadOrCreateKeys は鍵セットをファイルから読み、なければ RS256 と ES256 の鍵を生成して保存する。
// 再起動後も同じ鍵で検証できるようにするため。ファイルは秘密鍵を含むので 0600 で書く。
func loadOrCreateKeys(path string, logger *slog.Logger) (*keys.Set, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		set, err := keys.ImportPrivate(data)
		if err != nil {
			return nil, fmt.Errorf("load keys %s: %w", path, err)
		}
		logger.Info("loaded signing keys", "path", path, "algs", set.SigningAlgorithms())
		return set, nil
	case errors.Is(err, os.ErrNotExist):
		set := keys.NewSet()
		for _, alg := range []string{keys.AlgRS256, keys.AlgES256} {
			k, err := keys.Generate(alg, time.Now())
			if err != nil {
				return nil, err
			}
			if err := set.AddSigning(k); err != nil {
				return nil, err
			}
		}
		data, err := set.ExportPrivate()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, fmt.Errorf("save keys %s: %w", path, err)
		}
		logger.Info("generated signing keys", "path", path, "algs", set.SigningAlgorithms())
		return set, nil
	default:
		return nil, err
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
