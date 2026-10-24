// Command server は、エンジン・Interaction API・デモ Interaction App を 1 プロセスで起動する。
//
//	go run ./cmd/server -db ./auth.db
//
// 起動すると 4 つのリスナーが立つ。
//   - 公開エンドポイント（既定 :8080）: /authorize, /token, /.well-known/oauth-authorization-server
//   - Interaction API（既定 127.0.0.1:8081）: Interaction App だけが使う。外部に公開しない
//   - デモ Interaction App（既定 :8082）: /login
//   - 開発者コンソール（既定 127.0.0.1:8083）: Client の登録とフローの手動確認。-console-addr "" で無効
//
// 初回起動時にデモ用クライアント demo-cli（Native、loopback redirect）を登録する。
// cmd/cli-client がこのクライアントでフローを実行できる。
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	"github.com/muno/auth-engine/examples/standalone/console"
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
		clientsPath     = flag.String("clients", "", "JSON file of clients to register on startup (see conformance/clients.json)")
		insecureIssuer  = flag.Bool("allow-insecure-issuer", false, "allow an http issuer other than localhost (e.g. http://host.docker.internal:8080; local development only)")
		consoleAddr     = flag.String("console-addr", "127.0.0.1:8083", "listen address for the developer console (empty to disable; it writes to the store without authentication, so keep it on loopback)")
		consoleURL      = flag.String("console-url", "http://127.0.0.1:8083", "public URL of the developer console (its redirect URI is this + /callback)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger, options{
		dbPath: *dbPath, keysPath: *keysPath, issuer: *issuer, publicAddr: *publicAddr, interactionAddr: *interactionAddr,
		loginAddr: *loginAddr, loginURL: *loginURL, autoApprove: *autoApprove, clientsPath: *clientsPath, insecureIssuer: *insecureIssuer,
		consoleAddr: *consoleAddr, consoleURL: *consoleURL,
	}); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

type options struct {
	dbPath, keysPath, issuer, publicAddr, interactionAddr, loginAddr, loginURL, clientsPath, consoleAddr, consoleURL string
	autoApprove, insecureIssuer                                                                                      bool
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
	engine, err := authengine.New(authengine.Config{Issuer: o.issuer, Store: store, Keys: keySet, Logger: logger, AllowInsecureIssuer: o.insecureIssuer})
	if err != nil {
		return err
	}
	known, err := registerDemoClients(ctx, store, logger)
	if err != nil {
		return err
	}
	if o.clientsPath != "" {
		fromFile, err := registerClientsFromFile(ctx, store, logger, o.clientsPath)
		if err != nil {
			return err
		}
		known = append(known, fromFile...)
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
	if o.consoleAddr != "" {
		con, err := console.New(console.Config{Issuer: o.issuer, BaseURL: o.consoleURL, Store: store, Known: known, Logger: logger})
		if err != nil {
			return err
		}
		servers = append(servers, &http.Server{Addr: o.consoleAddr, Handler: con.Handler(), ReadHeaderTimeout: 5 * time.Second})
		names = append(names, "console")
	}
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
	logger.Info("ready", "issuer", o.issuer, "login_url", o.loginURL, "console_url", o.consoleURL, "auto_approve", o.autoApprove)

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

// registerDemoClients はデモ用の Native クライアントを初回だけ登録し、コンソールに出す一覧を返す。
func registerDemoClients(ctx context.Context, store authengine.Store, logger *slog.Logger) ([]console.KnownClient, error) {
	const id = "demo-cli"
	known := []console.KnownClient{{ID: id}}
	if _, err := store.GetClient(ctx, id); err == nil {
		return known, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	c, err := client.NewNative(client.NativeParams{
		ID:           id,
		Name:         "Demo CLI",
		RedirectURIs: []string{"http://127.0.0.1/callback"}, // RFC 8252 §7.3: ポートは任意
		Scopes:       []string{"openid", "profile", "email"},
	}, time.Now())
	if err != nil {
		return nil, err
	}
	if err := store.CreateClient(ctx, c); err != nil {
		return nil, err
	}
	logger.Info("registered demo client", "client_id", id, "profile", c.Profile)
	return known, nil
}

// clientSpec は -clients で読むクライアント定義。
type clientSpec struct {
	ClientID               string   `json:"client_id"`
	Profile                string   `json:"profile"` // web | native | machine
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	Scopes                 []string `json:"scopes"`
	Secret                 string   `json:"secret"` // web / machine。空なら生成してログに出す
	IDTokenAlg             string   `json:"id_token_alg"`
	AllowInsecureLocalhost bool     `json:"allow_insecure_localhost"`
}

// registerClientsFromFile は JSON ファイルのクライアントを登録し、コンソールに出す一覧を返す。
// 既に同じ client_id があれば変更せずに飛ばす（Store に更新操作はない。変えたいときは DB を作り直す）。
func registerClientsFromFile(ctx context.Context, store authengine.Store, logger *slog.Logger, path string) ([]console.KnownClient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read clients %s: %w", path, err)
	}
	var specs []clientSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("parse clients %s: %w", path, err)
	}
	now := time.Now()
	var known []console.KnownClient
	for _, sp := range specs {
		if _, err := store.GetClient(ctx, sp.ClientID); err == nil {
			logger.Info("client already registered", "client_id", sp.ClientID)
			known = append(known, console.KnownClient{ID: sp.ClientID, Secret: sp.Secret})
			continue
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		var (
			c      *client.Client
			secret client.Secret
		)
		switch client.Profile(sp.Profile) {
		case client.ProfileWeb:
			c, secret, err = client.NewWeb(client.WebParams{ID: sp.ClientID, Name: sp.Name, Secret: sp.Secret, RedirectURIs: sp.RedirectURIs,
				Scopes: sp.Scopes, IDTokenAlg: sp.IDTokenAlg, AllowInsecureLocalhost: sp.AllowInsecureLocalhost}, now)
		case client.ProfileNative:
			c, err = client.NewNative(client.NativeParams{ID: sp.ClientID, Name: sp.Name, RedirectURIs: sp.RedirectURIs,
				Scopes: sp.Scopes, IDTokenAlg: sp.IDTokenAlg, AllowInsecureLocalhost: sp.AllowInsecureLocalhost}, now)
		case client.ProfileMachine:
			c, secret, err = client.NewMachine(client.MachineParams{ID: sp.ClientID, Name: sp.Name, Secret: sp.Secret, Scopes: sp.Scopes}, now)
		default:
			return nil, fmt.Errorf("client %s: unknown profile %q", sp.ClientID, sp.Profile)
		}
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", sp.ClientID, err)
		}
		if err := store.CreateClient(ctx, c); err != nil {
			return nil, fmt.Errorf("client %s: %w", sp.ClientID, err)
		}
		attrs := []any{"client_id", c.ID, "profile", c.Profile}
		if secret != "" && sp.Secret == "" {
			attrs = append(attrs, "generated_secret", string(secret)) // 1 回しか得られないので表示する
		}
		logger.Info("registered client from file", attrs...)
		known = append(known, console.KnownClient{ID: c.ID, Secret: string(secret)})
	}
	return known, nil
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
