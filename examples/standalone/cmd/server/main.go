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
//
// MCP 連携（M3）: -resources で Resource Server（MCP サーバー）を静的に登録し、CIMD（URL 形式の
// client_id）は既定で有効。文書をローカルの cmd/cimd-host から取るときは -cimd-allow-loopback と
// -cimd-ca を付ける。
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"syscall"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/adapters/sqlite"
	"github.com/u-masato/auth-engine/cimd"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/console"
	"github.com/u-masato/auth-engine/examples/standalone/loginapp"
	"github.com/u-masato/auth-engine/httpapi"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/storage"
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
		resourcesPath   = flag.String("resources", "", "JSON file of resource servers (RFC 8707 resource indicators; see resources.json)")
		cimdEnabled     = flag.Bool("cimd", true, "resolve URL client_ids with Client ID Metadata Documents (MCP clients without registration)")
		cimdLoopback    = flag.Bool("cimd-allow-loopback", false, "allow fetching metadata documents from loopback addresses (local development only; e.g. cmd/cimd-host)")
		cimdCA          = flag.String("cimd-ca", "", "PEM file of additional CA / self-signed certificates to trust when fetching metadata documents (e.g. cimd-host's cimd-cert.pem)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger, options{
		dbPath: *dbPath, keysPath: *keysPath, issuer: *issuer, publicAddr: *publicAddr, interactionAddr: *interactionAddr,
		loginAddr: *loginAddr, loginURL: *loginURL, autoApprove: *autoApprove, clientsPath: *clientsPath, insecureIssuer: *insecureIssuer,
		consoleAddr: *consoleAddr, consoleURL: *consoleURL, resourcesPath: *resourcesPath,
		cimd: *cimdEnabled, cimdLoopback: *cimdLoopback, cimdCA: *cimdCA,
	}); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

type options struct {
	dbPath, keysPath, issuer, publicAddr, interactionAddr, loginAddr, loginURL, clientsPath, consoleAddr, consoleURL string
	resourcesPath, cimdCA                                                                                            string
	autoApprove, insecureIssuer, cimd, cimdLoopback                                                                  bool
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
	resources, err := loadResources(o.resourcesPath, logger)
	if err != nil {
		return err
	}
	cimdCfg, err := cimdConfig(o, logger)
	if err != nil {
		return err
	}
	engine, err := authengine.New(authengine.Config{Issuer: o.issuer, Store: store, Keys: keySet, Logger: logger, AllowInsecureIssuer: o.insecureIssuer,
		Resources: resources, CIMD: cimdCfg})
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
	logger.Info("ready", "issuer", o.issuer, "login_url", o.loginURL, "console_url", o.consoleURL, "auto_approve", o.autoApprove,
		"resources", len(resources), "cimd", cimdCfg != nil)

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
	Profile                string   `json:"profile"` // web | native | machine | mcp
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	Scopes                 []string `json:"scopes"`
	Resources              []string `json:"resources"`  // 要求できる resource の上限（RFC 8707）。空なら設定済みの全部
	Secret                 string   `json:"secret"`     // web / machine。空なら生成してログに出す
	ClientURI              string   `json:"client_uri"` // mcp（CIMD 文書の client_uri）
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
				Scopes: sp.Scopes, Resources: sp.Resources, IDTokenAlg: sp.IDTokenAlg, AllowInsecureLocalhost: sp.AllowInsecureLocalhost}, now)
		case client.ProfileNative:
			c, err = client.NewNative(client.NativeParams{ID: sp.ClientID, Name: sp.Name, RedirectURIs: sp.RedirectURIs,
				Scopes: sp.Scopes, Resources: sp.Resources, IDTokenAlg: sp.IDTokenAlg, AllowInsecureLocalhost: sp.AllowInsecureLocalhost}, now)
		case client.ProfileMachine:
			c, secret, err = client.NewMachine(client.MachineParams{ID: sp.ClientID, Name: sp.Name, Secret: sp.Secret, Scopes: sp.Scopes, Resources: sp.Resources}, now)
		case client.ProfileMCP:
			// URL 形式の client_id を事前登録する経路（CIMD §7）。文書は取得せず、ここに書いた内容が登録情報になる。
			// Store にあるものが CIMD より優先される（client.ChainResolver）。
			c, err = client.NewMCP(client.MetadataDocument{ClientID: sp.ClientID, ClientName: sp.Name, ClientURI: sp.ClientURI,
				RedirectURIs: sp.RedirectURIs, Scope: strings.Join(sp.Scopes, " ")}, sp.ClientID, now)
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

// resourceSpec は -resources で読む Resource Server の定義（resource.Resource と同じ項目）。
type resourceSpec struct {
	URI               string   `json:"uri"`
	Name              string   `json:"name"`
	AccessTokenFormat string   `json:"access_token_format"` // opaque（既定）| jwt
	AccessTokenAlg    string   `json:"access_token_alg"`    // jwt のとき RS256（既定）| ES256
	Scopes            []string `json:"scopes"`              // この resource 向けトークンに付けられる scope の上限。空なら制限なし
}

// loadResources は -resources の JSON を Config.Resources に写す。検証は Engine が行う。
func loadResources(path string, logger *slog.Logger) ([]resource.Resource, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resources %s: %w", path, err)
	}
	var specs []resourceSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("parse resources %s: %w", path, err)
	}
	out := make([]resource.Resource, 0, len(specs))
	for _, sp := range specs {
		r := resource.Resource{URI: sp.URI, Name: sp.Name, AccessTokenFormat: resource.Format(sp.AccessTokenFormat), AccessTokenAlg: sp.AccessTokenAlg, Scopes: sp.Scopes}
		out = append(out, r)
		logger.Info("configured resource", "uri", r.URI, "format", r.EffectiveFormat(), "alg", r.EffectiveAlg(), "scopes", r.Scopes)
	}
	return out, nil
}

// cimdConfig は CIMD の設定を組む。-cimd-ca があれば、その証明書を信頼する TLS 設定を cimd.NewTransport に
// 足した HTTP クライアントを渡す（接続先アドレスの検査は Transport の責務なので NewTransport を基にする）。
func cimdConfig(o options, logger *slog.Logger) (*cimd.Config, error) {
	if !o.cimd {
		return nil, nil
	}
	cfg := &cimd.Config{AllowLoopback: o.cimdLoopback}
	if o.cimdCA != "" {
		pemData, err := os.ReadFile(o.cimdCA)
		if err != nil {
			return nil, fmt.Errorf("read cimd ca %s: %w", o.cimdCA, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("cimd ca %s: no certificates found", o.cimdCA)
		}
		tr := cimd.NewTransport(o.cimdLoopback)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		cfg.HTTPClient = &http.Client{Transport: tr, Timeout: cimd.DefaultTimeout}
		logger.Info("trusting additional certificates for metadata documents", "path", o.cimdCA)
	}
	return cfg, nil
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
