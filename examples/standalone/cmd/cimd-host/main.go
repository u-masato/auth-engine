// Command cimd-host は、Client ID Metadata Document（CIMD）を HTTPS で配る最小のファイルサーバーである。
// 本来は MCP クライアントの提供者が自分のドメインで公開する文書を、ローカルの開発環境で
// 真似るために使う。
//
//	go run ./cmd/cimd-host
//
// 初回起動時に自己署名証明書（SAN: localhost, 127.0.0.1, ::1）を -cert / -key に生成する。CIMD の client_id は
// https でなければならず（CIMD §3）、認可サーバーは文書の取得先の証明書を検証するので、
// 認可サーバー側では cmd/server の -cimd-allow-loopback（loopback への接続を許す）と
// -cimd-ca（この証明書を信頼する）を付けて起動する。
//
// 配る文書:
//   - /demo-cli.json: cmd/cli-client 用の組み込み文書。client_id は -url + /demo-cli.json、redirect_uris は
//     http://127.0.0.1/callback（loopback はポートを無視して照合される。RFC 8252 §7.3）
//   - -docs DIR を与えると、その直下の *.json を /{ファイル名} で配る。文書の client_id は配信 URL と
//     一字一句一致していること（CIMD §4）
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/u-masato/auth-engine/client"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:8444", "listen address")
		baseURL  = flag.String("url", "https://localhost:8444", "public base URL of this server; client_id = this + document path")
		certPath = flag.String("cert", "cimd-cert.pem", "TLS certificate (PEM; created self-signed on first run)")
		keyPath  = flag.String("key", "cimd-key.pem", "TLS private key (PEM; created on first run)")
		docsDir  = flag.String("docs", "", "directory of additional *.json documents to serve at /{name}")
		name     = flag.String("name", "Demo MCP Client", "client_name of the built-in /demo-cli.json")
		redirect = flag.String("redirect-uris", "http://127.0.0.1/callback", "redirect_uris of the built-in document (space separated)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger, options{addr: *addr, baseURL: strings.TrimRight(*baseURL, "/"), certPath: *certPath, keyPath: *keyPath,
		docsDir: *docsDir, name: *name, redirectURIs: strings.Fields(*redirect)}); err != nil {
		logger.Error("cimd-host exited", "error", err)
		os.Exit(1)
	}
}

type options struct {
	addr, baseURL, certPath, keyPath, docsDir, name string
	redirectURIs                                    []string
}

func run(ctx context.Context, logger *slog.Logger, o options) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !strings.HasPrefix(o.baseURL, "https://") {
		return errors.New("-url must be an https URL (CIMD §3)")
	}
	cert, err := loadOrCreateCert(o.certPath, o.keyPath, logger)
	if err != nil {
		return err
	}

	// 組み込み文書は client.NewMCP で自分自身を検証し、認可サーバーに拒否される文書を配らないようにする。
	docURL := o.baseURL + "/demo-cli.json"
	doc := client.MetadataDocument{
		ClientID:                docURL,
		ClientName:              o.name,
		ClientURI:               o.baseURL,
		RedirectURIs:            o.redirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}
	if _, err := client.NewMCP(doc, docURL, time.Now()); err != nil {
		return fmt.Errorf("built-in document: %w", err)
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /demo-cli.json", func(w http.ResponseWriter, r *http.Request) { serveDocument(w, body) })
	if o.docsDir != "" {
		entries, err := os.ReadDir(o.docsDir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			p := filepath.Join(o.docsDir, e.Name())
			mux.HandleFunc("GET /"+e.Name(), func(w http.ResponseWriter, r *http.Request) {
				data, err := os.ReadFile(p)
				if err != nil {
					http.Error(w, "document unavailable", http.StatusInternalServerError)
					return
				}
				serveDocument(w, data)
			})
			logger.Info("serving document", "client_id", o.baseURL+"/"+path.Base(e.Name()), "file", p)
		}
	}

	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", o.addr, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	logger.Info("ready", "addr", ln.Addr().String(), "client_id", docURL, "cert", o.certPath)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// serveDocument は CIMD 文書を返す。Cache-Control は認可サーバーのキャッシュ期間になる（CIMD §5.2）。
// 開発中に文書を差し替えて試せるよう短めにする。
func serveDocument(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=60")
	_, _ = w.Write(body)
}

// loadOrCreateCert は証明書と鍵を読み、なければ localhost 向けの自己署名証明書（ECDSA P-256、1 年）を作って保存する。
func loadOrCreateCert(certPath, keyPath string, logger *slog.Logger) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		logger.Info("loaded certificate", "cert", certPath)
		return cert, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, fmt.Errorf("load certificate: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "auth-engine cimd-host (development)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("save certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("save key: %w", err)
	}
	logger.Info("generated self-signed certificate", "cert", certPath, "key", keyPath, "san", "localhost, 127.0.0.1, ::1")
	return tls.X509KeyPair(certPEM, keyPEM)
}
