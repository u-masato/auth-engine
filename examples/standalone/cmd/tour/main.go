// Command tour は「境界ツアー」を起動する。Client、auth-engine、Interaction App、Resource Server を
// 1 プロセスで立て、ログインから業務 API の呼び出しまでのやり取りを図とタイムラインで見せる。
//
//	go run ./cmd/tour
//
// 起動したら http://localhost:8100 を開く。設定ファイルも DB も要らない（Store はメモリ）。
// 待ち受けるのは loopback（127.0.0.1）だけで、ポートは -port-base から 5 つ続けて使う。
//   - Client「Notes Web」（base）: ツアーの画面
//   - auth-engine の公開エンドポイント（base+1）: /authorize, /token, /jwks など
//   - Interaction API（base+2）: Interaction App だけが呼ぶ
//   - Interaction App（base+3）: ログインと同意の画面
//   - Resource Server「Notes API」（base+4）: GET /notes, POST /notes
//
// -verify introspection にすると、Notes API は JWT のローカル検証ではなく Introspection でトークンを
// 確かめる。失効がすぐ反映される違いを見られる。
package main

import (
	"context"
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

	"github.com/u-masato/auth-engine/examples/standalone/tour"
)

func main() {
	var (
		portBase = flag.Int("port-base", 8100, "first of five consecutive ports (client, engine, interaction API, interaction app, resource server)")
		verify   = flag.String("verify", tour.VerifyJWT, "how the Notes API verifies access tokens: jwt (local validation) or introspection (RFC 7662)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(context.Background(), logger, *portBase, *verify); err != nil {
		logger.Error("tour exited", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, portBase int, verify string) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ブラウザに見せる URL は localhost、待ち受けは 127.0.0.1（LAN には出さない）
	url := func(offset int) string { return fmt.Sprintf("http://localhost:%d", portBase+offset) }
	cfg := tour.Config{ClientURL: url(0), IssuerURL: url(1), InteractionAPIURL: fmt.Sprintf("http://127.0.0.1:%d", portBase+2),
		LoginURL: url(3), ResourceURL: url(4), Verify: verify, Logger: logger}
	t, err := tour.New(ctx, cfg)
	if err != nil {
		return err
	}

	handlers := []struct {
		name string
		h    http.Handler
	}{{"client", t.Client}, {"engine", t.Public}, {"interaction-api", t.InteractionAPI}, {"interaction-app", t.Login}, {"resource-server", t.Resource}}
	servers := make([]*http.Server, 0, len(handlers))
	errCh := make(chan error, len(handlers))
	for i, hd := range handlers {
		addr := fmt.Sprintf("127.0.0.1:%d", portBase+i)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s (%s): %w; use -port-base to pick other ports", addr, hd.name, err)
		}
		srv := &http.Server{Handler: hd.h, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, srv)
		logger.Info("listening", "server", hd.name, "addr", addr)
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}
	logger.Info("ready", "open", cfg.ClientURL, "verify", verify)
	fmt.Fprintf(os.Stderr, "\n  境界ツアーを開く: %s\n\n", cfg.ClientURL)

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
