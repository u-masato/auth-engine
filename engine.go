package authengine

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/token"
)

// Config は Engine の設定。環境変数や設定ファイルの解釈は利用者側で行い、構造体で渡す（ADR-0002）。
type Config struct {
	// Issuer は認可サーバーの識別子（RFC 8414 の issuer）。https の絶対 URL で、
	// クエリとフラグメントを含まない。開発用に http://localhost / loopback も許す。
	// M1 ではパスを含まないこと（エンドポイントは Issuer 直下に配置する）。
	Issuer string

	// Store は永続化 Adapter。必須。
	Store Store

	// Now は現在時刻の取得関数。nil なら time.Now。テストで固定時刻を注入する。
	Now func() time.Time

	// Logger は監査イベントの出力先。nil なら slog.Default()。
	Logger *slog.Logger

	// TransactionTTL は Authorization Transaction の期限。0 なら 10 分、上限 1 時間。
	TransactionTTL time.Duration
	// CodeTTL は Authorization Code の期限。0 なら 60 秒、上限 10 分（RFC 6749 §4.1.2）。
	CodeTTL time.Duration
}

// Engine は全 Service を配線した本体。HTTP 層（httpapi）はこれを受け取る。
type Engine struct {
	Issuer string
	Store  Store
	Logger *slog.Logger
	Clock  clock.Clock

	Authorization *authorization.Service
	Token         *token.Service
}

// New は Config を検証して Engine を組み立てる。
func New(cfg Config) (*Engine, error) {
	if err := ValidateIssuer(cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		return nil, errors.New("authengine: Store is required")
	}
	if cfg.TransactionTTL < 0 || cfg.TransactionTTL > authorization.MaxTransactionTTL {
		return nil, fmt.Errorf("authengine: TransactionTTL must be within (0, %s]", authorization.MaxTransactionTTL)
	}
	if cfg.CodeTTL < 0 || cfg.CodeTTL > authorization.MaxCodeTTL {
		return nil, fmt.Errorf("authengine: CodeTTL must be within (0, %s]", authorization.MaxCodeTTL)
	}

	var clk clock.Clock = clock.Real{}
	if cfg.Now != nil {
		clk = clock.Func(cfg.Now)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{Issuer: cfg.Issuer, Store: cfg.Store, Logger: logger, Clock: clk}
	e.Authorization = &authorization.Service{
		Clients:        cfg.Store,
		Store:          cfg.Store,
		Grants:         cfg.Store,
		Clock:          clk,
		Issuer:         cfg.Issuer,
		TransactionTTL: cfg.TransactionTTL,
		CodeTTL:        cfg.CodeTTL,
	}
	e.Token = &token.Service{
		Clients: cfg.Store,
		Store:   cfg.Store,
		Clock:   clk,
		Logger:  logger,
	}
	return e, nil
}

// ValidateIssuer は Issuer の形式を検証する。
func ValidateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return errors.New("authengine: Issuer must be an absolute URL")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("authengine: Issuer must not contain query, fragment or userinfo")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("authengine: Issuer must not contain a path")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLocalHost(u.Hostname()) {
			return errors.New("authengine: Issuer must use https (http is allowed only for localhost)")
		}
	default:
		return errors.New("authengine: Issuer scheme must be https")
	}
	return nil
}

func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
