package authengine

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/keys"
	"github.com/muno/auth-engine/oidc"
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

	// Keys は ID Token の署名鍵セット。必須。RS256 の署名鍵を含むこと
	// （OIDC Core §15.1、Client の既定アルゴリズム）。
	Keys *keys.Set

	// Now は現在時刻の取得関数。nil なら time.Now。テストで固定時刻を注入する。
	Now func() time.Time

	// Logger は監査イベントの出力先。nil なら slog.Default()。
	Logger *slog.Logger

	// TransactionTTL は Authorization Transaction の期限。0 なら 10 分、上限 1 時間。
	TransactionTTL time.Duration
	// CodeTTL は Authorization Code の期限。0 なら 60 秒、上限 10 分（RFC 6749 §4.1.2）。
	CodeTTL time.Duration
	// IDTokenTTL は ID Token の有効期間。0 なら 1 時間、上限 24 時間。
	IDTokenTTL time.Duration
	// RefreshTokenTTL は Refresh Token の絶対期限（Token Family の寿命）。0 なら 30 日。
	// RefreshTokenIdleTTL は最終使用からのスライド期限。0 なら 14 日。絶対期限を超えないこと。
	RefreshTokenTTL     time.Duration
	RefreshTokenIdleTTL time.Duration
}

// Engine は全 Service を配線した本体。HTTP 層（httpapi）はこれを受け取る。
type Engine struct {
	Issuer string
	Store  Store
	Keys   *keys.Set
	Logger *slog.Logger
	Clock  clock.Clock

	Authorization *authorization.Service
	Token         *token.Service
	IDTokens      *oidc.IDTokenIssuer
	UserInfo      *oidc.UserInfoService
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
	if cfg.IDTokenTTL < 0 || cfg.IDTokenTTL > 24*time.Hour {
		return nil, errors.New("authengine: IDTokenTTL must be within (0, 24h]")
	}
	if cfg.RefreshTokenTTL < 0 || cfg.RefreshTokenIdleTTL < 0 {
		return nil, errors.New("authengine: RefreshTokenTTL and RefreshTokenIdleTTL must not be negative")
	}
	refreshTTL, refreshIdle := cfg.RefreshTokenTTL, cfg.RefreshTokenIdleTTL
	if refreshTTL == 0 {
		refreshTTL = token.DefaultRefreshTokenTTL
	}
	if refreshIdle == 0 {
		refreshIdle = token.DefaultRefreshTokenIdleTTL
	}
	if refreshIdle > refreshTTL {
		return nil, errors.New("authengine: RefreshTokenIdleTTL must not exceed RefreshTokenTTL")
	}
	if cfg.Keys == nil {
		return nil, errors.New("authengine: Keys is required")
	}
	if _, err := cfg.Keys.SigningKey(keys.AlgRS256); err != nil {
		return nil, errors.New("authengine: Keys must contain an RS256 signing key (OIDC Core §15.1)")
	}

	var clk clock.Clock = clock.Real{}
	if cfg.Now != nil {
		clk = clock.Func(cfg.Now)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{Issuer: cfg.Issuer, Store: cfg.Store, Keys: cfg.Keys, Logger: logger, Clock: clk}
	e.IDTokens = &oidc.IDTokenIssuer{Issuer: cfg.Issuer, Keys: cfg.Keys, Clock: clk, TTL: cfg.IDTokenTTL}
	e.UserInfo = &oidc.UserInfoService{Tokens: cfg.Store, Clock: clk}
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
		Clients:             cfg.Store,
		Store:               cfg.Store,
		Grants:              cfg.Store,
		Clock:               clk,
		Logger:              logger,
		IDTokens:            e.IDTokens,
		RefreshTokenTTL:     refreshTTL,
		RefreshTokenIdleTTL: refreshIdle,
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
