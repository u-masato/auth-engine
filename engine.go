package authengine

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/oidc"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/token"
)

// Config は Engine の設定。環境変数や設定ファイルの解釈は利用者側で行い、構造体で渡す（ADR-0002）。
type Config struct {
	// Issuer は認可サーバーの識別子（RFC 8414 の issuer）。https の絶対 URL で、
	// クエリとフラグメントを含まない。開発用に http://localhost / loopback も許す。
	// パスを含まないこと（エンドポイントは Issuer 直下に配置する）。
	Issuer string

	// AllowInsecureIssuer は localhost 以外の http Issuer を許す開発用の緩和
	// （例: Docker 内の Conformance Suite から http://host.docker.internal:8080 で到達させる）。
	// 既定 false。true のとき起動時に警告ログを出す。本番では使わない。
	AllowInsecureIssuer bool

	// Store は永続化 Adapter。必須。
	Store Store

	// Keys は ID Token の署名鍵セット。必須。RS256 の署名鍵を含むこと
	// （OIDC Core §15.1、Client の既定アルゴリズム）。
	Keys *keys.Set

	// Resources は Resource Server（RFC 8707 の resource indicator）の静的設定（ADR-0008 §1）。
	// 認可要求の resource はこの一覧にあるものだけを受理し、それ以外は invalid_target になる。
	// 空なら resource 付きの要求はすべて invalid_target（意図したフェイルクローズ）。
	Resources []resource.Resource

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
	// Resources は検証・正規化済みの Resource Server 設定。
	Resources *resource.Set

	Authorization *authorization.Service
	Token         *token.Service
	// Grants は Grant の管理操作（一覧・連携解除）。Go API と Interaction API の GET /grants が使う。
	Grants   *grant.Service
	IDTokens *oidc.IDTokenIssuer
	UserInfo *oidc.UserInfoService
}

// New は Config を検証して Engine を組み立てる。
func New(cfg Config) (*Engine, error) {
	if err := validateIssuer(cfg.Issuer, cfg.AllowInsecureIssuer); err != nil {
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
	resources, err := resource.NewSet(cfg.Resources)
	if err != nil {
		return nil, fmt.Errorf("authengine: Resources: %w", err)
	}
	// JWT を発行する resource の署名アルゴリズムに対応する署名鍵があることを起動時に確認する。
	for _, uri := range resources.URIs() {
		r, _ := resources.Lookup(uri)
		if alg := r.EffectiveAlg(); alg != "" {
			if _, err := cfg.Keys.SigningKey(alg); err != nil {
				return nil, fmt.Errorf("authengine: Resources: %s requires a %s signing key in Keys", uri, alg)
			}
		}
	}

	var clk clock.Clock = clock.Real{}
	if cfg.Now != nil {
		clk = clock.Func(cfg.Now)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.AllowInsecureIssuer {
		logger.Warn("insecure issuer allowed: http issuer accepted for non-localhost hosts; use only for local development",
			"event", "config.insecure_issuer", "issuer", cfg.Issuer)
	}

	e := &Engine{Issuer: cfg.Issuer, Store: cfg.Store, Keys: cfg.Keys, Logger: logger, Clock: clk, Resources: resources}
	e.IDTokens = &oidc.IDTokenIssuer{Issuer: cfg.Issuer, Keys: cfg.Keys, Clock: clk, TTL: cfg.IDTokenTTL}
	e.UserInfo = &oidc.UserInfoService{Tokens: cfg.Store, Clock: clk}
	e.Grants = &grant.Service{Store: cfg.Store, Clock: clk}
	e.Authorization = &authorization.Service{
		Clients:        cfg.Store,
		Store:          cfg.Store,
		Grants:         cfg.Store,
		Resources:      resources,
		Clock:          clk,
		Issuer:         cfg.Issuer,
		TransactionTTL: cfg.TransactionTTL,
		CodeTTL:        cfg.CodeTTL,
	}
	e.Token = &token.Service{
		Clients:   cfg.Store,
		Store:     cfg.Store,
		Grants:    cfg.Store,
		Clock:     clk,
		Logger:    logger,
		IDTokens:  e.IDTokens,
		Resources: resources,
		Issuer: token.ByFormat{
			resource.FormatOpaque: token.OpaqueIssuer{},
			resource.FormatJWT:    &token.JWTIssuer{Issuer: cfg.Issuer, Keys: cfg.Keys},
		},
		RefreshTokenTTL:     refreshTTL,
		RefreshTokenIdleTTL: refreshIdle,
	}
	return e, nil
}

// ValidateIssuer は Issuer の形式を検証する。http は localhost / loopback に限る。
func ValidateIssuer(issuer string) error { return validateIssuer(issuer, false) }

func validateIssuer(issuer string, allowInsecure bool) error {
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
		if !allowInsecure && !isLocalHost(u.Hostname()) {
			return errors.New("authengine: Issuer must use https (http is allowed only for localhost unless AllowInsecureIssuer is set)")
		}
	default:
		return errors.New("authengine: Issuer scheme must be https")
	}
	return nil
}

func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
