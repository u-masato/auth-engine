package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	authengine "github.com/muno/auth-engine"
)

// エンドポイントのパス。Issuer 直下に固定する（ADR-0001 §2「選ばせない」）。
const (
	PathAuthorize = "/authorize"
	PathResume    = "/authorize/resume"
	PathToken     = "/token"
	PathJWKS      = "/jwks"
	PathUserInfo  = "/userinfo"
	PathMetadata  = "/.well-known/oauth-authorization-server"
	PathOpenID    = "/.well-known/openid-configuration"
)

// Config は HTTP 層の設定。
type Config struct {
	// Engine は配線済みの本体。必須。
	Engine *authengine.Engine

	// InteractionURL は Interaction App のログイン画面の URL。/authorize はここへ
	// `txn` クエリを付けてリダイレクトする。必須。
	InteractionURL string

	// InteractionAuth は Interaction API の認証。必須。既定実装は BearerAuthenticator。
	InteractionAuth InteractionAuthenticator

	// ErrorRenderer はリダイレクトできないエラーの描写。nil なら PlainErrorRenderer。
	ErrorRenderer ErrorRenderer

	// InsecureCookies は開発用に Secure 属性と __Host- プレフィックスを外す。
	// 既定 false。true のとき起動時に警告ログを出す。
	InsecureCookies bool

	// Logger は nil なら Engine.Logger。
	Logger *slog.Logger
}

// Server は 2 つの http.Handler を生成する。
type Server struct {
	cfg            Config
	engine         *authengine.Engine
	interactionURL *url.URL
	render         ErrorRenderer
	logger         *slog.Logger
}

// New は Config を検証して Server を返す。
func New(cfg Config) (*Server, error) {
	if cfg.Engine == nil {
		return nil, errors.New("httpapi: Engine is required")
	}
	iu, err := url.Parse(cfg.InteractionURL)
	if err != nil || iu.Scheme == "" || iu.Host == "" {
		return nil, errors.New("httpapi: InteractionURL must be an absolute URL")
	}
	if cfg.InteractionAuth == nil {
		return nil, errors.New("httpapi: InteractionAuth is required")
	}
	s := &Server{cfg: cfg, engine: cfg.Engine, interactionURL: iu, render: cfg.ErrorRenderer, logger: cfg.Logger}
	if s.render == nil {
		s.render = PlainErrorRenderer{}
	}
	if s.logger == nil {
		s.logger = cfg.Engine.Logger
	}
	if cfg.InsecureCookies {
		s.logger.Warn("insecure cookies enabled: browser binding cookie is sent without Secure; use only for local development",
			"event", "config.insecure_cookies")
	}
	return s, nil
}

// PublicHandler は Client とブラウザ向けの公開エンドポイントを返す。
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("POST "+PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("GET "+PathResume, s.handleResume)
	mux.HandleFunc("POST "+PathToken, s.handleToken)
	mux.HandleFunc("GET "+PathJWKS, s.handleJWKS)
	mux.HandleFunc("GET "+PathMetadata, s.handleMetadata)
	mux.HandleFunc("GET "+PathOpenID, s.handleOpenIDConfiguration)
	return mux
}

// InteractionHandler は Interaction App 向けのバックチャネル API を返す。
// 全ルートで InteractionAuth を通す。
func (s *Server) InteractionHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /transactions/{id}", s.handleGetTransaction)
	mux.HandleFunc("POST /transactions/{id}/complete", s.handleComplete)
	mux.HandleFunc("POST /transactions/{id}/reject", s.handleReject)
	return s.requireInteractionAuth(mux)
}

// endpoint は Issuer 直下のエンドポイント URL を返す。
func (s *Server) endpoint(path string) string {
	u, _ := url.Parse(s.engine.Issuer)
	u.Path = path
	u.RawQuery = ""
	return u.String()
}

// resumeURL は Interaction App がブラウザを戻す先（ADR-0003 §3 (5)）。
func (s *Server) resumeURL(txnID, resumeToken string) string {
	u, _ := url.Parse(s.endpoint(PathResume))
	q := url.Values{}
	q.Set("txn", txnID)
	q.Set("token", resumeToken)
	u.RawQuery = q.Encode()
	return u.String()
}

// redirect は 302 で Location を返す。認可応答のリダイレクトは RFC 6749 §4.1.2 の例に従い 302 を使う。
func redirect(w http.ResponseWriter, r *http.Request, location string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, location, http.StatusFound)
}
