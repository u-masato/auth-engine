package resourceserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/resource"
)

// WellKnownPath は RFC 9728 §3 の well-known URI のパス部分。
const WellKnownPath = "/.well-known/oauth-protected-resource"

// Config は Protector の設定。
type Config struct {
	// Resource は自分自身の resource URI（RFC 8707 の resource indicator。RFC 9728 §2 の resource）。必須。
	// 認可サーバーの Config.Resources に登録した値と同じものを使う。トークンの aud はこれと正規形で比較する。
	Resource string

	// AuthorizationServers はこの Resource Server 向けのトークンを発行する認可サーバーの issuer。1 つ以上。
	// RFC 9728 §2 の authorization_servers に載せ、クライアントはここから認可サーバーのメタデータを見つける。
	AuthorizationServers []string

	// Scopes はこの Resource Server が理解する scope（RFC 9728 §2 の scopes_supported）。省略可。
	Scopes []string

	// Name は表示名（resource_name）。Documentation は利用者向け文書の URL（resource_documentation）。いずれも省略可。
	Name          string
	Documentation string

	// Verifier はトークンの検証方式。必須。IntrospectionVerifier か JWTVerifier、または独自実装。
	Verifier TokenVerifier

	// Now は現在時刻の取得関数。nil なら time.Now。
	Now func() time.Time

	// Logger は検証失敗などの出力先。nil なら slog.Default()。
	Logger *slog.Logger
}

// Metadata は RFC 9728 §2 の Protected Resource Metadata。
type Metadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// Protector は 1 つの Resource Server を表し、メタデータの配信とトークン検証のミドルウェアを提供する。
type Protector struct {
	resource     string // 正規形
	metadata     Metadata
	metadataURL  string
	metadataPath string
	verifier     TokenVerifier
	now          func() time.Time
	logger       *slog.Logger
}

// New は Config を検証して Protector を返す。
func New(cfg Config) (*Protector, error) {
	res, err := resource.Normalize(cfg.Resource)
	if err != nil {
		return nil, fmt.Errorf("resourceserver: Resource: %w", err)
	}
	u, err := url.Parse(res)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		// RFC 9728 §3 の well-known URI は http(s) の resource にしか組み立てられない
		return nil, errors.New("resourceserver: Resource must be an http(s) URL")
	}
	if u.RawQuery != "" {
		return nil, errors.New("resourceserver: Resource must not contain a query (RFC 9728 §3)")
	}
	if len(cfg.AuthorizationServers) == 0 {
		return nil, errors.New("resourceserver: at least one AuthorizationServer is required")
	}
	for _, as := range cfg.AuthorizationServers {
		if au, err := url.Parse(as); err != nil || (au.Scheme != "https" && au.Scheme != "http") || au.Host == "" {
			return nil, fmt.Errorf("resourceserver: AuthorizationServers: %q must be an absolute http(s) URL", as)
		}
	}
	if cfg.Verifier == nil {
		return nil, errors.New("resourceserver: Verifier is required")
	}
	p := &Protector{
		resource: res,
		metadata: Metadata{
			Resource:               res,
			AuthorizationServers:   slices.Clone(cfg.AuthorizationServers),
			ScopesSupported:        slices.Clone(cfg.Scopes),
			BearerMethodsSupported: []string{"header"},
			ResourceName:           cfg.Name,
			ResourceDocumentation:  cfg.Documentation,
		},
		verifier: cfg.Verifier,
		now:      cfg.Now,
		logger:   cfg.Logger,
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.logger == nil {
		p.logger = slog.Default()
	}
	// RFC 9728 §3: path を持つ resource の well-known URI は host と path の間に挿入する。
	mu := *u
	mu.Path = WellKnownPath + strings.TrimSuffix(u.Path, "/")
	p.metadataURL, p.metadataPath = mu.String(), mu.Path
	return p, nil
}

// Resource は正規化した resource URI を返す。
func (p *Protector) Resource() string { return p.resource }

// MetadataPath は MetadataHandler を mount すべきパス（RFC 9728 §3）。
// resource が https://mcp.example.com なら /.well-known/oauth-protected-resource、
// https://mcp.example.com/api なら /.well-known/oauth-protected-resource/api。
func (p *Protector) MetadataPath() string { return p.metadataPath }

// MetadataURL は WWW-Authenticate の resource_metadata に載せる絶対 URL。
func (p *Protector) MetadataURL() string { return p.metadataURL }

// Metadata は配信するメタデータの写し。
func (p *Protector) Metadata() Metadata {
	m := p.metadata
	m.AuthorizationServers = slices.Clone(m.AuthorizationServers)
	m.ScopesSupported = slices.Clone(m.ScopesSupported)
	m.BearerMethodsSupported = slices.Clone(m.BearerMethodsSupported)
	return m
}

// MetadataHandler は GET /.well-known/oauth-protected-resource[/{path}] を返す（RFC 9728 §3.1）。
// MetadataPath に mount する。認証は要らない（クライアントは 401 を受けた後、トークンなしで取得する）。
func (p *Protector) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(p.metadata)
	})
}

// Require は Bearer トークンを検証し、scopes がすべて付与されていることを確認するミドルウェアを返す。
//
//   - トークンなし: 401、WWW-Authenticate: Bearer resource_metadata="...", scope="..."（RFC 9728 §5.1。
//     scope は要求に必要なもの。MCP 仕様「Scope Selection Strategy」）
//   - 無効なトークン、aud に自分が含まれないトークン: 401、error="invalid_token"（RFC 6750 §3.1）
//   - scope 不足: 403、error="insufficient_scope"、scope="必要な scope"（MCP 仕様「Runtime Insufficient Scope Errors」）
//   - 検証方式の障害（認可サーバーに到達できない等）: 503
//
// 通ったら Principal を context に載せて next を呼ぶ。scopes が空なら有効なトークンだけを要求する。
func (p *Protector) Require(scopes ...string) func(http.Handler) http.Handler {
	required := slices.Clone(scopes)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, present, ok := bearerToken(r)
			if !present {
				p.challenge(w, http.StatusUnauthorized, "", "", required)
				return
			}
			if !ok {
				p.challenge(w, http.StatusBadRequest, "invalid_request", "malformed Authorization header", required)
				return
			}
			pr, err := p.verifier.Verify(r.Context(), token)
			if err != nil {
				if errors.Is(err, ErrInvalidToken) {
					p.logger.InfoContext(r.Context(), "resourceserver: token rejected", "event", "rs.invalid_token", "error", err)
					p.challenge(w, http.StatusUnauthorized, "invalid_token", trimPrefix(err), required)
					return
				}
				p.logger.ErrorContext(r.Context(), "resourceserver: token verification failed", "event", "rs.verifier_error", "error", err)
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "token verification is unavailable"})
				return
			}
			// aud に自分が含まれること（MCP 仕様「Token Handling」。無効化する設定は置かない）。
			if !p.audienceMatches(pr.Audience) {
				p.logger.WarnContext(r.Context(), "resourceserver: token for another resource", "event", "rs.audience_mismatch", "aud", pr.Audience, "client_id", pr.ClientID)
				p.challenge(w, http.StatusUnauthorized, "invalid_token", "token is not intended for this resource", required)
				return
			}
			if !pr.ExpiresAt.IsZero() && !p.now().Before(pr.ExpiresAt) {
				p.challenge(w, http.StatusUnauthorized, "invalid_token", "token has expired", required)
				return
			}
			for _, s := range required {
				if !pr.HasScope(s) {
					p.challenge(w, http.StatusForbidden, "insufficient_scope", "the request requires higher privileges than provided by the access token", required)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, pr)))
		})
	}
}

// Protect は Require(scopes...)(next) の短縮形。
func (p *Protector) Protect(next http.Handler, scopes ...string) http.Handler {
	return p.Require(scopes...)(next)
}

// audienceMatches は aud に自分の resource が正規形で含まれるかを返す。
func (p *Protector) audienceMatches(aud []string) bool {
	for _, a := range aud {
		if a == p.resource { // 認可サーバーは正規形で発行するので、普段はここで一致する
			return true
		}
		if n, err := resource.Normalize(a); err == nil && n == p.resource {
			return true
		}
	}
	return false
}

// bearerToken は Authorization: Bearer <token> を取り出す（RFC 6750 §2.1）。
// present はヘッダがあるか、ok は形式が正しいか。クエリやフォームの access_token は受け付けない
// （bearer_methods_supported は header のみ）。
func bearerToken(r *http.Request) (token string, present, ok bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false, false
	}
	scheme, rest, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", true, false
	}
	token = strings.TrimSpace(rest)
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", true, false
	}
	return token, true, true
}

// challenge は WWW-Authenticate 付きのエラー応答を書く（RFC 6750 §3、RFC 9728 §5.1）。
// code が空のときはトークン未提示で、RFC 6750 §3.1 のとおりエラーコードを付けない。
func (p *Protector) challenge(w http.ResponseWriter, status int, code, description string, scopes []string) {
	params := []string{fmt.Sprintf(`resource_metadata=%s`, quote(p.metadataURL))}
	if code != "" {
		params = append(params, fmt.Sprintf(`error=%s`, quote(code)))
		if description != "" {
			params = append(params, fmt.Sprintf(`error_description=%s`, quote(description)))
		}
	}
	if len(scopes) > 0 {
		params = append(params, fmt.Sprintf(`scope=%s`, quote(strings.Join(scopes, " "))))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	w.Header().Set("Cache-Control", "no-store")
	if code == "" {
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// quote は RFC 7235 の quoted-string にする。
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func trimPrefix(err error) string {
	return strings.TrimPrefix(err.Error(), "resourceserver: ")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
