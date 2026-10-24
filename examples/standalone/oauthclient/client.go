// Package oauthclient は、エンジンに対して Authorization Code + PKCE を実行する
// 最小限の OAuth 2.0 クライアントである。サンプル CLI と E2E テストで使う。
//
// 対応する仕様: RFC 6749 §4.1 / §4.4 / §6、RFC 7009、RFC 7636（S256）、RFC 7662、RFC 8252 §7.3（loopback redirect）、
// RFC 8414（メタデータ取得）、RFC 9207（iss の検証）、OIDC Core §5.3（UserInfo）。
package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Metadata は RFC 8414 のメタデータのうち、クライアントが使う部分。
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Discover は issuer のメタデータを取得する。
func Discover(ctx context.Context, hc *http.Client, issuer string) (*Metadata, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauthclient: discovery returned %d", res.StatusCode)
	}
	var md Metadata
	if err := json.NewDecoder(res.Body).Decode(&md); err != nil {
		return nil, err
	}
	if md.Issuer != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("oauthclient: issuer mismatch: %q", md.Issuer)
	}
	return &md, nil
}

// CodeFlow は 1 回の Authorization Code フローの状態。
type CodeFlow struct {
	Metadata     *Metadata
	ClientID     string
	ClientSecret string // confidential クライアントのみ。空なら public
	RedirectURI  string
	Scopes       []string
	HTTPClient   *http.Client
	// Extra は認可要求に足すパラメータ（nonce、prompt、login_hint、max_age など）。
	// response_type や PKCE のように CodeFlow が決めるパラメータは上書きできない。
	Extra url.Values

	state    string
	verifier string
}

// NewCodeFlow は state と PKCE の code_verifier を生成してフローを初期化する。
func NewCodeFlow(md *Metadata, clientID, redirectURI string, scopes []string) (*CodeFlow, error) {
	state, err := randomString(16)
	if err != nil {
		return nil, err
	}
	verifier, err := randomString(32) // 43 文字の base64url（RFC 7636 §4.1 の範囲内）
	if err != nil {
		return nil, err
	}
	return &CodeFlow{Metadata: md, ClientID: clientID, RedirectURI: redirectURI, Scopes: scopes,
		HTTPClient: &http.Client{Timeout: 10 * time.Second}, state: state, verifier: verifier}, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthorizationURL はブラウザで開く認可要求 URL を返す。
func (f *CodeFlow) AuthorizationURL() string {
	sum := sha256.Sum256([]byte(f.verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {f.ClientID},
		"redirect_uri":          {f.RedirectURI},
		"scope":                 {strings.Join(f.Scopes, " ")},
		"state":                 {f.state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range f.Extra {
		if _, ok := q[k]; !ok {
			q[k] = v
		}
	}
	return f.Metadata.AuthorizationEndpoint + "?" + q.Encode()
}

// State はこのフローの state を返す。コールバックを受ける側がフローを引き当てるのに使う。
func (f *CodeFlow) State() string { return f.state }

// AuthorizationError は認可サーバーがエラー応答を返したことを表す。
type AuthorizationError struct {
	Code        string
	Description string
}

func (e *AuthorizationError) Error() string {
	return "authorization error: " + e.Code + ": " + e.Description
}

// HandleCallback はリダイレクト先に届いたクエリを検証して Code を返す。
// state と iss（RFC 9207）が一致しなければエラー。
func (f *CodeFlow) HandleCallback(q url.Values) (string, error) {
	if q.Get("state") != f.state {
		return "", errors.New("oauthclient: state mismatch")
	}
	if iss := q.Get("iss"); iss != f.Metadata.Issuer {
		return "", fmt.Errorf("oauthclient: iss mismatch: %q", iss)
	}
	if e := q.Get("error"); e != "" {
		return "", &AuthorizationError{Code: e, Description: q.Get("error_description")}
	}
	code := q.Get("code")
	if code == "" {
		return "", errors.New("oauthclient: no code in callback")
	}
	return code, nil
}

// TokenResponse は RFC 6749 §5.1 の応答。
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// TokenError は RFC 6749 §5.2 のエラー応答。
type TokenError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("token error: %d %s: %s", e.Status, e.Code, e.Description)
}

// Exchange は Code をトークンに交換する。
func (f *CodeFlow) Exchange(ctx context.Context, code string) (*TokenResponse, error) {
	return f.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.RedirectURI},
		"code_verifier": {f.verifier},
	})
}

// Refresh は Refresh Token で新しいトークンを得る（RFC 6749 §6）。scope は空なら省略。
// 応答の refresh_token は Rotation された後継なので、呼び出し側は必ず差し替えること。
func (f *CodeFlow) Refresh(ctx context.Context, refreshToken, scope string) (*TokenResponse, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return f.tokenRequest(ctx, form)
}

// Revoke はトークンを失効させる（RFC 7009）。hint は "access_token" / "refresh_token" / 空。
func (f *CodeFlow) Revoke(ctx context.Context, token, hint string) error {
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	res, err := f.HTTPClient.Do(f.formRequest(ctx, f.Metadata.RevocationEndpoint, form))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		terr := &TokenError{Status: res.StatusCode}
		_ = json.Unmarshal(body, terr)
		return terr
	}
	return nil
}

// ClientCredentials は Client Credentials Grant でトークンを得る（RFC 6749 §4.4）。
// Machine Profile 用で、state・PKCE・RedirectURI は使わない。scope は空なら省略。
func (f *CodeFlow) ClientCredentials(ctx context.Context, scope string) (*TokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return f.tokenRequest(ctx, form)
}

// Introspect はトークンの状態を問い合わせる（RFC 7662 §2）。confidential クライアントだけが呼べる。
// 応答は §2.2 の JSON をそのまま返す。
func (f *CodeFlow) Introspect(ctx context.Context, token, hint string) (map[string]any, error) {
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	res, err := f.HTTPClient.Do(f.formRequest(ctx, f.Metadata.IntrospectionEndpoint, form))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		terr := &TokenError{Status: res.StatusCode}
		_ = json.Unmarshal(body, terr)
		return nil, terr
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UserInfo は Access Token で UserInfo エンドポイントを呼ぶ（OIDC Core §5.3）。
func (f *CodeFlow) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.Metadata.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		terr := &TokenError{Status: res.StatusCode}
		_ = json.Unmarshal(body, terr)
		return nil, terr
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// formRequest はクライアント認証付きの form-urlencoded POST を組み立てる。
// confidential なら Basic（RFC 6749 §2.3.1: form-urlencoded してから Basic）、public なら client_id をフォームに入れる。
func (f *CodeFlow) formRequest(ctx context.Context, endpoint string, form url.Values) *http.Request {
	if f.ClientSecret == "" {
		form.Set("client_id", f.ClientID)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(f.ClientID), url.QueryEscape(f.ClientSecret))
	}
	return req
}

func (f *CodeFlow) tokenRequest(ctx context.Context, form url.Values) (*TokenResponse, error) {
	res, err := f.HTTPClient.Do(f.formRequest(ctx, f.Metadata.TokenEndpoint, form))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		terr := &TokenError{Status: res.StatusCode}
		_ = json.Unmarshal(body, terr)
		return nil, terr
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// ListenLoopback は 127.0.0.1 の空きポートで待ち受け、RFC 8252 §7.3 の loopback redirect URI を返す。
func ListenLoopback() (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	return ln, fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port), nil
}

// WaitForCallback は ln で 1 回だけ /callback を受け、そのクエリを返す。ブラウザには完了ページを返す。
func WaitForCallback(ctx context.Context, ln net.Listener) (url.Values, error) {
	result := make(chan url.Values, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><body><p>You may close this window.</p></body></html>")
		select {
		case result <- r.URL.Query():
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	select {
	case q := <-result:
		return q, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
