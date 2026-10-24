package resourceserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IntrospectionVerifier は認可サーバーの Introspection エンドポイント（RFC 7662）でトークンを検証する。
//
// Resource Server 自身を認可サーバーに Machine Profile の Client として登録し、その資格情報で
// client_secret_basic 認証する（ADR-0006 §1）。Opaque Access Token はこの方式でしか検証できない。
// JWT Access Token もこの方式で検証でき、失効が即時に反映される。
type IntrospectionVerifier struct {
	// Issuer は認可サーバーの issuer。Endpoint が空ならメタデータ（RFC 8414）から introspection_endpoint を得る。
	Issuer string
	// Endpoint は Introspection エンドポイントの URL。指定すればメタデータを取得しない。
	Endpoint string
	// ClientID / ClientSecret は Resource Server の資格情報（Machine Profile の Client）。必須。
	ClientID     string
	ClientSecret string
	// HTTPClient は nil なら 10 秒タイムアウトの既定。
	HTTPClient *http.Client

	as *asClient
}

var _ TokenVerifier = (*IntrospectionVerifier)(nil)

// introspectionResponse は RFC 7662 §2.2 の応答。aud は文字列か配列。
type introspectionResponse struct {
	Active    bool            `json:"active"`
	Scope     string          `json:"scope"`
	ClientID  string          `json:"client_id"`
	TokenType string          `json:"token_type"`
	Exp       int64           `json:"exp"`
	Iat       int64           `json:"iat"`
	Sub       string          `json:"sub"`
	Aud       json.RawMessage `json:"aud"`
}

// Verify はトークンを Introspection し、active なら Principal を返す。
//
// active が false、または token_type が Bearer でない（Refresh Token など。省略も拒否する）応答は
// ErrInvalidToken。Introspection エンドポイントに到達できない・応答が不正なときは通常の error（503 になる）。
func (v *IntrospectionVerifier) Verify(ctx context.Context, token string) (*Principal, error) {
	if v.ClientID == "" || v.ClientSecret == "" {
		return nil, errors.New("resourceserver: IntrospectionVerifier requires ClientID and ClientSecret")
	}
	endpoint, err := v.endpoint(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: Basic 認証の資格情報は form-urlencoded してから Base64 にする。
	req.SetBasicAuth(url.QueryEscape(v.ClientID), url.QueryEscape(v.ClientSecret))
	res, err := v.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("resourceserver: introspection: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxMetadataBody))
	if err != nil {
		return nil, fmt.Errorf("resourceserver: introspection: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resourceserver: introspection: status %d", res.StatusCode)
	}
	var in introspectionResponse
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("resourceserver: introspection: malformed response: %w", err)
	}
	if !in.Active {
		return nil, fmt.Errorf("%w: token is not active", ErrInvalidToken)
	}
	if !strings.EqualFold(in.TokenType, "Bearer") {
		return nil, fmt.Errorf("%w: token_type %q is not Bearer", ErrInvalidToken, in.TokenType)
	}
	aud, err := parseAudience(in.Aud)
	if err != nil {
		return nil, fmt.Errorf("resourceserver: introspection: %w", err)
	}
	p := &Principal{Subject: in.Sub, ClientID: in.ClientID, Scopes: strings.Fields(in.Scope), Audience: aud}
	if in.Exp != 0 {
		p.ExpiresAt = time.Unix(in.Exp, 0)
	}
	if in.Iat != 0 {
		p.IssuedAt = time.Unix(in.Iat, 0)
	}
	return p, nil
}

func (v *IntrospectionVerifier) endpoint(ctx context.Context) (string, error) {
	if v.Endpoint != "" {
		return v.Endpoint, nil
	}
	if v.Issuer == "" {
		return "", errors.New("resourceserver: IntrospectionVerifier requires Issuer or Endpoint")
	}
	if v.as == nil {
		v.as = newASClient(v.Issuer, v.httpClient())
	}
	m, err := v.as.metadata(ctx)
	if err != nil {
		return "", err
	}
	if m.IntrospectionEndpoint == "" {
		return "", errors.New("resourceserver: authorization server metadata has no introspection_endpoint")
	}
	return m.IntrospectionEndpoint, nil
}

func (v *IntrospectionVerifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// parseAudience は aud（文字列または配列。RFC 7519 §4.1.3）を配列にする。
func parseAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("aud must be a string or an array of strings: %w", err)
	}
	return many, nil
}
