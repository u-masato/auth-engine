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
	"sync"
	"time"
)

// asMetadata は認可サーバーメタデータ（RFC 8414 §2）のうち Resource Server が使う項目。
type asMetadata struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// maxMetadataBody はメタデータ応答と JWKS 応答の上限。
const maxMetadataBody = 256 << 10

// metadataURL は issuer から RFC 8414 §3.1 の well-known URL を組み立てる
// （path を持つ issuer は host と path の間に挿入する）。
func metadataURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("resourceserver: issuer %q must be an absolute http(s) URL without query or fragment", issuer)
	}
	u.Path = "/.well-known/oauth-authorization-server" + strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}

// asClient は認可サーバーのメタデータを 1 回取得して保持する。
type asClient struct {
	issuer string
	http   *http.Client

	mu   sync.Mutex
	meta *asMetadata
}

func newASClient(issuer string, hc *http.Client) *asClient {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &asClient{issuer: issuer, http: hc}
}

// metadata はメタデータを返す。初回だけ取得し、issuer が一致することを確認する（RFC 8414 §3.3）。
func (c *asClient) metadata(ctx context.Context) (*asMetadata, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.meta != nil {
		return c.meta, nil
	}
	u, err := metadataURL(c.issuer)
	if err != nil {
		return nil, err
	}
	body, err := getJSON(ctx, c.http, u)
	if err != nil {
		return nil, fmt.Errorf("resourceserver: authorization server metadata: %w", err)
	}
	var m asMetadata
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("resourceserver: authorization server metadata: %w", err)
	}
	if strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(c.issuer, "/") {
		return nil, fmt.Errorf("resourceserver: authorization server metadata: issuer %q does not match %q (RFC 8414 §3.3)", m.Issuer, c.issuer)
	}
	c.meta = &m
	return c.meta, nil
}

// getJSON は GET で JSON 本文を取得する。200 以外はエラー。
func getJSON(ctx context.Context, hc *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", u, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxMetadataBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMetadataBody {
		return nil, errors.New("response too large")
	}
	return body, nil
}
