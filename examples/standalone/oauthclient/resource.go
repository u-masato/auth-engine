package oauthclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ResourceMetadata は RFC 9728 §2 の Protected Resource Metadata のうち、クライアントが使う部分。
type ResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
	ResourceName         string   `json:"resource_name"`
}

// Challenge は Resource Server の 401 応答に付く WWW-Authenticate: Bearer のパラメータ（RFC 6750 §3）。
type Challenge struct {
	// ResourceMetadata はメタデータの URL（RFC 9728 §5.1）。空なら well-known の既定パスから組む。
	ResourceMetadata string
	// Scope は Resource Server が求める scope（空白区切り。MCP「Scope Selection Strategy」）。
	Scope string
	Error string
}

// Discovery は MCP サーバー（Resource Server）から辿った結果。
type Discovery struct {
	Metadata  *ResourceMetadata
	Challenge Challenge
}

// DiscoverResource は MCP 仕様「Authorization Server Location」の手順で Resource Server のメタデータを得る。
// resourceURL にトークンなしで要求し、401 の WWW-Authenticate から resource_metadata を読む（なければ
// RFC 9728 §3.1 の well-known パスを組む）。取得したメタデータの resource は resourceURL と一致すること
// （RFC 9728 §3.3、MCP「Canonical Server URI」）。
func DiscoverResource(ctx context.Context, hc *http.Client, resourceURL string) (*Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("oauthclient: %s returned %d without a token; expected 401", resourceURL, res.StatusCode)
	}
	ch := ParseChallenge(res.Header.Values("WWW-Authenticate"))
	metadataURL := ch.ResourceMetadata
	if metadataURL == "" {
		metadataURL, err = wellKnownResourceMetadata(resourceURL)
		if err != nil {
			return nil, err
		}
	}
	md, err := fetchResourceMetadata(ctx, hc, metadataURL)
	if err != nil {
		return nil, err
	}
	if md.Resource != resourceURL {
		return nil, fmt.Errorf("oauthclient: resource metadata is for %q, not %q (use the canonical URI)", md.Resource, resourceURL)
	}
	if len(md.AuthorizationServers) == 0 {
		return nil, errors.New("oauthclient: resource metadata lists no authorization_servers")
	}
	return &Discovery{Metadata: md, Challenge: ch}, nil
}

// wellKnownResourceMetadata は RFC 9728 §3.1 のとおり、path を持つ resource では
// /.well-known/oauth-protected-resource の後ろに path を付ける。
func wellKnownResourceMetadata(resourceURL string) (string, error) {
	u, err := url.Parse(resourceURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("oauthclient: resource %q must be an absolute http(s) URL", resourceURL)
	}
	path := strings.TrimSuffix(u.Path, "/")
	u.Path = "/.well-known/oauth-protected-resource" + path
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

func fetchResourceMetadata(ctx context.Context, hc *http.Client, metadataURL string) (*ResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauthclient: resource metadata %s returned %d", metadataURL, res.StatusCode)
	}
	var md ResourceMetadata
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&md); err != nil {
		return nil, fmt.Errorf("oauthclient: resource metadata %s: %w", metadataURL, err)
	}
	return &md, nil
}

// ParseChallenge は WWW-Authenticate ヘッダ群から Bearer チャレンジのパラメータを取り出す（RFC 6750 §3、RFC 9110 §11.6.1）。
// Bearer 以外のスキームは無視する。クライアントが使う 3 つのパラメータだけを返す。
func ParseChallenge(headers []string) Challenge {
	var ch Challenge
	for _, h := range headers {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		for k, v := range authParams(rest) {
			switch strings.ToLower(k) {
			case "resource_metadata":
				ch.ResourceMetadata = v
			case "scope":
				ch.Scope = v
			case "error":
				ch.Error = v
			}
		}
	}
	return ch
}

// authParams は `k="v", k2=v2` を読む。quoted-string のバックスラッシュエスケープを解く。
func authParams(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t,")
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[:eq])
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(s); i++ {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					continue
				}
				if c == '"' {
					break
				}
				b.WriteByte(c)
			}
			val = b.String()
			if i < len(s) {
				i++
			}
			s = s[i:]
		} else {
			end := strings.IndexByte(s, ',')
			if end < 0 {
				end = len(s)
			}
			val = strings.TrimSpace(s[:end])
			s = s[end:]
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// CallResource は Access Token を Bearer として付けて resourceURL を呼び、応答をそのまま返す（RFC 6750 §2.1）。
// 呼び出し側がステータスと WWW-Authenticate（401 invalid_token、403 insufficient_scope）を解釈する。
func CallResource(ctx context.Context, hc *http.Client, method, resourceURL, accessToken string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, resourceURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return hc.Do(req)
}
