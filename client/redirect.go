package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrRedirectURIMismatch は、要求された redirect_uri が登録済みのどれとも一致しないことを表す。
	// RFC 6749 §4.1.2.1 により、この場合は Client へリダイレクトしてはならない。
	ErrRedirectURIMismatch = errors.New("client: redirect_uri does not match any registered URI")

	// ErrRedirectURIRequired は、redirect_uri が省略されたが登録 URI が 1 つに定まらないことを表す
	// （RFC 6749 §3.1.2.3）。
	ErrRedirectURIRequired = errors.New("client: redirect_uri is required")
)

// 認可サーバーがリダイレクト先として扱うべきでないスキーム。
var forbiddenSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "about": true, "blob": true, "vbscript": true,
}

// ResolveRedirectURI は認可要求の redirect_uri を登録情報と照合し、実際に使う URI を返す。
//
//   - requested が空: 登録 URI がちょうど 1 つならそれを使う（RFC 6749 §3.1.2.3）。
//   - requested が非空: 完全一致を要求する（RFC 9700 §4.1.3）。Native と MCP の http loopback だけは
//     ポート番号の違いを許す（RFC 8252 §7.3）。http://localhost はポートも含めて完全一致。
func (c *Client) ResolveRedirectURI(requested string) (string, error) {
	if requested == "" {
		if len(c.RedirectURIs) == 1 {
			return c.RedirectURIs[0], nil
		}
		return "", ErrRedirectURIRequired
	}
	for _, reg := range c.RedirectURIs {
		if reg == requested {
			return reg, nil
		}
	}
	if c.Profile.rules().redirect.ignoresLoopbackPort() && loopbackMatch(c.RedirectURIs, requested) {
		return requested, nil
	}
	return "", ErrRedirectURIMismatch
}

// ignoresLoopbackPort は http loopback の redirect URI をポート番号を無視して照合する規則か（RFC 8252 §7.3）。
func (p redirectPolicy) ignoresLoopbackPort() bool {
	return p == redirectNative || p == redirectMCP
}

// loopbackMatch は requested が、登録済みの http loopback URI とポート番号以外で一致するかを返す。
func loopbackMatch(registered []string, requested string) bool {
	req, err := url.Parse(requested)
	if err != nil || req.Scheme != "http" || !isLoopbackIP(req.Hostname()) || req.Fragment != "" || req.User != nil {
		return false
	}
	for _, r := range registered {
		reg, err := url.Parse(r)
		if err != nil || reg.Scheme != "http" || !isLoopbackIP(reg.Hostname()) {
			continue
		}
		if reg.Hostname() == req.Hostname() && reg.Path == req.Path && reg.RawQuery == req.RawQuery {
			return true
		}
	}
	return false
}

// validateRedirectURIs は登録時の redirect URI を Profile の規則で検証する。
func validateRedirectURIs(policy redirectPolicy, uris []string, allowInsecureLocalhost bool) error {
	if policy == redirectNone {
		if len(uris) != 0 {
			return fmt.Errorf("%w: this profile does not use redirect URIs", ErrInvalid)
		}
		return nil
	}
	if len(uris) == 0 {
		return fmt.Errorf("%w: at least one redirect URI is required", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(uris))
	for _, raw := range uris {
		if _, dup := seen[raw]; dup {
			return fmt.Errorf("%w: duplicate redirect URI %q", ErrInvalid, raw)
		}
		seen[raw] = struct{}{}

		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" {
			return fmt.Errorf("%w: redirect URI %q must be an absolute URI", ErrInvalid, raw)
		}
		// RFC 6749 §3.1.2: フラグメントを含めてはならない。
		if u.Fragment != "" || strings.HasSuffix(raw, "#") {
			return fmt.Errorf("%w: redirect URI %q must not contain a fragment", ErrInvalid, raw)
		}
		if forbiddenSchemes[strings.ToLower(u.Scheme)] {
			return fmt.Errorf("%w: redirect URI %q uses a forbidden scheme", ErrInvalid, raw)
		}

		var ok bool
		switch policy {
		case redirectWeb:
			ok = validWebRedirect(u, allowInsecureLocalhost)
		case redirectNative:
			ok = validNativeRedirect(u, allowInsecureLocalhost)
		case redirectMCP:
			ok = validMCPRedirect(u)
		}
		if !ok {
			return fmt.Errorf("%w: redirect URI %q is not allowed for this profile", ErrInvalid, raw)
		}
	}
	return nil
}

// validWebRedirect: https のみ。開発用緩和時は http://localhost と http loopback も可。
func validWebRedirect(u *url.URL, allowInsecureLocalhost bool) bool {
	if u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return allowInsecureLocalhost && (isLocalhost(u.Hostname()) || isLoopbackIP(u.Hostname()))
	}
	return false
}

// validNativeRedirect: https クレーム URL、カスタムスキーム、http loopback IP。
// http://localhost は RFC 8252 §8.3 に従い既定で拒否し、開発用緩和時のみ許す。
func validNativeRedirect(u *url.URL, allowInsecureLocalhost bool) bool {
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		host := u.Hostname()
		return isLoopbackIP(host) || (allowInsecureLocalhost && isLocalhost(host))
	default:
		// カスタムスキーム（例: com.example.app:/callback）。スキーム以外に何かが必要。
		return u.Opaque != "" || u.Host != "" || u.Path != ""
	}
}

// validMCPRedirect: https、http://localhost、http loopback IP（ADR-0008 §4）。
// MCP 仕様「Communication Security」は redirect URI を「localhost か HTTPS」と定め、CIMD 文書の例が
// http://localhost:3000/callback を使うため、Native Profile と異なり localhost を既定で許す。
// RFC 8252 §8.3 の懸念（localhost の名前解決の乗っ取り）は、Interaction App が同意画面で
// redirect URI のホスト名を表示することで補う（docs/interaction-api.md）。
func validMCPRedirect(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		host := u.Hostname()
		return isLoopbackIP(host) || isLocalhost(host)
	default:
		return false
	}
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLocalhost(host string) bool {
	return strings.EqualFold(host, "localhost")
}
