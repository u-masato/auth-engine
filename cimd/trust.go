package cimd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// TrustPolicy は CIMD の client_id URL を受け入れるかを決める（CIMD §8.9、MCP 仕様「Trust Policies」）。
//
// 文書を取得する前に呼ばれる。拒否すると Client は解決されず、認可要求は理由付きの invalid_request、
// トークン要求は invalid_client になる。ドメイン許可リストや初回利用の確認などは利用者が実装する。
type TrustPolicy interface {
	// Allow は clientID を受け入れるなら nil、拒否するなら理由を表す error を返す。
	Allow(ctx context.Context, clientID *url.URL) error
}

// AllowAll はすべての client_id URL を受け入れる既定の TrustPolicy。
type AllowAll struct{}

// Allow は常に nil を返す。
func (AllowAll) Allow(context.Context, *url.URL) error { return nil }

// ErrUntrusted は TrustPolicy が client_id を拒否したことを表す。
var ErrUntrusted = errors.New("cimd: client_id is not trusted")

// HostAllowlist は client_id URL のホスト名が一覧にあるものだけを受け入れる TrustPolicy。
// 比較は大文字小文字を区別しない。"*.example.com" の形はそのサブドメイン（example.com 自身は含まない）に一致する。
type HostAllowlist []string

// Allow はホスト名が一覧に含まれるかを返す。
func (a HostAllowlist) Allow(_ context.Context, clientID *url.URL) error {
	host := strings.ToLower(clientID.Hostname())
	for _, pattern := range a {
		pattern = strings.ToLower(pattern)
		if sub, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+sub) {
				return nil
			}
			continue
		}
		if host == pattern {
			return nil
		}
	}
	return fmt.Errorf("%w: host %q is not in the allowlist", ErrUntrusted, host)
}
