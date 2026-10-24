package client

import (
	"fmt"
	"slices"

	"github.com/muno/auth-engine/resource"
)

// validateResources は登録時の resource 一覧を検証する。各要素は resource.Normalize を通る
// 絶対 URI で、正規形で重複しないこと。空は「制限なし」で正当。
func validateResources(uris []string) error {
	seen := make(map[string]struct{}, len(uris))
	for _, raw := range uris {
		n, err := resource.Normalize(raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if _, dup := seen[n]; dup {
			return fmt.Errorf("%w: duplicate resource %q", ErrInvalid, n)
		}
		seen[n] = struct{}{}
	}
	return nil
}

// AllowsResource は uri（RFC 8707 の resource indicator）をこのクライアントに許可しているかを返す。
// Resources が空なら全 resource を許可する（ADR-0008 §2）。設定済みかどうかの判定は
// resource.Set の責務で、ここでは Client の許可範囲だけを見る。
func (c *Client) AllowsResource(uri string) bool {
	if len(c.Resources) == 0 {
		return true
	}
	n, err := resource.Normalize(uri)
	if err != nil {
		return false
	}
	return slices.Contains(c.Resources, n)
}
