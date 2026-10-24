package client

import "fmt"

// validateScopes は scope の一覧が空でなく、各要素が RFC 6749 §3.3 の scope-token 構文に
// 従い、重複がないことを検証する。
func validateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("%w: at least one scope is required", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if !ValidScopeToken(s) {
			return fmt.Errorf("%w: invalid scope token %q", ErrInvalid, s)
		}
		if _, dup := seen[s]; dup {
			return fmt.Errorf("%w: duplicate scope %q", ErrInvalid, s)
		}
		seen[s] = struct{}{}
	}
	return nil
}

// ValidScopeToken は s が RFC 6749 §3.3 の scope-token
// （1*( %x21 / %x23-5B / %x5D-7E )、つまり空白・二重引用符・バックスラッシュを含まない
// 印字可能 ASCII）であるかを返す。
func ValidScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == 0x21, ch >= 0x23 && ch <= 0x5B, ch >= 0x5D && ch <= 0x7E:
		default:
			return false
		}
	}
	return true
}

// DisallowedScopes は requested のうち、このクライアントに許可されていない scope を返す。
// 空なら全て許可されている。
func (c *Client) DisallowedScopes(requested []string) []string {
	var out []string
	for _, s := range requested {
		allowed := false
		for _, a := range c.Scopes {
			if a == s {
				allowed = true
				break
			}
		}
		if !allowed {
			out = append(out, s)
		}
	}
	return out
}
