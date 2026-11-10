package client

import (
	"fmt"
	"slices"

	"github.com/u-masato/auth-engine/internal/rand"
)

// RotateSecret は新しいシークレットを生成し、そのハッシュに差し替えた Client と平文を返す。
// c 自体は変更しない。平文はこの戻り値でしか得られない。public クライアントでは ErrInvalid。
//
// 保存は Store.RotateClientSecret で行う。保存した時点で旧シークレットは使えなくなる
// （新旧を併用する期間はない。ADR-0004 §2）。発行済みのトークンと Grant には触れないので、
// 漏えいへの対応では、必要に応じて Grant も失効させる（grant.Service.Revoke）。
//
// シークレットは常に生成する（256 bit 乱数）。WebParams.Secret のような値の指定は受け付けない。
func (c *Client) RotateSecret() (*Client, Secret, error) {
	if c.IsPublic() {
		return nil, "", fmt.Errorf("%w: public client has no secret to rotate", ErrInvalid)
	}
	s, err := rand.Token("")
	if err != nil {
		return nil, "", err
	}
	next := *c
	next.RedirectURIs = slices.Clone(c.RedirectURIs)
	next.Scopes = slices.Clone(c.Scopes)
	next.Resources = slices.Clone(c.Resources)
	next.SecretHash = rand.Hash(s)
	if err := next.Validate(); err != nil {
		return nil, "", err
	}
	return &next, Secret(s), nil
}
