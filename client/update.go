package client

import (
	"slices"
	"time"
)

// UpdateParams は Update の入力。登録後に変更できる項目（ADR-0004 §2 の開放項目）だけを持つ。
//
// ID・Profile・シークレット・CreatedAt・ClientURI は含まない。Profile は登録後に変更できず
// （ADR-0004 §4）、用途が変わる場合は Client を作り直す。シークレットのローテーションは提供しない。
//
// 部分更新ではなく全項目の置き換えである。一部だけ変えるときは Client.UpdateParams で現在値を得て、
// 変えたい項目だけを書き換えてから渡す。
type UpdateParams struct {
	Name                   string
	LogoURI                string
	PolicyURI              string
	RedirectURIs           []string
	Scopes                 []string
	Resources              []string      // 空なら制限なし
	AccessTokenTTL         time.Duration // 0 なら既定
	IDTokenAlg             string        // ID Token を発行する Profile で空なら RS256
	AllowInsecureLocalhost bool
}

// UpdateParams は現在の登録内容を UpdateParams の形で返す。
func (c *Client) UpdateParams() UpdateParams {
	return UpdateParams{
		Name:                   c.Name,
		LogoURI:                c.LogoURI,
		PolicyURI:              c.PolicyURI,
		RedirectURIs:           slices.Clone(c.RedirectURIs),
		Scopes:                 slices.Clone(c.Scopes),
		Resources:              slices.Clone(c.Resources),
		AccessTokenTTL:         c.AccessTokenTTL,
		IDTokenAlg:             c.IDTokenAlg,
		AllowInsecureLocalhost: c.AllowInsecureLocalhost,
	}
}

// Update は開放項目を p で置き換えた新しい Client を返す。c 自体は変更しない。
//
// 結果はコンストラクタと同じ既定値の補完と Validate を通す。Profile の規則に反する値
// （Machine に redirect URI を与える、Web に http の redirect URI を与えるなど）は ErrInvalid。
// 保存は Store.UpdateClient で行う。
func (c *Client) Update(p UpdateParams) (*Client, error) {
	next := &Client{
		ID:                     c.ID,
		Profile:                c.Profile,
		Name:                   p.Name,
		LogoURI:                p.LogoURI,
		PolicyURI:              p.PolicyURI,
		ClientURI:              c.ClientURI,
		RedirectURIs:           slices.Clone(p.RedirectURIs),
		Scopes:                 slices.Clone(p.Scopes),
		Resources:              slices.Clone(p.Resources),
		SecretHash:             c.SecretHash,
		AccessTokenTTL:         p.AccessTokenTTL,
		IDTokenAlg:             p.IDTokenAlg,
		AllowInsecureLocalhost: p.AllowInsecureLocalhost,
		CreatedAt:              c.CreatedAt,
	}
	if err := next.applyDefaults(); err != nil {
		return nil, err
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	return next, nil
}
