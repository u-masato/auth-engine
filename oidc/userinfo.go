package oidc

import (
	"context"
	"errors"
	"slices"

	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage"
	"github.com/muno/auth-engine/token"
)

var (
	// ErrInvalidToken は Access Token が不明・期限切れ・失効（Grant の失効を含む）。
	// HTTP 層は 401 と WWW-Authenticate: Bearer error="invalid_token" にする（RFC 6750 §3.1）。
	ErrInvalidToken = errors.New("oidc: invalid access token")
	// ErrInsufficientScope は Access Token に openid scope がない。403 insufficient_scope。
	ErrInsufficientScope = errors.New("oidc: access token lacks the openid scope")
)

// UserInfoService は UserInfo エンドポイント（OIDC Core §5.3）のユースケース。
type UserInfoService struct {
	Tokens token.Store
	Clock  clock.Clock
}

// UserInfo は Access Token の平文を受け取り、sub と scope で絞った Claims を返す。
//
// Claims の出所は Grant に保存されたスナップショット（ADR-0006 §3）。Access Token の
// scope（Grant の scope ではなく、そのトークンに付いた scope）で絞る。
func (s *UserInfoService) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if accessToken == "" {
		return nil, ErrInvalidToken
	}
	at, g, err := s.Tokens.LookupAccessToken(ctx, rand.Hash(accessToken))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if !at.Valid(s.Clock.Now()) || !g.Active() {
		return nil, ErrInvalidToken
	}
	if !slices.Contains(at.Scopes, "openid") {
		return nil, ErrInsufficientScope
	}
	claims := FilterClaims(g.Claims, at.Scopes)
	claims["sub"] = at.Subject // OIDC Core §5.3.2: sub は必須で、Access Token の subject と一致する
	return claims, nil
}
