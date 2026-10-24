package token

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage"
)

// refresh は refresh_token グラント（RFC 6749 §6）を Rotation 付きで処理する（RFC 9700 §4.14）。
//
// 提示された Refresh Token は 1 回の使用で rotated になり、後継の Refresh Token と新しい
// Access Token を返す。rotated なトークンの再提示は漏えいの兆候とみなし、Family 全体を
// 失効させる。Grant は失効させない（同じユーザーの他のセッションを巻き込まない、ADR-0006 §4）。
//
// scope パラメータで scope を縮小できるが、元の付与を超える拡大は invalid_scope。
// 縮小は今回の Access Token にだけ効き、Family（と後継の Refresh Token）の scope は変わらない。
func (s *Service) refresh(ctx context.Context, c *client.Client, req Request) (*Response, error) {
	if req.RefreshToken == "" {
		return nil, protocolErr(CodeInvalidRequest, "refresh_token is required")
	}
	requested, perr := parseScope(req.Scope)
	if perr != nil {
		return nil, perr
	}
	now := s.Clock.Now()
	oldHash := rand.Hash(req.RefreshToken)

	old, err := s.Store.LookupRefreshToken(ctx, oldHash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, protocolErr(CodeInvalidGrant, "refresh token is invalid")
		}
		return nil, fmt.Errorf("token: lookup refresh token: %w", err)
	}
	family, err := s.Store.GetTokenFamily(ctx, old.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("token: get token family: %w", err)
	}
	// RFC 6749 §6: Refresh Token は発行先の Client に束縛される。他の Client からの提示は
	// 盗用の可能性があるので、状態は変えずに拒否して記録する。
	if family.ClientID != c.ID {
		s.logger().WarnContext(ctx, "refresh token presented by another client",
			"event", "refresh.client_mismatch", "client_id", c.ID, "family_id", family.ID)
		return nil, protocolErr(CodeInvalidGrant, "refresh token is invalid")
	}
	scopes := family.Scopes
	if requested != nil {
		for _, sc := range requested {
			if !slices.Contains(family.Scopes, sc) {
				return nil, protocolErr(CodeInvalidScope, "requested scope exceeds the original grant")
			}
		}
		scopes = requested
	}

	next, nextPlain, err := s.newRefreshToken(family, now)
	if err != nil {
		return nil, err
	}
	access, accessPlain, err := s.newAccessToken(c, family, scopes, now)
	if err != nil {
		return nil, err
	}
	err = s.Store.RotateRefreshToken(ctx, oldHash, next, access, now)
	switch {
	case errors.Is(err, storage.ErrTokenReused):
		s.revokeFamilyOnRefreshReuse(ctx, c, family.ID, now)
		return nil, protocolErr(CodeInvalidGrant, "refresh token is invalid")
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrFamilyRevoked), errors.Is(err, storage.ErrGrantRevoked):
		return nil, protocolErr(CodeInvalidGrant, "refresh token is invalid")
	case err != nil:
		return nil, fmt.Errorf("token: rotate refresh token: %w", err)
	}
	s.logger().InfoContext(ctx, "token issued",
		"event", "token.issued", "client_id", c.ID, "grant_id", family.GrantID, "family_id", family.ID, "grant_type", req.GrantType)

	res := &Response{
		AccessToken:  accessPlain,
		TokenType:    "Bearer",
		ExpiresIn:    int64(access.ExpiresAt.Sub(now).Seconds()),
		Scope:        strings.Join(scopes, " "),
		RefreshToken: nextPlain,
	}
	// OIDC Core §12.2: openid が含まれていれば新しい ID Token を返す。auth_time / amr / acr は
	// 元の認証のもの。nonce は元の認可要求に対するものなので載せない。
	if s.IDTokens != nil && c.IssuesIDToken() && slices.Contains(scopes, "openid") {
		idToken, err := s.IDTokens.IssueIDToken(ctx, c, IDTokenInput{
			Subject: family.Subject, AuthenticatedAt: family.AuthenticatedAt,
			AMR: family.AMR, ACR: family.ACR, AccessToken: accessPlain, Scopes: scopes,
		})
		if err != nil {
			return nil, fmt.Errorf("token: issue id token: %w", err)
		}
		res.IDToken = idToken
	}
	return res, nil
}

// revokeFamilyOnRefreshReuse は Rotation 済み Refresh Token の再提示を受けて Family を失効させる。
func (s *Service) revokeFamilyOnRefreshReuse(ctx context.Context, c *client.Client, familyID string, now time.Time) {
	err := s.Store.RevokeTokenFamily(ctx, familyID, now)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.logger().ErrorContext(ctx, "failed to revoke token family after refresh token reuse",
			"event", "refresh.reuse", "client_id", c.ID, "family_id", familyID, "error", err)
		return
	}
	s.logger().WarnContext(ctx, "refresh token reuse detected",
		"event", "refresh.reuse", "client_id", c.ID, "family_id", familyID)
}
