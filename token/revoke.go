package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage"
)

// RevokeToken はトークン平文を失効させる（Go API。ADR-0006 §5 の RevokeToken）。
//
//   - Access Token: そのトークンだけを失効させる。同じ Family の Refresh Token は残る。
//   - Refresh Token: Family 全体（後継の Refresh Token と全 Access Token）を失効させる
//     （RFC 7009 §2.1 の "SHOULD also invalidate all access tokens based on the same grant"）。
//
// 戻り値はトークンが見つかったか。不明・失効済みでもエラーにしない。
func (s *Service) RevokeToken(ctx context.Context, plaintext, hint string) (bool, error) {
	return s.revoke(ctx, plaintext, hint, "")
}

// RevocationRequest は Revocation エンドポイントの要求（RFC 7009 §2.1）。
type RevocationRequest struct {
	Token         string
	TokenTypeHint string
	Credentials   Credentials
}

// Revoke は Revocation エンドポイントの処理。
//
// Client を認証し、そのトークンが提示した Client に発行されたものであれば失効させる。
// 他 Client のトークン・不明なトークン・失効済みのトークンに対しては何もせず成功を返す
// （RFC 7009 §2.2: invalid token は成功。他 Client のトークンについて存在を教えない）。
func (s *Service) Revoke(ctx context.Context, req RevocationRequest) error {
	c, err := authenticateClient(ctx, s.Clients, req.Credentials)
	if err != nil {
		return err
	}
	if req.Token == "" {
		return protocolErr(CodeInvalidRequest, "token is required")
	}
	found, err := s.revoke(ctx, req.Token, req.TokenTypeHint, c.ID)
	if err != nil {
		return err
	}
	if found {
		s.logger().InfoContext(ctx, "token revoked", "event", "token.revoked", "client_id", c.ID)
	}
	return nil
}

// revoke は owner が空なら所有者を問わず、空でなければ owner に発行されたトークンだけを失効させる。
func (s *Service) revoke(ctx context.Context, plaintext, hint, owner string) (bool, error) {
	if plaintext == "" {
		return false, nil
	}
	hash := rand.Hash(plaintext)
	now := s.Clock.Now()
	for _, kind := range lookupOrder(hint) {
		var (
			found bool
			err   error
		)
		if kind == HintAccessToken {
			found, err = s.revokeAccess(ctx, hash, owner, now)
		} else {
			found, err = s.revokeRefresh(ctx, hash, owner, now)
		}
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		return found, err
	}
	return false, nil
}

// revokeAccess は Access Token を失効させる。見つからなければ storage.ErrNotFound。
func (s *Service) revokeAccess(ctx context.Context, hash, owner string, now time.Time) (bool, error) {
	at, _, err := s.Store.LookupAccessToken(ctx, hash)
	if errors.Is(err, storage.ErrNotFound) {
		return false, err
	}
	if err != nil {
		return false, fmt.Errorf("token: lookup access token: %w", err)
	}
	if owner != "" && at.ClientID != owner {
		return false, nil
	}
	if err := s.Store.RevokeAccessToken(ctx, hash, now); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return false, fmt.Errorf("token: revoke access token: %w", err)
	}
	return true, nil
}

// revokeRefresh は Refresh Token の Family ごと失効させる（RFC 7009 §2.1）。見つからなければ storage.ErrNotFound。
func (s *Service) revokeRefresh(ctx context.Context, hash, owner string, now time.Time) (bool, error) {
	rt, err := s.Store.LookupRefreshToken(ctx, hash)
	if errors.Is(err, storage.ErrNotFound) {
		return false, err
	}
	if err != nil {
		return false, fmt.Errorf("token: lookup refresh token: %w", err)
	}
	if owner != "" {
		family, err := s.Store.GetTokenFamily(ctx, rt.FamilyID)
		if err != nil {
			return false, fmt.Errorf("token: get token family: %w", err)
		}
		if family.ClientID != owner {
			return false, nil
		}
	}
	if err := s.Store.RevokeTokenFamily(ctx, rt.FamilyID, now); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return false, fmt.Errorf("token: revoke token family: %w", err)
	}
	return true, nil
}
