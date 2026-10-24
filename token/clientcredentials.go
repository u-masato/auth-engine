package token

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/grant"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage"
)

// clientCredentials は client_credentials グラント（RFC 6749 §4.4）を処理する。
//
// Machine Profile 専用（Allows の判定は Exchange で済んでいる）。ユーザーが介在しないので
// Grant は subject = client_id で記録し、Refresh Token と ID Token は発行しない（RFC 6749 §4.4.3、
// ADR-0004 §1）。scope は未指定なら Client に許可された全 scope、指定されたなら
// その範囲内でなければ invalid_scope。
func (s *Service) clientCredentials(ctx context.Context, c *client.Client, req Request) (*Response, error) {
	if s.Grants == nil {
		return nil, errors.New("token: Grants store is not configured")
	}
	scopes, perr := parseScope(req.Scope)
	if perr != nil {
		return nil, perr
	}
	if scopes == nil {
		scopes = c.Scopes
	} else if bad := c.DisallowedScopes(scopes); len(bad) > 0 {
		return nil, protocolErr(CodeInvalidScope, "scope not allowed for this client: "+strings.Join(bad, " "))
	}
	now := s.Clock.Now()

	grantID, err := rand.Token("")
	if err != nil {
		return nil, err
	}
	// 同じ Client の再要求は既存 Grant を更新する（scope は和集合）。Claims は持たない。
	g, err := s.Grants.UpsertGrant(ctx, &grant.Grant{
		ID: grantID, ClientID: c.ID, Subject: c.ID, Scopes: scopes,
		Status: grant.StatusActive, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("token: upsert grant: %w", err)
	}
	familyID, err := rand.Token("")
	if err != nil {
		return nil, err
	}
	family := &Family{
		ID: familyID, GrantID: g.ID, ClientID: c.ID, Subject: c.ID, Scopes: scopes,
		Status: FamilyActive, CreatedAt: now,
	}
	access, accessPlain, err := s.newAccessToken(c, family, scopes, now)
	if err != nil {
		return nil, err
	}
	if err := s.Store.IssueTokens(ctx, family, access, nil); err != nil {
		if errors.Is(err, storage.ErrGrantRevoked) {
			// UpsertGrant で active に戻した直後なので通常は起きない（直後に RevokeGrant が走った場合のみ）。
			return nil, protocolErr(CodeInvalidGrant, "authorization has been revoked")
		}
		return nil, fmt.Errorf("token: issue tokens: %w", err)
	}
	s.logger().InfoContext(ctx, "token issued",
		"event", "token.issued", "client_id", c.ID, "grant_id", g.ID, "family_id", family.ID, "grant_type", req.GrantType)

	return &Response{
		AccessToken: accessPlain,
		TokenType:   "Bearer",
		ExpiresIn:   int64(access.ExpiresAt.Sub(now).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}
