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
// その範囲内でなければ invalid_scope。resource（RFC 8707 §2.2）は設定済みかつ Client の許可範囲内
// でなければ invalid_target。未指定なら Audience は空（認可サーバー自身向け。ADR-0008 §2）。
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
	audience, perr := s.clientCredentialsAudience(c, req.Resource, scopes)
	if perr != nil {
		return nil, perr
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
		ID: familyID, GrantID: g.ID, ClientID: c.ID, Subject: c.ID, Scopes: scopes, Audience: audience,
		Status: FamilyActive, CreatedAt: now,
	}
	access, accessPlain, err := s.issueAccessToken(ctx, c, family, scopes, audience, now)
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

// clientCredentialsAudience は client_credentials の resource パラメータを検証する。
// ユーザーの同意を経ない grant なので、認可済みの範囲は「設定にあり、Client に許された resource」
// （ADR-0008 §2）。設定になければ invalid_target、Client の許可範囲外も invalid_target。
func (s *Service) clientCredentialsAudience(c *client.Client, requested, scopes []string) ([]string, *Error) {
	uris, err := s.Resources.Resolve(requested)
	if err != nil {
		return nil, &Error{Code: CodeInvalidTarget, Description: resourceErrorDescription(err)}
	}
	for _, uri := range uris {
		if !c.AllowsResource(uri) {
			return nil, protocolErr(CodeInvalidTarget, "resource not allowed for this client: "+uri)
		}
	}
	if dis := s.Resources.DisallowedScopes(uris, scopes); len(dis) > 0 {
		return nil, protocolErr(CodeInvalidScope, "scope not allowed for the requested resource: "+strings.Join(dis, " "))
	}
	return uris, nil
}
