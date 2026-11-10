package token

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage"
)

// exchangeCode は authorization_code グラント（RFC 6749 §4.1.3、RFC 7636 §4.6）を処理する。
//
// Code の消費は最初に行う。消費後に検証が失敗しても Code は戻さない（fail-closed）。
// 消費済み Code の再提示は、その Code から作られた Token Family を失効させる（RFC 6749 §4.1.2）。
func (s *Service) exchangeCode(ctx context.Context, c *client.Client, req Request) (*Response, error) {
	if req.Code == "" {
		return nil, protocolErr(CodeInvalidRequest, "code is required")
	}
	if req.CodeVerifier == "" {
		return nil, protocolErr(CodeInvalidRequest, "code_verifier is required")
	}
	now := s.Clock.Now()

	code, err := s.Store.ConsumeAuthorizationCode(ctx, rand.Hash(req.Code), now)
	switch {
	case errors.Is(err, storage.ErrCodeAlreadyUsed):
		s.revokeFamilyOnReuse(ctx, code, now)
		return nil, protocolErr(CodeInvalidGrant, "authorization code is invalid")
	case errors.Is(err, storage.ErrNotFound):
		return nil, protocolErr(CodeInvalidGrant, "authorization code is invalid")
	case err != nil:
		return nil, fmt.Errorf("token: consume code: %w", err)
	}

	if code.ClientID != c.ID {
		return nil, protocolErr(CodeInvalidGrant, "authorization code was not issued to this client")
	}
	// RFC 6749 §4.1.3: 認可要求に redirect_uri が含まれていたなら必須かつ同一。
	// 含まれていなくても、提示されたなら一致を要求する。
	if code.RedirectURIExplicit && req.RedirectURI == "" {
		return nil, protocolErr(CodeInvalidGrant, "redirect_uri is required")
	}
	if req.RedirectURI != "" && req.RedirectURI != code.RedirectURI {
		return nil, protocolErr(CodeInvalidGrant, "redirect_uri does not match")
	}
	if !authorization.VerifyS256(code.CodeChallenge, req.CodeVerifier) {
		return nil, protocolErr(CodeInvalidGrant, "code_verifier does not match")
	}
	// RFC 8707 §2.2: トークン要求の resource は認可要求で認可された resource の部分集合。
	// Family には認可された全部を持ち、今回の Access Token だけを絞る（ADR-0008 §3）。
	audience, perr := s.narrowAudience(req.Resource, code.Resource, code.Scopes)
	if perr != nil {
		return nil, perr
	}

	family := &Family{
		ID:              code.FamilyID,
		GrantID:         code.GrantID,
		ClientID:        c.ID,
		Subject:         code.Subject,
		Scopes:          code.Scopes,
		Audience:        code.Resource,
		AuthenticatedAt: code.AuthenticatedAt,
		AMR:             code.AMR,
		ACR:             code.ACR,
		Status:          FamilyActive,
		CreatedAt:       now,
	}
	access, accessPlain, err := s.issueAccessToken(ctx, c, family, code.Scopes, audience, now)
	if err != nil {
		return nil, err
	}
	var (
		refresh      *RefreshToken
		refreshPlain string
	)
	if c.IssuesRefreshToken() {
		family.ExpiresAt = now.Add(s.refreshTTL())
		refresh, refreshPlain, err = s.newRefreshToken(family, now)
		if err != nil {
			return nil, err
		}
	}
	if err := s.Store.IssueTokens(ctx, family, access, refresh); err != nil {
		if errors.Is(err, storage.ErrGrantRevoked) {
			return nil, protocolErr(CodeInvalidGrant, "authorization has been revoked")
		}
		return nil, fmt.Errorf("token: issue tokens: %w", err)
	}
	s.logger().InfoContext(ctx, "token issued",
		"event", "token.issued", "client_id", c.ID, "grant_id", code.GrantID, "family_id", family.ID, "grant_type", req.GrantType)

	res := &Response{
		AccessToken:  accessPlain,
		TokenType:    tokenTypeBearer,
		ExpiresIn:    expiresIn(access, now),
		Scope:        strings.Join(code.Scopes, " "),
		RefreshToken: refreshPlain,
	}
	// OIDC Core §3.1.3.3: openid が付与されていれば ID Token を返す。
	if s.IDTokens != nil && c.IssuesIDToken() && slices.Contains(code.Scopes, "openid") {
		idToken, err := s.IDTokens.IssueIDToken(ctx, c, IDTokenInput{
			Subject: code.Subject, AuthenticatedAt: code.AuthenticatedAt, Nonce: code.Nonce,
			AMR: code.AMR, ACR: code.ACR, AccessToken: accessPlain, Scopes: code.Scopes,
		})
		if err != nil {
			return nil, fmt.Errorf("token: issue id token: %w", err)
		}
		res.IDToken = idToken
	}
	return res, nil
}

// revokeFamilyOnReuse は再利用された Code の Family を失効させる。
// 最初の交換が Family 作成前に失敗していれば Family は存在しないので、ErrNotFound は無視する。
//
// 同じ Code を持つ 2 つの要求がほぼ同時に届き、勝者の IssueTokens より先に敗者の失効が
// 走った場合も Family は存在せず、勝者のトークンは有効なまま残る。この窓は 1 要求内の
// 数マイクロ秒で、かつ PKCE 必須の下では code_verifier を持たない攻撃者は交換に成功できないため、
// Family 作成を Resume 時に前倒しする複雑さに見合わないと判断し、許容する。
func (s *Service) revokeFamilyOnReuse(ctx context.Context, code *authorization.AuthorizationCode, now time.Time) {
	if code == nil {
		return
	}
	err := s.Store.RevokeTokenFamily(ctx, code.FamilyID, now)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.logger().ErrorContext(ctx, "failed to revoke token family after code reuse",
			"event", "code.reuse", "client_id", code.ClientID, "family_id", code.FamilyID, "error", err)
		return
	}
	s.logger().WarnContext(ctx, "authorization code reuse detected",
		"event", "code.reuse", "client_id", code.ClientID, "grant_id", code.GrantID, "family_id", code.FamilyID)
}
