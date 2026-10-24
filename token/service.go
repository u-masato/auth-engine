package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/grant"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage"
)

// Service はトークンエンドポイントのユースケース群。フィールドは Engine が配線する。
type Service struct {
	Clients client.Resolver
	Store   Store
	// Grants は client_credentials が Grant を記録するのに使う。
	Grants grant.Store
	Clock  clock.Clock
	// Logger は監査イベント（発行、再利用検知）の出力先。nil なら slog.Default()。
	Logger *slog.Logger
	// IDTokens は openid scope が付与されたときに ID Token を発行する。nil なら発行しない。
	IDTokens IDTokenIssuer

	// RefreshTokenTTL は Refresh Token の絶対期限、RefreshTokenIdleTTL はスライド期限。
	// 0 なら既定値（DefaultRefreshTokenTTL / DefaultRefreshTokenIdleTTL）。
	RefreshTokenTTL     time.Duration
	RefreshTokenIdleTTL time.Duration
}

// Request はトークン要求（RFC 6749 §4.1.3、§4.4.2、§6）。HTTP 層がフォームから組み立てる。
type Request struct {
	GrantType   string
	Credentials Credentials

	// authorization_code
	Code         string
	RedirectURI  string
	CodeVerifier string

	// refresh_token
	RefreshToken string

	// Scope は refresh_token / client_credentials の scope パラメータ（空白区切り、未指定なら空）。
	Scope string
}

// Response はトークン応答（RFC 6749 §5.1、RFC 6750）。
type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Exchange はトークン要求を処理する。失敗は *Error（プロトコルエラー）か、内部障害の error。
func (s *Service) Exchange(ctx context.Context, req Request) (*Response, error) {
	c, err := authenticateClient(ctx, s.Clients, req.Credentials)
	if err != nil {
		return nil, err
	}
	gt := client.GrantType(req.GrantType)
	if gt == "" {
		return nil, protocolErr(CodeInvalidRequest, "grant_type is required")
	}
	switch gt {
	case client.GrantAuthorizationCode, client.GrantRefreshToken, client.GrantClientCredentials:
	default:
		return nil, protocolErr(CodeUnsupportedGrantType, "unsupported grant_type")
	}
	if !c.Allows(gt) {
		return nil, protocolErr(CodeUnauthorizedClient, "client is not allowed to use this grant type")
	}
	switch gt {
	case client.GrantAuthorizationCode:
		return s.exchangeCode(ctx, c, req)
	case client.GrantRefreshToken:
		return s.refresh(ctx, c, req)
	default:
		return s.clientCredentials(ctx, c, req)
	}
}

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

	family := &Family{
		ID:              code.FamilyID,
		GrantID:         code.GrantID,
		ClientID:        c.ID,
		Subject:         code.Subject,
		Scopes:          code.Scopes,
		AuthenticatedAt: code.AuthenticatedAt,
		AMR:             code.AMR,
		ACR:             code.ACR,
		Status:          FamilyActive,
		CreatedAt:       now,
	}
	access, accessPlain, err := s.newAccessToken(c, family, code.Scopes, now)
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
		TokenType:    "Bearer",
		ExpiresIn:    int64(access.ExpiresAt.Sub(now) / time.Second),
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

// newAccessToken は family に属する Opaque な Access Token を生成する。戻り値の平文は応答にのみ使う。
// scopes は family.Scopes の部分集合（Refresh 時の縮小を反映する）。
func (s *Service) newAccessToken(c *client.Client, family *Family, scopes []string, now time.Time) (*AccessToken, string, error) {
	plaintext, err := rand.Token(AccessTokenPrefix)
	if err != nil {
		return nil, "", err
	}
	return &AccessToken{
		Hash:      rand.Hash(plaintext),
		FamilyID:  family.ID,
		GrantID:   family.GrantID,
		ClientID:  c.ID,
		Subject:   family.Subject,
		Scopes:    scopes,
		Status:    AccessActive,
		IssuedAt:  now,
		ExpiresAt: now.Add(c.EffectiveAccessTokenTTL()),
	}, plaintext, nil
}

// newRefreshToken は family に属する Refresh Token を生成する。期限はスライド期限と
// Family の絶対期限の早い方。
func (s *Service) newRefreshToken(family *Family, now time.Time) (*RefreshToken, string, error) {
	plaintext, err := rand.Token(RefreshTokenPrefix)
	if err != nil {
		return nil, "", err
	}
	expires := now.Add(s.refreshIdleTTL())
	if expires.After(family.ExpiresAt) {
		expires = family.ExpiresAt
	}
	return &RefreshToken{
		Hash:      rand.Hash(plaintext),
		FamilyID:  family.ID,
		Status:    RefreshActive,
		IssuedAt:  now,
		ExpiresAt: expires,
	}, plaintext, nil
}

func (s *Service) refreshTTL() time.Duration {
	if s.RefreshTokenTTL == 0 {
		return DefaultRefreshTokenTTL
	}
	return s.RefreshTokenTTL
}

func (s *Service) refreshIdleTTL() time.Duration {
	if s.RefreshTokenIdleTTL == 0 {
		return DefaultRefreshTokenIdleTTL
	}
	return s.RefreshTokenIdleTTL
}

// parseScope は scope パラメータ（RFC 6749 §3.3）を分解し、空の要素と不正な scope-token を拒否する。
// 未指定（空文字）なら nil を返す。
func parseScope(raw string) ([]string, *Error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	for _, s := range strings.Split(raw, " ") {
		if !client.ValidScopeToken(s) {
			return nil, protocolErr(CodeInvalidScope, "malformed scope")
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}
