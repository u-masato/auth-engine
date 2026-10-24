package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage"
)

// Service はトークンエンドポイントのユースケース群。フィールドは Engine が配線する。
type Service struct {
	Clients client.Resolver
	Store   Store
	Clock   clock.Clock
	// Logger は監査イベント（発行、再利用検知）の出力先。nil なら slog.Default()。
	Logger *slog.Logger
}

// Request はトークン要求（RFC 6749 §4.1.3）。HTTP 層がフォームから組み立てる。
type Request struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	Credentials  Credentials
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
	switch client.GrantType(req.GrantType) {
	case "":
		return nil, protocolErr(CodeInvalidRequest, "grant_type is required")
	case client.GrantAuthorizationCode:
		if !c.Allows(client.GrantAuthorizationCode) {
			return nil, protocolErr(CodeUnauthorizedClient, "client is not allowed to use this grant type")
		}
		return s.exchangeCode(ctx, c, req)
	default:
		// refresh_token と client_credentials は M2 で対応する。
		return nil, protocolErr(CodeUnsupportedGrantType, "unsupported grant_type")
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

	access, plaintext, err := s.newAccessToken(c, code.FamilyID, code.GrantID, code.Subject, code.Scopes, now)
	if err != nil {
		return nil, err
	}
	family := &Family{
		ID:        code.FamilyID,
		GrantID:   code.GrantID,
		ClientID:  c.ID,
		Subject:   code.Subject,
		Scopes:    code.Scopes,
		Status:    FamilyActive,
		CreatedAt: now,
	}
	// Refresh Token の発行と ID Token は M2 で追加する。
	if err := s.Store.IssueTokens(ctx, family, access, nil); err != nil {
		if errors.Is(err, storage.ErrGrantRevoked) {
			return nil, protocolErr(CodeInvalidGrant, "authorization has been revoked")
		}
		return nil, fmt.Errorf("token: issue tokens: %w", err)
	}
	s.logger().InfoContext(ctx, "token issued",
		"event", "token.issued", "client_id", c.ID, "grant_id", code.GrantID, "family_id", family.ID, "grant_type", req.GrantType)

	return &Response{
		AccessToken: plaintext,
		TokenType:   "Bearer",
		ExpiresIn:   int64(access.ExpiresAt.Sub(now) / time.Second),
		Scope:       strings.Join(code.Scopes, " "),
	}, nil
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

// newAccessToken は Opaque な Access Token を生成する。戻り値の plaintext は応答にのみ使う。
func (s *Service) newAccessToken(c *client.Client, familyID, grantID, subject string, scopes []string, now time.Time) (*AccessToken, string, error) {
	plaintext, err := rand.Token(AccessTokenPrefix)
	if err != nil {
		return nil, "", err
	}
	return &AccessToken{
		Hash:      rand.Hash(plaintext),
		FamilyID:  familyID,
		GrantID:   grantID,
		ClientID:  c.ID,
		Subject:   subject,
		Scopes:    scopes,
		Status:    AccessActive,
		IssuedAt:  now,
		ExpiresAt: now.Add(c.EffectiveAccessTokenTTL()),
	}, plaintext, nil
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}
