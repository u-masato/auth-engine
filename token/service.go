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
	"github.com/muno/auth-engine/resource"
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
	// Resources は resource パラメータ（RFC 8707 §2.2）で指定できる Resource Server の集合。
	// authorization.Service と同じ Set を Engine が配線する。nil なら空集合。
	Resources *resource.Set
	// Issuer は Access Token を発行する（ADR-0007 §4）。Engine は形式ごとの ByFormat（Opaque と JWT）を
	// 配線する。nil なら OpaqueIssuer だけで、JWT を要求する resource は内部エラーになる。
	Issuer Issuer

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

	// Resource は resource パラメータ（RFC 8707 §2.2。複数可）。発行する Access Token の Audience を
	// 認可済みの範囲内で絞る。未指定なら認可済みの全部。
	Resource []string
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

// issueAccessToken は family に属する Access Token を Issuer で発行する。戻り値の平文は応答にのみ使う。
// scopes は family.Scopes の、audience は family.Audience の部分集合（要求時の縮小を反映する）。
//
// 形式は audience の resource 設定で決まる（ADR-0008 §3）。audience が空なら Opaque。複数の resource は
// narrowAudience（Set.Resolve）で形式が揃っていることを確認済みなので、先頭の設定を見ればよい。
func (s *Service) issueAccessToken(ctx context.Context, c *client.Client, family *Family, scopes, audience []string, now time.Time) (*AccessToken, string, error) {
	in := IssueInput{Client: c, Family: family, Scopes: scopes, Audience: audience, Format: resource.FormatOpaque, Now: now}
	if len(audience) > 0 {
		r, ok := s.Resources.Lookup(audience[0])
		if !ok {
			return nil, "", fmt.Errorf("token: resource %q is not configured", audience[0])
		}
		in.Format, in.Alg = r.EffectiveFormat(), r.EffectiveAlg()
	}
	issuer := s.Issuer
	if issuer == nil {
		issuer = ByFormat{resource.FormatOpaque: OpaqueIssuer{}}
	}
	plaintext, rec, err := issuer.Issue(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("token: issue access token: %w", err)
	}
	return rec, plaintext, nil
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

// narrowAudience はトークン要求の resource パラメータ（RFC 8707 §2.2）を、認可済みの Audience
// （Code の Resource、または Family の Audience）の範囲内に絞って返す。
//
//   - 未指定なら認可済みの全部。ただし設定から外された resource が残っていれば invalid_target
//     （設定変更後に古い Code / Family で発行し続けないための fail-closed）。
//   - 指定があれば、各値が設定にあり（Set.Resolve）、認可済みの範囲内であること。範囲外は invalid_target。
//   - 絞った Audience に対して scopes が resource ごとの上限に収まること（invalid_scope、ADR-0008 §1）。
func (s *Service) narrowAudience(requested, authorized, scopes []string) ([]string, *Error) {
	if _, err := s.Resources.Resolve(authorized); err != nil {
		return nil, &Error{Code: CodeInvalidTarget, Description: resourceErrorDescription(err)}
	}
	audience := authorized
	if len(requested) > 0 {
		uris, err := s.Resources.Resolve(requested)
		if err != nil {
			return nil, &Error{Code: CodeInvalidTarget, Description: resourceErrorDescription(err)}
		}
		for _, uri := range uris {
			if !slices.Contains(authorized, uri) {
				return nil, protocolErr(CodeInvalidTarget, "resource was not authorized: "+uri)
			}
		}
		audience = uris
	}
	if dis := s.Resources.DisallowedScopes(audience, scopes); len(dis) > 0 {
		return nil, protocolErr(CodeInvalidScope, "scope not allowed for the requested resource: "+strings.Join(dis, " "))
	}
	return audience, nil
}

// resourceErrorDescription は resource.Set.Resolve のエラーを error_description 向けの文に写す。
func resourceErrorDescription(err error) string {
	return strings.TrimPrefix(err.Error(), "resource: ")
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
