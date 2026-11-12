package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage"
)

// token_type_hint の値（RFC 7009 §2.1、RFC 7662 §2.1）。
const (
	HintAccessToken  = "access_token"
	HintRefreshToken = "refresh_token"
)

// errNoSuchToken は、探している種別のトークンが存在しない（次の種別を探す）ことを表す。
// Inspect と RevokeToken / Revoke の種別ごとの探索が共通に使う。Store の ErrNotFound を
// そのまま使わないのは、Family の欠落のような下位の ErrNotFound を「この種別ではない」と
// 取り違えて、黙って成功や active: false にしないため。
var errNoSuchToken = errors.New("token: no such token")

// parentLookupErr は、Refresh Token を引いた後に親（Token Family / Grant）の操作が err を返した
// ときの扱いを決める。Inspect、Revoke、Refresh が共通に使う。
//
// Store.Purge は子のなくなった親を、子と同じ 1 回の操作で消す（ADR-0005 §7）。親が
// storage.ErrNotFound なら Refresh Token を引き直して、次のどちらかを区別する。
//
//   - Refresh Token も消えている: 引いた直後に Purge された。errNoSuchToken を返す。
//   - Refresh Token が残っている: 不整合。err をそのまま返す（HTTP 層で 500）。
func (s *Service) parentLookupErr(ctx context.Context, refreshHash string, err error) error {
	if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if _, again := s.Store.LookupRefreshToken(ctx, refreshHash); errors.Is(again, storage.ErrNotFound) {
		return errNoSuchToken
	}
	return err
}

// lookupOrder は token_type_hint から探索順を返す。hint が外れていても両方の種別を探す
// （RFC 7009 §2.1、RFC 7662 §2.1）。
func lookupOrder(hint string) []string {
	if hint == HintRefreshToken {
		return []string{HintRefreshToken, HintAccessToken}
	}
	return []string{HintAccessToken, HintRefreshToken}
}

// Introspection はトークンの状態（RFC 7662 §2.2）。Active が false なら他のフィールドは空。
type Introspection struct {
	Active bool
	// TokenType は Access Token なら "Bearer"。Refresh Token は RFC 6749 §5.1 の token_type を
	// 持たないので空。
	TokenType string
	Scopes    []string
	// Audience はトークンが向けられる resource（RFC 7662 §2.2 の aud）。Access Token はそのトークンの、
	// Refresh Token は Family の Audience。空なら認可サーバー自身向け。
	Audience  []string
	ClientID  string
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Kind は内部の種別（HintAccessToken / HintRefreshToken）。HTTP 応答には載せない。
	Kind string
}

// Inspect はトークン平文の状態を返す（Go API。ADR-0006 §5 の Inspect）。
//
// 不明・期限切れ・失効（Grant / Family の失効を含む）はすべて Active: false で、エラーにしない。
// hint は探索順序のヒントで、外れていても両方の種別を探す。
func (s *Service) Inspect(ctx context.Context, plaintext, hint string) (*Introspection, error) {
	if plaintext == "" {
		return &Introspection{}, nil
	}
	hash := rand.Hash(plaintext)
	now := s.Clock.Now()
	for _, kind := range lookupOrder(hint) {
		var (
			in  *Introspection
			err error
		)
		if kind == HintAccessToken {
			in, err = s.inspectAccess(ctx, hash, now)
		} else {
			in, err = s.inspectRefresh(ctx, hash, now)
		}
		if errors.Is(err, errNoSuchToken) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return in, nil
	}
	return &Introspection{}, nil
}

// inspectAccess は Access Token の状態を返す。見つからなければ errNoSuchToken。
func (s *Service) inspectAccess(ctx context.Context, hash string, now time.Time) (*Introspection, error) {
	at, g, err := s.Store.LookupAccessToken(ctx, hash)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, errNoSuchToken
	}
	if err != nil {
		return nil, fmt.Errorf("token: lookup access token: %w", err)
	}
	if !at.Valid(now) || !g.Active() {
		return &Introspection{Kind: HintAccessToken}, nil
	}
	return &Introspection{
		Active: true, TokenType: tokenTypeBearer, Scopes: at.Scopes, Audience: at.Audience, ClientID: at.ClientID, Subject: at.Subject,
		IssuedAt: at.IssuedAt, ExpiresAt: at.ExpiresAt, Kind: HintAccessToken,
	}, nil
}

// inspectRefresh は Refresh Token の状態を返す。見つからなければ errNoSuchToken。
//
// 有効な Refresh Token が参照する Family や Grant がないのは不整合なので、「この種別ではない」と
// 取り違えて active: false にせず、内部エラーにする（revokeRefresh と同じ扱い）。引いた直後に
// Purge で Refresh Token ごと消えた場合だけ errNoSuchToken になる（parentLookupErr）。
func (s *Service) inspectRefresh(ctx context.Context, hash string, now time.Time) (*Introspection, error) {
	rt, err := s.Store.LookupRefreshToken(ctx, hash)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, errNoSuchToken
	}
	if err != nil {
		return nil, fmt.Errorf("token: lookup refresh token: %w", err)
	}
	inactive := &Introspection{Kind: HintRefreshToken}
	if rt.Status != RefreshActive || rt.Expired(now) {
		return inactive, nil
	}
	family, err := s.Store.GetTokenFamily(ctx, rt.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("token: get token family: %w", s.parentLookupErr(ctx, hash, err))
	}
	if !family.Active() {
		return inactive, nil
	}
	g, err := s.Grants.GetGrant(ctx, family.GrantID)
	if err != nil {
		return nil, fmt.Errorf("token: get grant: %w", s.parentLookupErr(ctx, hash, err))
	}
	if !g.Active() {
		return inactive, nil
	}
	return &Introspection{
		Active: true, Scopes: family.Scopes, Audience: family.Audience, ClientID: family.ClientID, Subject: family.Subject,
		IssuedAt: rt.IssuedAt, ExpiresAt: rt.ExpiresAt, Kind: HintRefreshToken,
	}, nil
}

// IntrospectionRequest は Introspection エンドポイントの要求（RFC 7662 §2.1）。
type IntrospectionRequest struct {
	Token         string
	TokenTypeHint string
	Credentials   Credentials
}

// Introspect は Introspection エンドポイントの処理。
//
// 呼び出し元は confidential な Client（Web / Machine Profile）として認証しなければならない。
// Resource Server は Machine Profile の Client として登録する想定（ADR-0006 §1）。
// public な Client は自分を証明できないので invalid_client。認証に通れば、他 Client に
// 発行されたトークンも参照できる（Resource Server は任意の Client のトークンを検証する）。
func (s *Service) Introspect(ctx context.Context, req IntrospectionRequest) (*Introspection, error) {
	c, err := authenticateClient(ctx, s.Clients, req.Credentials)
	if err != nil {
		return nil, err
	}
	if c.IsPublic() {
		return nil, protocolErr(CodeInvalidClient, "client authentication failed")
	}
	if req.Token == "" {
		return nil, protocolErr(CodeInvalidRequest, "token is required")
	}
	return s.Inspect(ctx, req.Token, req.TokenTypeHint)
}
