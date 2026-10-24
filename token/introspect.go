package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage"
)

// token_type_hint の値（RFC 7009 §2.1、RFC 7662 §2.1）。
const (
	HintAccessToken  = "access_token"
	HintRefreshToken = "refresh_token"
)

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
	order := []string{HintAccessToken, HintRefreshToken}
	if hint == HintRefreshToken {
		order = []string{HintRefreshToken, HintAccessToken}
	}
	for _, kind := range order {
		var (
			in  *Introspection
			err error
		)
		if kind == HintAccessToken {
			in, err = s.inspectAccess(ctx, hash, now)
		} else {
			in, err = s.inspectRefresh(ctx, hash, now)
		}
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return in, nil
	}
	return &Introspection{}, nil
}

func (s *Service) inspectAccess(ctx context.Context, hash string, now time.Time) (*Introspection, error) {
	at, g, err := s.Store.LookupAccessToken(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !at.Valid(now) || !g.Active() {
		return &Introspection{Kind: HintAccessToken}, nil
	}
	return &Introspection{
		Active: true, TokenType: "Bearer", Scopes: at.Scopes, Audience: at.Audience, ClientID: at.ClientID, Subject: at.Subject,
		IssuedAt: at.IssuedAt, ExpiresAt: at.ExpiresAt, Kind: HintAccessToken,
	}, nil
}

func (s *Service) inspectRefresh(ctx context.Context, hash string, now time.Time) (*Introspection, error) {
	rt, err := s.Store.LookupRefreshToken(ctx, hash)
	if err != nil {
		return nil, err
	}
	family, err := s.Store.GetTokenFamily(ctx, rt.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("token: get token family: %w", err)
	}
	g, err := s.Grants.GetGrant(ctx, family.GrantID)
	if err != nil {
		return nil, fmt.Errorf("token: get grant: %w", err)
	}
	if rt.Status != RefreshActive || !now.Before(rt.ExpiresAt) || !family.Active() || !g.Active() {
		return &Introspection{Kind: HintRefreshToken}, nil
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
