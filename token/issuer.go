package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/resource"
)

// IssueInput は Access Token の発行に必要な情報。Service が Code 交換・Refresh・client_credentials
// のそれぞれで組み立てる。
type IssueInput struct {
	Client *client.Client
	// Family はトークンが属する Token Family。GrantID・Subject と、認可コード由来の認証情報
	// （AuthenticatedAt / AMR / ACR。client_credentials ではゼロ値）をここから取る。
	Family *Family
	// Scopes は Family.Scopes の、Audience は Family.Audience の部分集合（要求時の縮小を反映済み）。
	Scopes   []string
	Audience []string
	// Format は発行する形式。Audience の resource 設定で決まり、Audience が空なら FormatOpaque（ADR-0008 §3）。
	Format resource.Format
	// Alg は FormatJWT のときの署名アルゴリズム（resource.Resource.EffectiveAlg）。
	Alg string
	Now time.Time
}

// Issuer は Access Token を発行する拡張点（ADR-0007 §4、ADR-0008 §3）。
//
// 戻り値の平文は応答にのみ使い、rec は Store に保存する記録。形式に依らず rec.Hash は
// 平文全体の SHA-256 で、Introspection と Revocation は同じ経路で動く。
type Issuer interface {
	Issue(ctx context.Context, in IssueInput) (plaintext string, rec *AccessToken, err error)
}

// ErrUnsupportedFormat は、要求された形式を発行できる Issuer が配線されていない（設定不備。500）。
var ErrUnsupportedFormat = errors.New("token: no issuer for the requested access token format")

// OpaqueIssuer はランダム文字列の Access Token を発行する既定の Issuer（ADR-0006 §1）。
type OpaqueIssuer struct{}

// Issue は 256 bit 乱数の平文（接頭辞 at_）と、その SHA-256 を Hash に持つ記録を返す。
func (OpaqueIssuer) Issue(_ context.Context, in IssueInput) (string, *AccessToken, error) {
	plaintext, err := rand.Token(AccessTokenPrefix)
	if err != nil {
		return "", nil, err
	}
	return plaintext, newAccessRecord(in, plaintext), nil
}

// ByFormat は形式ごとの Issuer に振り分ける。Engine が Opaque と JWT の 2 実装を配線する。
type ByFormat map[resource.Format]Issuer

// Issue は in.Format（空なら FormatOpaque）の Issuer に委譲する。なければ ErrUnsupportedFormat。
func (b ByFormat) Issue(ctx context.Context, in IssueInput) (string, *AccessToken, error) {
	format := in.Format
	if format == "" {
		format = resource.FormatOpaque
	}
	issuer, ok := b[format]
	if !ok || issuer == nil {
		return "", nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
	return issuer.Issue(ctx, in)
}

// newAccessRecord は形式に依らない Access Token の記録を組み立てる。
func newAccessRecord(in IssueInput, plaintext string) *AccessToken {
	return &AccessToken{
		Hash:      rand.Hash(plaintext),
		FamilyID:  in.Family.ID,
		GrantID:   in.Family.GrantID,
		ClientID:  in.Client.ID,
		Subject:   in.Family.Subject,
		Scopes:    in.Scopes,
		Audience:  in.Audience,
		Status:    AccessActive,
		IssuedAt:  in.Now,
		ExpiresAt: in.Now.Add(in.Client.EffectiveAccessTokenTTL()),
	}
}
