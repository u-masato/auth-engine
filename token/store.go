package token

import (
	"context"
	"time"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/grant"
)

// Store はトークンの永続化 Port。各メソッドは単体で原子的でなければならない（ADR-0005 §2）。
type Store interface {
	// ConsumeAuthorizationCode は Code を消費済みにして内容を返す。
	//
	//   - 未消費かつ未期限: 消費済みにして Code を返す。
	//   - 既に消費済み: 消費済みの Code と storage.ErrCodeAlreadyUsed を返す。
	//     呼び出し側は Code.FamilyID の Family を失効させる。
	//   - 存在しない、または期限切れ: storage.ErrNotFound。
	//
	// 消費済みの Code は再利用検知のため、期限まで削除しない。
	ConsumeAuthorizationCode(ctx context.Context, codeHash string, now time.Time) (*authorization.AuthorizationCode, error)

	// IssueTokens は新しい Family と、それに属する最初のトークンを保存する。
	// refresh は nil でよい。Family の GrantID が指す Grant が active でなければ
	// storage.ErrGrantRevoked を返し、何も保存しない。
	IssueTokens(ctx context.Context, family *Family, access *AccessToken, refresh *RefreshToken) error

	// RotateRefreshToken は oldHash の Refresh Token を rotated にし、同じ Family に
	// next（Refresh Token）と access（Access Token）を保存する。
	//
	//   - oldHash が active かつ未期限: 成功。
	//   - oldHash が rotated: storage.ErrTokenReused。呼び出し側は Family を失効させる。
	//   - oldHash が revoked、または Family が revoked: storage.ErrFamilyRevoked。
	//   - Grant が revoked: storage.ErrGrantRevoked。
	//   - 存在しない、または期限切れ: storage.ErrNotFound。
	RotateRefreshToken(ctx context.Context, oldHash string, next *RefreshToken, access *AccessToken, now time.Time) error

	// LookupAccessToken は Access Token と、それが属する Grant を返す。
	// Grant の失効チェックを二重化するため、Grant も併せて返す。なければ storage.ErrNotFound。
	LookupAccessToken(ctx context.Context, hash string) (*AccessToken, *grant.Grant, error)

	// LookupRefreshToken は Refresh Token を返す。なければ storage.ErrNotFound。
	LookupRefreshToken(ctx context.Context, hash string) (*RefreshToken, error)

	// GetTokenFamily は Family を返す。なければ storage.ErrNotFound。
	// Refresh Token は Family を介して Client・subject・scope に結びつく。
	GetTokenFamily(ctx context.Context, id string) (*Family, error)

	// RevokeTokenFamily は Family と配下の全トークンを失効させる。
	// 既に失効済みなら何もせず nil。存在しなければ storage.ErrNotFound。
	RevokeTokenFamily(ctx context.Context, familyID string, now time.Time) error

	// RevokeAccessToken は Access Token 1 つを失効させる。存在しなければ storage.ErrNotFound。
	RevokeAccessToken(ctx context.Context, hash string, now time.Time) error
}
