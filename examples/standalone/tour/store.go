package tour

import (
	"context"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/token"
)

// tracedStore は Store の呼び出しのうち、状態を進める主なものを記録する。
//
// authengine.Store を埋め込み、図で見せたいメソッドだけを上書きする。読み取り（GetClient、
// GetTransaction など）は記録しないので、タイムラインに出るのは Store への全アクセスではない。
// 記録するだけで、引数も結果も変えない。
type tracedStore struct {
	authengine.Store
	rec *Recorder
}

func (s tracedStore) CreateTransaction(ctx context.Context, txn *authorization.Transaction) error {
	err := s.Store.CreateTransaction(ctx, txn)
	s.rec.storeCall("CreateTransaction", "検証済みの認可要求を Transaction（pending）として保存する", err)
	return err
}

func (s tracedStore) TransitionTransaction(ctx context.Context, id string, from, to authorization.Status, patch authorization.Patch) error {
	err := s.Store.TransitionTransaction(ctx, id, from, to, patch)
	note := "Transaction の状態を " + string(from) + " から " + string(to) + " へ進める（CAS）。"
	switch to {
	case authorization.StatusCompleted:
		note += "Interaction App が伝えた認証と同意の結果を保存する"
	case authorization.StatusRejected:
		note += "拒否の結果を保存する"
	case authorization.StatusConsumed:
		note += "Resume を 1 回だけ通す。Code を作るのはこの後"
	}
	s.rec.storeCall("TransitionTransaction", note, err)
	return err
}

func (s tracedStore) CreateAuthorizationCode(ctx context.Context, code *authorization.AuthorizationCode) error {
	err := s.Store.CreateAuthorizationCode(ctx, code)
	s.rec.storeCall("CreateAuthorizationCode", "Authorization Code を保存する。保存するのは SHA-256 ハッシュだけ", err)
	return err
}

func (s tracedStore) UpsertGrant(ctx context.Context, candidate *grant.Grant) (*grant.Grant, error) {
	g, err := s.Store.UpsertGrant(ctx, candidate)
	s.rec.storeCall("UpsertGrant", "ユーザーの同意（Client・subject・scope）を Grant として記録する", err)
	return g, err
}

func (s tracedStore) ConsumeAuthorizationCode(ctx context.Context, codeHash string, now time.Time) (*authorization.AuthorizationCode, error) {
	c, err := s.Store.ConsumeAuthorizationCode(ctx, codeHash, now)
	s.rec.storeCall("ConsumeAuthorizationCode", "Code を消費済みにする。2 回目の提示は再利用として検知する", err)
	return c, err
}

func (s tracedStore) IssueTokens(ctx context.Context, family *token.Family, access *token.AccessToken, refresh *token.RefreshToken) error {
	err := s.Store.IssueTokens(ctx, family, access, refresh)
	s.rec.storeCall("IssueTokens", "Token Family と、Access Token・Refresh Token のハッシュを保存する", err)
	return err
}

func (s tracedStore) RotateRefreshToken(ctx context.Context, oldHash string, next *token.RefreshToken, access *token.AccessToken, now time.Time) error {
	err := s.Store.RotateRefreshToken(ctx, oldHash, next, access, now)
	s.rec.storeCall("RotateRefreshToken", "古い Refresh Token を rotated にし、同じ Token Family に後継を保存する", err)
	return err
}

func (s tracedStore) LookupAccessToken(ctx context.Context, hash string) (*token.AccessToken, *grant.Grant, error) {
	t, g, err := s.Store.LookupAccessToken(ctx, hash)
	s.rec.storeCall("LookupAccessToken", "Access Token のハッシュから、状態（失効していないか）と Grant を引く", err)
	return t, g, err
}

func (s tracedStore) RevokeAccessToken(ctx context.Context, hash string, now time.Time) error {
	err := s.Store.RevokeAccessToken(ctx, hash, now)
	s.rec.storeCall("RevokeAccessToken", "Access Token を失効させる", err)
	return err
}

func (s tracedStore) RevokeTokenFamily(ctx context.Context, familyID string, now time.Time) error {
	err := s.Store.RevokeTokenFamily(ctx, familyID, now)
	s.rec.storeCall("RevokeTokenFamily", "Token Family と配下のトークンをまとめて失効させる", err)
	return err
}
