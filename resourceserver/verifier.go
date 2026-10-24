package resourceserver

import (
	"context"
	"errors"
	"slices"
	"time"
)

// TokenVerifier は Bearer トークンを検証し、検証済みの主体を返す。
//
// 実装は IntrospectionVerifier（RFC 7662）と JWTVerifier（RFC 9068 のローカル検証）。
// トークンが無効（不明・期限切れ・失効・署名不正・形式違い）なら ErrInvalidToken を包んだ error を返す。
// それ以外の error（認可サーバーに到達できない等）は一時的な障害として 503 になる。
//
// aud の確認は Protector が行うので、実装は Principal.Audience を埋めるだけでよい。
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*Principal, error)
}

// ErrInvalidToken はトークンが無効であることを表す（RFC 6750 §3.1 の invalid_token）。
var ErrInvalidToken = errors.New("resourceserver: invalid token")

// Principal は検証済みの Access Token が表す主体。Require を通ったハンドラが FromContext で取り出す。
type Principal struct {
	// Subject はユーザー識別子（sub）。client_credentials のトークンでは client_id と同じ。
	Subject string
	// ClientID はトークンを得た Client（RFC 9068 §2.2 / RFC 7662 §2.2 の client_id）。
	ClientID string
	// Scopes は付与された scope。
	Scopes []string
	// Audience はトークンの aud（resource indicator）。Protector が自分の resource を含むことを確認済み。
	Audience []string
	// ExpiresAt は有効期限。ゼロなら不明（Introspection が exp を返さなかった）。
	ExpiresAt time.Time
	// IssuedAt は発行時刻。ゼロなら不明。
	IssuedAt time.Time
}

// HasScope は s が付与されているかを返す。
func (p *Principal) HasScope(s string) bool { return slices.Contains(p.Scopes, s) }

type principalKey struct{}

// FromContext は Require が context に載せた Principal を返す。Require を通っていなければ false。
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

// VerifierFunc は関数を TokenVerifier にする（テストや独自の検証方式に使う）。
type VerifierFunc func(ctx context.Context, token string) (*Principal, error)

// Verify は f を呼ぶ。
func (f VerifierFunc) Verify(ctx context.Context, token string) (*Principal, error) {
	return f(ctx, token)
}
