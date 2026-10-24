package grant

import (
	"context"
	"time"
)

// Store は Grant の永続化 Port。各メソッドは単体で原子的でなければならない。
type Store interface {
	// UpsertGrant は candidate.ClientID × candidate.Subject の Grant を作成または更新し、
	// 保存後の Grant を返す。既存があれば Merge(existing, candidate) の結果で更新し、
	// なければ candidate をそのまま保存する。
	UpsertGrant(ctx context.Context, candidate *Grant) (*Grant, error)

	// GetGrant は ID で Grant を返す。なければ storage.ErrNotFound。
	GetGrant(ctx context.Context, id string) (*Grant, error)

	// FindGrant は clientID × subject の Grant を返す（失効済みも含む）。なければ storage.ErrNotFound。
	FindGrant(ctx context.Context, clientID, subject string) (*Grant, error)

	// ListGrantsBySubject は subject の全 Grant（失効済みも含む）を CreatedAt 昇順で返す。
	// なければ空のスライス。
	ListGrantsBySubject(ctx context.Context, subject string) ([]*Grant, error)

	// RevokeGrant は Grant と、それに属する全 Token Family・全トークンを 1 つの操作で失効させる。
	// 既に失効済みなら何もせず nil を返す。存在しなければ storage.ErrNotFound。
	RevokeGrant(ctx context.Context, id string, now time.Time) error
}
