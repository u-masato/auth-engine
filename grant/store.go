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

	// ListGrantsByClient は clientID の Grant（失効済みも含む）を Subject の昇順（バイト列としての比較）で
	// 最大 limit 件返す。after が空でなければ、Subject が after より大きいものだけを返す。続きを読むときは、
	// 前回の最後の要素の Subject を after に渡す（キーセットページング。client.Store.ListClients と同じ規則）。
	// 該当がなければ空のスライス。limit が 1 未満のときも空のスライスを返す。
	//
	// 1 つの Client の Grant は利用者の数だけあるので、ListGrantsBySubject と違って件数を区切る。
	// 並びを Subject にするのは、clientID × Subject の一意制約の索引をそのまま使えるからである。
	//
	// 運用者向けの管理操作（Client の利用者の一覧、棚卸し）のためのもので、プロトコル処理からは呼ばない。
	// clientID の Client が Store にあるかは見ない（CIMD で解決した Client や削除済みの Client の
	// Grant も引ける）。
	ListGrantsByClient(ctx context.Context, clientID, after string, limit int) ([]*Grant, error)

	// RevokeGrant は Grant と、それに属する全 Token Family・全トークンを 1 つの操作で失効させる。
	// 既に失効済みなら何もせず nil を返す。存在しなければ storage.ErrNotFound。
	RevokeGrant(ctx context.Context, id string, now time.Time) error
}
