package grant

import (
	"context"
	"errors"
	"fmt"

	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/storage"
)

// ErrNotFound は、指定した client_id × subject の Grant が存在しない。
var ErrNotFound = errors.New("grant: not found")

// Service は Grant の管理操作（ADR-0006 §5）。プロトコル上の対応物はなく、Go API と
// Interaction API（GET /grants）から使う。フィールドは Engine が配線する。
type Service struct {
	Store Store
	Clock clock.Clock
}

// Find は clientID × subject の active な Grant を返す。失効済み・未登録なら ErrNotFound。
// Interaction App が「既に同意済みの scope なら同意画面を省く」判断に使う（ADR-0003 §3 (4)）。
func (s *Service) Find(ctx context.Context, clientID, subject string) (*Grant, error) {
	g, err := s.Store.FindGrant(ctx, clientID, subject)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("grant: find: %w", err)
	}
	if !g.Active() {
		return nil, ErrNotFound
	}
	return g, nil
}

// List は subject の active な Grant を CreatedAt 昇順で返す。「連携済みアプリ一覧」用。
func (s *Service) List(ctx context.Context, subject string) ([]*Grant, error) {
	if subject == "" {
		return nil, errors.New("grant: subject is required")
	}
	all, err := s.Store.ListGrantsBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("grant: list: %w", err)
	}
	out := make([]*Grant, 0, len(all))
	for _, g := range all {
		if g.Active() {
			out = append(out, g)
		}
	}
	return out, nil
}

// Revoke は clientID × subject の Grant と、その配下の全 Token Family・全トークンを失効させる
// （「このアプリとの連携を解除する」）。既に失効済みなら何もしない。未登録なら ErrNotFound。
func (s *Service) Revoke(ctx context.Context, clientID, subject string) error {
	g, err := s.Store.FindGrant(ctx, clientID, subject)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("grant: find: %w", err)
	}
	if err := s.Store.RevokeGrant(ctx, g.ID, s.Clock.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("grant: revoke: %w", err)
	}
	return nil
}
