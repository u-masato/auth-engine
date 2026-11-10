package authorization

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/storage"
)

// 期限の既定値と上限（ADR-0003 §5）。
const (
	DefaultTransactionTTL = 10 * time.Minute
	MaxTransactionTTL     = time.Hour
	DefaultCodeTTL        = time.Minute
	MaxCodeTTL            = 10 * time.Minute // RFC 6749 §4.1.2
)

// ResumeTokenPrefix は Resume Token の接頭辞。
const ResumeTokenPrefix = "rs_"

// Service は認可エンドポイントのユースケース群。フィールドは Engine が配線する。
type Service struct {
	Clients client.Resolver
	Store   Store
	Grants  grant.Store
	Clock   clock.Clock

	// Resources は認可要求の resource パラメータで指定できる Resource Server の集合（RFC 8707 §2.1）。
	// nil なら空集合で、resource 付きの要求はすべて invalid_target になる。
	Resources *resource.Set

	// Issuer は認可サーバーの識別子（RFC 8414 の issuer）。認可応答の iss に使う（RFC 9207）。
	Issuer string

	// TransactionTTL / CodeTTL は 0 なら既定値。上限の検査は Engine の設定検証で行う。
	TransactionTTL time.Duration
	CodeTTL        time.Duration
}

func (s *Service) txnTTL() time.Duration {
	if s.TransactionTTL == 0 {
		return DefaultTransactionTTL
	}
	return s.TransactionTTL
}

func (s *Service) codeTTL() time.Duration {
	if s.CodeTTL == 0 {
		return DefaultCodeTTL
	}
	return s.CodeTTL
}

// Transaction は存在し期限内の Transaction を返す。Interaction App が UI を描くための
// GET /transactions/{id} と、Complete / Reject / Resume の前提確認に使う（ADR-0003 §3 (4)）。
// 存在しなければ ErrTransactionNotFound、期限切れなら ErrTransactionExpired を返す。
func (s *Service) Transaction(ctx context.Context, id string) (*Transaction, error) {
	txn, err := s.Store.GetTransaction(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTransactionNotFound
		}
		return nil, fmt.Errorf("authorization: get transaction: %w", err)
	}
	if txn.Expired(s.Clock.Now()) {
		return nil, ErrTransactionExpired
	}
	return txn, nil
}
