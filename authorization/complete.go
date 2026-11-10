package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage"
)

// Complete は Interaction App からの成功結果を記録し、Resume Token の平文を返す（ADR-0003 §3 (5)）。
//
// Outcome の検証: subject 非空、authenticated_at 非ゼロ、granted_scopes が要求 scope の
// 空でない部分集合、max_age 要求時は認証が新しいこと。
func (s *Service) Complete(ctx context.Context, txnID string, out Outcome) (string, error) {
	txn, err := s.pendingTransaction(ctx, txnID)
	if err != nil {
		return "", err
	}
	now := s.Clock.Now()
	if out.Subject == "" {
		return "", invalidOutcome("subject is required")
	}
	if out.AuthenticatedAt.IsZero() {
		return "", invalidOutcome("authenticated_at is required")
	}
	if len(out.GrantedScopes) == 0 {
		return "", invalidOutcome("granted_scopes must not be empty; use Reject to deny")
	}
	// 要求 scope の部分集合であることを確かめつつ、順序を保って重複を除く（隣り合わない重複も）。
	var granted []string
	for _, sc := range out.GrantedScopes {
		if !slices.Contains(txn.Request.Scopes, sc) {
			return "", invalidOutcome("granted scope %q was not requested", sc)
		}
		if !slices.Contains(granted, sc) {
			granted = append(granted, sc)
		}
	}
	if txn.Request.HasMaxAge && now.Sub(out.AuthenticatedAt) > txn.Request.MaxAge {
		return "", invalidOutcome("authentication is older than max_age; re-authenticate the user")
	}
	out.GrantedScopes = granted
	out.AMR = slices.Clone(out.AMR)

	token, hash, err := s.newResumeToken()
	if err != nil {
		return "", err
	}
	err = s.Store.TransitionTransaction(ctx, txn.ID, StatusPending, StatusCompleted, Patch{Outcome: &out, ResumeTokenHash: hash})
	if err != nil {
		return "", mapTransitionError(err)
	}
	return token, nil
}

// Reject は Interaction App からの失敗結果を記録し、Resume Token の平文を返す。
func (s *Service) Reject(ctx context.Context, txnID string, rej Rejection) (string, error) {
	txn, err := s.pendingTransaction(ctx, txnID)
	if err != nil {
		return "", err
	}
	if !rejectionCodes[rej.Error] {
		return "", invalidOutcome("unsupported rejection error code %q", rej.Error)
	}
	token, hash, err := s.newResumeToken()
	if err != nil {
		return "", err
	}
	err = s.Store.TransitionTransaction(ctx, txn.ID, StatusPending, StatusRejected, Patch{Rejection: &rej, ResumeTokenHash: hash})
	if err != nil {
		return "", mapTransitionError(err)
	}
	return token, nil
}

// pendingTransaction は Complete / Reject の前提（存在・未期限・pending）を確認する。
func (s *Service) pendingTransaction(ctx context.Context, id string) (*Transaction, error) {
	txn, err := s.Transaction(ctx, id)
	if err != nil {
		return nil, err
	}
	if txn.Status != StatusPending {
		return nil, ErrTransactionNotPending
	}
	return txn, nil
}

func (s *Service) newResumeToken() (token, hash string, err error) {
	token, err = rand.Token(ResumeTokenPrefix)
	if err != nil {
		return "", "", err
	}
	return token, rand.Hash(token), nil
}

func mapTransitionError(err error) error {
	if errors.Is(err, storage.ErrStateConflict) {
		return ErrTransactionNotPending
	}
	if errors.Is(err, storage.ErrNotFound) {
		return ErrTransactionNotFound
	}
	return fmt.Errorf("authorization: transition transaction: %w", err)
}
