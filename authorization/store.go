package authorization

import "context"

// Patch は TransitionTransaction で遷移と同時に書き込む値。nil / 空のフィールドは変更しない。
type Patch struct {
	Outcome         *Outcome
	Rejection       *Rejection
	ResumeTokenHash string
}

// Store は Authorization Transaction と Authorization Code の永続化 Port。
// 各メソッドは単体で原子的でなければならない（ADR-0005 §1）。
type Store interface {
	// CreateTransaction は Transaction を保存する。同じ ID があれば storage.ErrAlreadyExists。
	CreateTransaction(ctx context.Context, txn *Transaction) error

	// GetTransaction は ID で Transaction を返す。なければ storage.ErrNotFound。
	GetTransaction(ctx context.Context, id string) (*Transaction, error)

	// TransitionTransaction は Status が from のときだけ to に更新し、patch を適用する（CAS）。
	// Status が from でなければ storage.ErrStateConflict、存在しなければ storage.ErrNotFound。
	// 遷移の正当性（from.CanTransitionTo(to)）は呼び出し側が保証する。
	TransitionTransaction(ctx context.Context, id string, from, to Status, patch Patch) error

	// CreateAuthorizationCode は Code を保存する。同じ Hash があれば storage.ErrAlreadyExists。
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
}
