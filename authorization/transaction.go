package authorization

import "time"

// Status は Authorization Transaction の状態。
//
//	pending ──Complete──▶ completed ──Resume──▶ consumed
//	   │                      │
//	   └──Reject──▶ rejected ─┴──Resume──▶ consumed
type Status string

const (
	StatusPending   Status = "pending"
	StatusCompleted Status = "completed"
	StatusRejected  Status = "rejected"
	StatusConsumed  Status = "consumed"
)

// CanTransitionTo は状態機械上で許される遷移かを返す。
// Adapter は遷移の原子性（CAS）を担い、遷移の正当性はこの関数で判定する。
func (s Status) CanTransitionTo(to Status) bool {
	switch s {
	case StatusPending:
		return to == StatusCompleted || to == StatusRejected
	case StatusCompleted, StatusRejected:
		return to == StatusConsumed
	}
	return false
}

// Transaction は 1 回の /authorize 要求から Code 発行（または失敗）までを表す。
type Transaction struct {
	ID     string
	Status Status

	// Request は検証済みの認可要求。Interaction App はこれを参照してログイン・同意 UI を描く。
	Request Request

	// BrowserBindingHash は、/authorize でブラウザに発行した結合 Cookie 値の SHA-256。
	// Resume 時に同じブラウザからの要求であることを確認する（ADR-0003 §3）。
	BrowserBindingHash string

	// Outcome は Complete で記録される結果。Status が completed / consumed のときのみ非 nil。
	Outcome *Outcome
	// Rejection は Reject で記録される結果。Status が rejected / consumed のときのみ非 nil。
	Rejection *Rejection
	// ResumeTokenHash は Complete / Reject で発行した単回使用トークンの SHA-256。
	ResumeTokenHash string

	CreatedAt time.Time
	ExpiresAt time.Time
}

// Expired は now 時点で期限切れかを返す。
func (t *Transaction) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

// Outcome は Interaction App が Complete で伝える成功結果（ADR-0003 §3 (5)）。
type Outcome struct {
	// Subject はエンジンにとって不透明なユーザー識別子。
	Subject string
	// AuthenticatedAt は認証時刻。max_age の検証と ID Token の auth_time に使う。
	AuthenticatedAt time.Time
	// GrantedScopes は要求 scope の部分集合。
	GrantedScopes []string
	// AMR / ACR は ID Token にそのまま載せる（OIDC Core §2）。
	AMR []string
	ACR string
	// Claims は ID Token / UserInfo 用のスナップショット（ADR-0006 §3）。
	Claims map[string]any
}

// Rejection は Interaction App が Reject で伝える失敗結果。
type Rejection struct {
	// Error は RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6 のエラーコード。
	Error       string
	Description string
}
