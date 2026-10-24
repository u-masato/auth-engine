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

// Request は検証済みの認可要求パラメータ。
// エンジンが解釈するもの（redirect_uri, scope, PKCE, nonce）と、
// Interaction App へ透過するヒント（prompt, max_age, login_hint, ...）の両方を持つ。
type Request struct {
	ClientID string

	// RedirectURI は登録情報と照合済みの、実際に使う redirect URI。
	RedirectURI string
	// RedirectURIExplicit は要求に redirect_uri パラメータが含まれていたか。
	// RFC 6749 §4.1.3 により、含まれていた場合はトークン要求でも同じ値を要求する。
	RedirectURIExplicit bool

	Scopes []string
	State  string

	// PKCE（RFC 7636）。Method は常に "S256"。
	CodeChallenge       string
	CodeChallengeMethod string

	// OIDC Core §3.1.2.1。Nonce は ID Token に転記する。他はエンジンが解釈しない。
	Nonce     string
	Prompt    []string
	MaxAge    time.Duration
	HasMaxAge bool
	LoginHint string
	UILocales string
	ACRValues string

	// Resource は RFC 8707 の resource パラメータ。M1 では保存のみで検証しない。
	Resource []string
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

// AuthorizationCode は Resume 時に発行する単回使用の Code（RFC 6749 §4.1.2）。
// Code の平文は保存せず、SHA-256 の Hash をキーにする。
type AuthorizationCode struct {
	Hash string

	TxnID    string
	ClientID string
	GrantID  string
	// FamilyID は、この Code の交換で作られる Token Family の ID をあらかじめ確定したもの。
	// Code の再利用を検知したとき、この Family を失効させる（RFC 6749 §4.1.2）。
	FamilyID string

	Subject             string
	RedirectURI         string
	RedirectURIExplicit bool
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string

	AuthenticatedAt time.Time
	AMR             []string
	ACR             string
	Claims          map[string]any

	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time // ゼロ値なら未消費
}

// Consumed は消費済みかを返す。
func (c *AuthorizationCode) Consumed() bool { return !c.ConsumedAt.IsZero() }

// Expired は now 時点で期限切れかを返す。
func (c *AuthorizationCode) Expired(now time.Time) bool { return !now.Before(c.ExpiresAt) }
