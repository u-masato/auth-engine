package authorization

import "time"

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
	// Resource は認可要求の resource をそのまま引き継いだもの（ADR-0008 §3）。
	// Code 交換で発行する Access Token の Audience はこの部分集合になる（RFC 8707 §2.2）。
	Resource []string

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
