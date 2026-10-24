package token

import "time"

// FamilyStatus は Token Family の状態。
type FamilyStatus string

const (
	FamilyActive  FamilyStatus = "active"
	FamilyRevoked FamilyStatus = "revoked"
)

// Family は 1 回の Code 交換（または client_credentials 要求）から派生するトークンの集まり。
type Family struct {
	ID       string
	GrantID  string
	ClientID string
	Subject  string
	// Scopes はこの Family のトークンに付く scope。Grant の scope の部分集合。
	Scopes []string

	// AuthenticatedAt / AMR / ACR は元の認証の情報。Refresh 時に発行する ID Token の
	// auth_time / amr / acr は元の認証を表さなければならない（OIDC Core §12.2）ため、
	// Family に写しを持つ。client_credentials の Family ではゼロ値。
	AuthenticatedAt time.Time
	AMR             []string
	ACR             string

	Status    FamilyStatus
	CreatedAt time.Time
	// ExpiresAt は Refresh Token の絶対期限（Family 全体の寿命）。Refresh Token を
	// 発行しない Family ではゼロ値。
	ExpiresAt time.Time
	RevokedAt time.Time // ゼロ値なら未失効
}

// Refresh Token の有効期間の既定値（ADR-0006 §4）。
//
//   - 絶対期限: Family 作成からの寿命。Rotation しても延びない。
//   - スライド期限: 最終使用からの寿命。Rotation のたびに延びるが、絶対期限を超えない。
const (
	DefaultRefreshTokenTTL     = 30 * 24 * time.Hour
	DefaultRefreshTokenIdleTTL = 14 * 24 * time.Hour
)

// Active は失効していないかを返す。
func (f *Family) Active() bool { return f.Status == FamilyActive }

// AccessStatus は Access Token の状態。
type AccessStatus string

const (
	AccessActive  AccessStatus = "active"
	AccessRevoked AccessStatus = "revoked"
)

// AccessToken は Opaque な Access Token の記録。平文は保存しない。
type AccessToken struct {
	Hash     string
	FamilyID string
	GrantID  string
	ClientID string
	Subject  string
	Scopes   []string

	Status    AccessStatus
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time // ゼロ値なら未失効
}

// Valid は now 時点で有効（未失効・未期限）かを返す。Grant / Family の状態は含まない。
func (t *AccessToken) Valid(now time.Time) bool {
	return t.Status == AccessActive && now.Before(t.ExpiresAt)
}

// RefreshStatus は Refresh Token の状態。
type RefreshStatus string

const (
	RefreshActive  RefreshStatus = "active"
	RefreshRotated RefreshStatus = "rotated"
	RefreshRevoked RefreshStatus = "revoked"
)

// RefreshToken は Refresh Token の記録。Rotation で rotated になり、後継の Hash を持つ。
type RefreshToken struct {
	Hash     string
	FamilyID string

	Status         RefreshStatus
	ReplacedByHash string // Status が rotated のとき、後継トークンの Hash
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RotatedAt      time.Time // ゼロ値なら未 Rotation
	RevokedAt      time.Time // ゼロ値なら未失効
}

// トークン平文の接頭辞。ログやシークレットスキャナでの識別用。
const (
	AccessTokenPrefix  = "at_"
	RefreshTokenPrefix = "rt_"
)
