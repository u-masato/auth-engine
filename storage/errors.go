package storage

import "errors"

// Adapter が返すセンチネルエラー。エンジンは errors.Is で判別する。
// Adapter 固有のエラー（接続断など）はこれらにラップせず、そのまま返してよい。
var (
	// ErrNotFound は、指定したキーに対応するレコードが存在しないことを表す。
	ErrNotFound = errors.New("storage: not found")

	// ErrAlreadyExists は、一意制約に違反する作成要求を表す。
	ErrAlreadyExists = errors.New("storage: already exists")

	// ErrStateConflict は、CAS（compare-and-swap）の前提状態が一致しなかったことを表す。
	// Authorization Transaction の二重 Complete などで返る。
	ErrStateConflict = errors.New("storage: state conflict")

	// ErrCodeAlreadyUsed は、消費済みの Authorization Code が再提示されたことを表す。
	// RFC 6749 §4.1.2 に従い、呼び出し側はこの Code に由来する Grant を失効させる。
	ErrCodeAlreadyUsed = errors.New("storage: authorization code already used")

	// ErrTokenReused は、Rotation 済みの Refresh Token が再提示されたことを表す。
	// RFC 9700 §4.14.2 に従い、呼び出し側は Token Family 全体を失効させる。
	ErrTokenReused = errors.New("storage: refresh token reused")

	// ErrGrantRevoked は、失効済みの Grant に対してトークン発行が要求されたことを表す。
	ErrGrantRevoked = errors.New("storage: grant revoked")
)

// ErrFamilyRevoked は、失効済みの Token Family に属するトークンの操作が要求されたことを表す。
var ErrFamilyRevoked = errors.New("storage: token family revoked")
