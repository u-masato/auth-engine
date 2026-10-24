package token

import "net/http"

// RFC 6749 §5.2 のエラーコード。
const (
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidClient        = "invalid_client"
	CodeInvalidGrant         = "invalid_grant"
	CodeUnauthorizedClient   = "unauthorized_client"
	CodeUnsupportedGrantType = "unsupported_grant_type"
	CodeInvalidScope         = "invalid_scope"
)

// Error はトークンエンドポイントのプロトコルエラー（RFC 6749 §5.2）。
// 内部障害（Store の失敗など）は *Error ではなく通常の error で返し、HTTP 層が 500 にする。
type Error struct {
	Code        string
	Description string
	// Cause はログ用の内部原因。Client には返さない。
	Cause error
}

func (e *Error) Error() string {
	if e.Description == "" {
		return "token: " + e.Code
	}
	return "token: " + e.Code + ": " + e.Description
}

// Unwrap は Cause を返す。
func (e *Error) Unwrap() error { return e.Cause }

// HTTPStatus は RFC 6749 §5.2 に従う HTTP ステータス。invalid_client は 401、他は 400。
func (e *Error) HTTPStatus() int {
	if e.Code == CodeInvalidClient {
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}

func protocolErr(code, desc string) *Error {
	return &Error{Code: code, Description: desc}
}
