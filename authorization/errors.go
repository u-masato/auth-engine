package authorization

import (
	"errors"
	"fmt"
	"net/url"
)

// RFC 6749 §4.1.2.1 と OIDC Core §3.1.2.6 のエラーコード。
const (
	CodeInvalidRequest          = "invalid_request"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeAccessDenied            = "access_denied"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeInvalidScope            = "invalid_scope"
	CodeServerError             = "server_error"
	CodeTemporarilyUnavailable  = "temporarily_unavailable"

	CodeInteractionRequired    = "interaction_required"
	CodeLoginRequired          = "login_required"
	CodeConsentRequired        = "consent_required"
	CodeRequestNotSupported    = "request_not_supported"
	CodeRequestURINotSupported = "request_uri_not_supported"
)

// rejectionCodes は Interaction App が Reject で指定できるエラーコード（ADR-0003 §3 (5)）。
var rejectionCodes = map[string]bool{
	CodeAccessDenied:        true,
	CodeLoginRequired:       true,
	CodeConsentRequired:     true,
	CodeInteractionRequired: true,
	CodeServerError:         true,
}

// Error は認可エンドポイントのプロトコルエラー。
//
// RedirectURI が空のときは client_id 不明または redirect_uri 不一致であり、
// RFC 6749 §4.1.2.1 により Client へリダイレクトしてはならない。呼び出し側はエラーページを描く。
// RedirectURI が非空なら RedirectURL で Client 向けのエラー応答 URL を組み立てる。
type Error struct {
	Code        string
	Description string
	RedirectURI string
	State       string
	// Cause はログ用の内部原因。Client には返さない。
	Cause error
}

func (e *Error) Error() string {
	if e.Description == "" {
		return "authorization: " + e.Code
	}
	return "authorization: " + e.Code + ": " + e.Description
}

// Unwrap は Cause を返す。
func (e *Error) Unwrap() error { return e.Cause }

// Redirectable は Client へリダイレクトして返してよいエラーかを返す。
func (e *Error) Redirectable() bool { return e.RedirectURI != "" }

// RedirectURL は Client へのエラー応答 URL を返す（RFC 6749 §4.1.2.1、RFC 9207 の iss 付き）。
// Redirectable でなければ空文字を返す。
func (e *Error) RedirectURL(issuer string) string {
	if !e.Redirectable() {
		return ""
	}
	q := url.Values{}
	q.Set("error", e.Code)
	if e.Description != "" {
		q.Set("error_description", e.Description)
	}
	if e.State != "" {
		q.Set("state", e.State)
	}
	q.Set("iss", issuer)
	return appendQuery(e.RedirectURI, q)
}

// appendQuery は base の既存クエリを保ったまま params を追加する（RFC 6749 §4.1.2）。
// base は登録済み redirect URI なので解析に失敗しない前提だが、万一失敗したらそのまま返す。
func appendQuery(base string, params url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String()
}

// Interaction API（Complete / Reject / Resume）向けのエラー。HTTP 層はこれらをステータスに写す。
var (
	// ErrTransactionNotFound は Txn が存在しない（404）。
	ErrTransactionNotFound = errors.New("authorization: transaction not found")
	// ErrTransactionExpired は Txn が期限切れ（410）。
	ErrTransactionExpired = errors.New("authorization: transaction expired")
	// ErrTransactionNotPending は既に Complete / Reject 済み（409）。
	ErrTransactionNotPending = errors.New("authorization: transaction is not pending")
	// ErrInvalidOutcome は Outcome / Rejection の内容が契約に反する（400）。詳細は fmt で付加される。
	ErrInvalidOutcome = errors.New("authorization: invalid outcome")
	// ErrResumeDenied は Resume を拒否した（ResumeToken・ブラウザ結合の不一致、未完了、再利用）。
	// 攻撃者に区別を与えないため、理由は分けない。エラーページを描き、Client へはリダイレクトしない。
	ErrResumeDenied = errors.New("authorization: resume denied")
)

func invalidOutcome(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOutcome, fmt.Sprintf(format, args...))
}
