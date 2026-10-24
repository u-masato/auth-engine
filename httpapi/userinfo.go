package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/u-masato/auth-engine/oidc"
)

// handleUserInfo は UserInfo エンドポイント（OIDC Core §5.3）。GET と POST を受ける。
// Access Token は Authorization: Bearer ヘッダ（RFC 6750 §2.1）か、POST のフォーム
// access_token（§2.2）で受け取る。両方あれば invalid_request。
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := bearerToken(r)
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			bearerError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
			return
		}
		if form := r.PostForm.Get("access_token"); form != "" {
			if ok {
				bearerError(w, http.StatusBadRequest, "invalid_request", "access token in both header and body")
				return
			}
			accessToken, ok = form, true
		}
	}
	if !ok {
		// RFC 6750 §3.1: 認証情報がない要求には error を付けない
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, err := s.engine.UserInfo.UserInfo(r.Context(), accessToken)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, claims)
	case errors.Is(err, oidc.ErrInvalidToken):
		bearerError(w, http.StatusUnauthorized, "invalid_token", "the access token is invalid, expired or revoked")
	case errors.Is(err, oidc.ErrInsufficientScope):
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="insufficient_scope", scope="openid"`)
		writeJSONError(w, http.StatusForbidden, "insufficient_scope", "the access token lacks the openid scope")
	default:
		s.logger.ErrorContext(r.Context(), "userinfo internal error", "event", "http.internal_error", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

// bearerToken は Authorization: Bearer <token> からトークンを取り出す。スキームは大文字小文字を区別しない。
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

// bearerError は RFC 6750 §3 のエラー応答。
func bearerError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="`+code+`", error_description="`+description+`"`)
	writeJSONError(w, status, code, description)
}
