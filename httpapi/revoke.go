package httpapi

import (
	"net/http"

	"github.com/u-masato/auth-engine/token"
)

// handleRevoke は /revoke（RFC 7009）。クライアント認証はトークンエンドポイントと同じ方式。
// 成功は本文なしの 200。不明・他 Client のトークンも 200（§2.2）。
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, token.CodeInvalidRequest, "malformed form body")
		return
	}
	creds, perr := clientCredentials(r)
	if perr != nil {
		s.writeTokenError(w, r, perr)
		return
	}
	err := s.engine.Token.Revoke(r.Context(), token.RevocationRequest{
		Token: r.PostForm.Get("token"), TokenTypeHint: r.PostForm.Get("token_type_hint"), Credentials: creds,
	})
	if err != nil {
		s.writeTokenFailure(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}
