package httpapi

import (
	"errors"
	"net/http"

	"github.com/u-masato/auth-engine/token"
)

// handleToken は /token（RFC 6749 §3.2、§4.1.3、§5）。
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, token.CodeInvalidRequest, "malformed form body")
		return
	}
	creds, perr := clientCredentials(r)
	if perr != nil {
		s.writeTokenError(w, r, perr)
		return
	}
	req := token.Request{
		GrantType:    r.PostForm.Get("grant_type"),
		Code:         r.PostForm.Get("code"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		CodeVerifier: r.PostForm.Get("code_verifier"),
		RefreshToken: r.PostForm.Get("refresh_token"),
		Scope:        r.PostForm.Get("scope"),
		Resource:     r.PostForm["resource"], // RFC 8707 §2.2。複数可
		Credentials:  creds,
	}
	res, err := s.engine.Token.Exchange(r.Context(), req)
	if err != nil {
		s.writeTokenFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// writeTokenFailure は Token Service（Exchange / Revoke / Introspect）の失敗を返す。
// *token.Error はプロトコルエラー（RFC 6749 §5.2）、それ以外は内部障害として JSON の 500 にする。
// これらのエンドポイントの呼び出し元は Client や Resource Server なので、HTML のエラーページは返さない。
func (s *Server) writeTokenFailure(w http.ResponseWriter, r *http.Request, err error) {
	var perr *token.Error
	if errors.As(err, &perr) {
		s.writeTokenError(w, r, perr)
		return
	}
	s.jsonInternalError(w, r, err)
}

// writeTokenError は RFC 6749 §5.2 のエラー応答を返す。
// Basic 認証を試みた要求への invalid_client には WWW-Authenticate を付ける。
func (s *Server) writeTokenError(w http.ResponseWriter, r *http.Request, perr *token.Error) {
	s.logger.InfoContext(r.Context(), "token request rejected",
		"event", "token.rejected", "error", perr.Code, "description", perr.Description)
	if perr.Code == token.CodeInvalidClient {
		if _, _, hasBasic := r.BasicAuth(); hasBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		}
	}
	writeJSONError(w, perr.HTTPStatus(), perr.Code, perr.Description)
}
