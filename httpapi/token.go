package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/token"
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
		Credentials:  creds,
	}
	res, err := s.engine.Token.Exchange(r.Context(), req)
	if err != nil {
		var perr *token.Error
		if errors.As(err, &perr) {
			s.writeTokenError(w, r, perr)
			return
		}
		s.logger.ErrorContext(r.Context(), "token endpoint internal error", "event", "http.internal_error", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// clientCredentials はクライアントの資格情報を取り出す（RFC 6749 §2.3.1）。
//
//   - Authorization: Basic → client_secret_basic。user / pass は form-urlencoded されているので復号する。
//   - フォームに client_secret → client_secret_post。
//   - どちらもなし → none（public クライアント。client_id はフォームから）。
//
// Basic とフォームの client_secret が両方あれば invalid_request（複数方式の併用禁止）。
func clientCredentials(r *http.Request) (token.Credentials, *token.Error) {
	user, pass, hasBasic := r.BasicAuth()
	formID := r.PostForm.Get("client_id")
	formSecret, hasFormSecret := r.PostForm["client_secret"]

	if hasBasic && hasFormSecret {
		return token.Credentials{}, &token.Error{Code: token.CodeInvalidRequest, Description: "multiple client authentication methods"}
	}
	if hasBasic {
		id, err1 := url.QueryUnescape(user)
		secret, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			return token.Credentials{}, &token.Error{Code: token.CodeInvalidRequest, Description: "malformed Basic credentials"}
		}
		if formID != "" && formID != id {
			return token.Credentials{}, &token.Error{Code: token.CodeInvalidRequest, Description: "client_id does not match Basic credentials"}
		}
		return token.Credentials{ClientID: id, Secret: secret, Method: client.AuthClientSecretBasic}, nil
	}
	if hasFormSecret {
		return token.Credentials{ClientID: formID, Secret: formSecret[0], Method: client.AuthClientSecretPost}, nil
	}
	return token.Credentials{ClientID: formID, Method: client.AuthNone}, nil
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
