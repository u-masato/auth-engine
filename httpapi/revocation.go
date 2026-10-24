package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/muno/auth-engine/token"
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
		var perr *token.Error
		if errors.As(err, &perr) {
			s.writeTokenError(w, r, perr)
			return
		}
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// introspectionBody は RFC 7662 §2.2 の応答。active が false なら他は省く。
type introspectionBody struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
}

// handleIntrospect は /introspect（RFC 7662）。confidential な Client の認証を要求する。
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, token.CodeInvalidRequest, "malformed form body")
		return
	}
	creds, perr := clientCredentials(r)
	if perr != nil {
		s.writeTokenError(w, r, perr)
		return
	}
	in, err := s.engine.Token.Introspect(r.Context(), token.IntrospectionRequest{
		Token: r.PostForm.Get("token"), TokenTypeHint: r.PostForm.Get("token_type_hint"), Credentials: creds,
	})
	if err != nil {
		var perr *token.Error
		if errors.As(err, &perr) {
			s.writeTokenError(w, r, perr)
			return
		}
		s.internalError(w, r, err)
		return
	}
	body := introspectionBody{Active: in.Active}
	if in.Active {
		body.Scope = strings.Join(in.Scopes, " ")
		body.ClientID = in.ClientID
		body.TokenType = in.TokenType
		body.Exp = in.ExpiresAt.Unix()
		body.Iat = in.IssuedAt.Unix()
		body.Sub = in.Subject
		body.Iss = s.engine.Issuer
	}
	writeJSON(w, http.StatusOK, body)
}
