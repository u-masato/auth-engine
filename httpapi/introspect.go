package httpapi

import (
	"net/http"
	"strings"

	"github.com/u-masato/auth-engine/token"
)

// introspectionBody は RFC 7662 §2.2 の応答。active が false なら他は省く。
// aud は RFC 7519 §4.1.3 のとおり文字列か配列のどちらでもよいが、本実装は常に配列で返す
// （Resource Server 側の分岐を減らす）。resource なしで発行したトークンでは省く。
type introspectionBody struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
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
		s.writeTokenFailure(w, r, err)
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
		body.Aud = in.Audience
		body.Iss = s.engine.Issuer
	}
	writeJSON(w, http.StatusOK, body)
}
