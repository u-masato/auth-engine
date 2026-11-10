package httpapi

import (
	"net/http"
	"net/url"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/token"
)

// clientCredentials はクライアントの資格情報を取り出す（RFC 6749 §2.3.1）。/token・/revoke・/introspect が
// 共通に使う。資格情報の検証は token.Service が行い、ここでは提示方法の判別だけをする。
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
