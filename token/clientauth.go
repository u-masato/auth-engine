package token

import (
	"context"
	"errors"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/storage"
)

// Credentials はトークンエンドポイントで提示されたクライアントの資格情報（RFC 6749 §2.3）。
//
// HTTP 層が Authorization ヘッダ（client_secret_basic）またはフォーム（client_secret_post、
// public クライアントの client_id のみ）から取り出して渡す。複数の方式が同時に使われた場合は
// HTTP 層が invalid_request にする（RFC 6749 §2.3: MUST NOT use more than one method）。
type Credentials struct {
	ClientID string
	Secret   string
	// Method は資格情報の提示方法。Secret が無ければ client.AuthNone。
	Method client.AuthMethod
}

// authenticateClient は資格情報を検証して Client を返す。
//
//   - client_id が空、不明、Profile が受理しない方式、シークレット不一致: invalid_client
//   - confidential クライアントがシークレットなしで来た場合も invalid_client
//
// 失敗理由は区別せず、すべて同じ invalid_client にする（クライアント列挙を助けない）。
func authenticateClient(ctx context.Context, clients client.Resolver, creds Credentials) (*client.Client, error) {
	if creds.ClientID == "" {
		return nil, protocolErr(CodeInvalidClient, "client authentication failed")
	}
	c, err := clients.GetClient(ctx, creds.ClientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, protocolErr(CodeInvalidClient, "client authentication failed")
		}
		return nil, err
	}
	method := creds.Method
	if method == "" {
		method = client.AuthNone
	}
	if !c.AcceptsAuthMethod(method) {
		return nil, protocolErr(CodeInvalidClient, "client authentication failed")
	}
	if method != client.AuthNone && !c.VerifySecret(creds.Secret) {
		return nil, protocolErr(CodeInvalidClient, "client authentication failed")
	}
	return c, nil
}
