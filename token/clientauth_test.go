package token_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/token"
)

type resolverFunc func(ctx context.Context, id string) (*client.Client, error)

func (f resolverFunc) GetClient(ctx context.Context, id string) (*client.Client, error) {
	return f(ctx, id)
}

// Resolver が ErrUnresolvable（CIMD 文書の取得・検証失敗）を返したら、理由付きの invalid_client にする。
// 登録済み Client の列挙には役立たない情報なので、不明な client_id の固定文言とは区別してよい。
func TestUnresolvableClientIsInvalidClient(t *testing.T) {
	f := newFixture(t)
	store := f.store
	f.svc.Clients = resolverFunc(func(ctx context.Context, id string) (*client.Client, error) {
		if strings.HasPrefix(id, "https://") {
			return nil, fmt.Errorf("%w: metadata document %s: not trusted", client.ErrUnresolvable, id)
		}
		return store.GetClient(ctx, id)
	})
	_, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "authorization_code", Code: "x",
		Credentials: token.Credentials{ClientID: "https://mcp-client.example/client", Method: client.AuthNone}})
	var perr *token.Error
	if !errors.As(err, &perr) || perr.Code != token.CodeInvalidClient || !strings.Contains(perr.Description, "not trusted") || strings.HasPrefix(perr.Description, "client:") {
		t.Fatalf("got %v, want invalid_client with the reason", err)
	}
	// 登録済み Client は従来どおり
	if _, err := f.svc.Exchange(f.ctx, token.Request{GrantType: "authorization_code", Code: "x",
		Credentials: token.Credentials{ClientID: "nope", Method: client.AuthNone}}); !errors.As(err, &perr) || perr.Code != token.CodeInvalidClient || perr.Description != "client authentication failed" {
		t.Fatalf("unknown client: got %v", err)
	}
}
