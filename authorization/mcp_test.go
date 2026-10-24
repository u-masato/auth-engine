package authorization_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
)

const mcpDocURL = "https://mcp-client.example/oauth/client.json"

// registerMCP は CIMD 文書から組み立てた MCP Client を Store に置く（事前登録、CIMD §7）。
// cimd.Resolver 経由でも authorization.Service から見える振る舞いは同じである。
func (f *fixture) registerMCP(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.NewMCP(client.MetadataDocument{ClientID: mcpDocURL, ClientName: "MCP", RedirectURIs: []string{"http://localhost:3000/callback"}}, mcpDocURL, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateClient(f.ctx, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func mcpParams() url.Values {
	p := params()
	p.Set("client_id", mcpDocURL)
	p.Set("redirect_uri", "http://localhost:3000/callback")
	p.Set("scope", "openid files:read") // 文書に scope がないので Client 側の上限はない
	return p
}

// ADR-0008 §4: MCP Client は resource が必須。欠落は invalid_request（リダイレクトして返す）。
func TestMCPRequiresResource(t *testing.T) {
	f := newFixture(t)
	f.registerMCP(t)

	txn, err := f.svc.Begin(f.ctx, mcpParams(), binding)
	if err != nil {
		t.Fatalf("mcp request with resource must succeed: %v", err)
	}
	if txn.Request.ClientID != mcpDocURL || txn.Request.Resource[0] != "https://api.example.com" || txn.Request.RedirectURI != "http://localhost:3000/callback" {
		t.Fatalf("request = %+v", txn.Request)
	}

	p := mcpParams()
	p.Del("resource")
	_, err = f.svc.Begin(f.ctx, p, binding)
	var perr *authorization.Error
	if !errors.As(err, &perr) || perr.Code != authorization.CodeInvalidRequest || !strings.Contains(perr.Description, "resource is required") {
		t.Fatalf("got %v, want invalid_request about resource", err)
	}
	if !perr.Redirectable() || perr.State != "xyz" {
		t.Fatalf("must redirect to the client with state: %+v", perr)
	}

	// 他の Profile では従来どおり省略できる
	q := params()
	q.Del("resource")
	if _, err := f.svc.Begin(f.ctx, q, binding); err != nil {
		t.Fatalf("web client without resource must still succeed: %v", err)
	}
}

// http loopback はポート番号を無視して照合する（RFC 8252 §7.3）。localhost は完全一致。
func TestMCPRedirectMatching(t *testing.T) {
	f := newFixture(t)
	c, err := client.NewMCP(client.MetadataDocument{ClientID: mcpDocURL, ClientName: "MCP",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://127.0.0.1/callback"}}, mcpDocURL, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateClient(f.ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		uri string
		ok  bool
	}{
		{"http://127.0.0.1:51004/callback", true},
		{"http://localhost:3000/callback", true},
		{"http://localhost:3001/callback", false},
	} {
		p := mcpParams()
		p.Set("redirect_uri", tt.uri)
		_, err := f.svc.Begin(f.ctx, p, binding)
		if (err == nil) != tt.ok {
			t.Errorf("%s: ok=%v err=%v", tt.uri, tt.ok, err)
		}
		var perr *authorization.Error
		if err != nil && (!errors.As(err, &perr) || perr.Redirectable()) {
			t.Errorf("%s: redirect_uri mismatch must not redirect: %v", tt.uri, err)
		}
	}
}

type resolverFunc func(ctx context.Context, id string) (*client.Client, error)

func (f resolverFunc) GetClient(ctx context.Context, id string) (*client.Client, error) {
	return f(ctx, id)
}

// Resolver が ErrUnresolvable（CIMD 文書の取得・検証失敗）を返したら、理由付きの invalid_request で
// リダイレクトせずに返す。それ以外の失敗は server_error。
func TestUnresolvableClient(t *testing.T) {
	f := newFixture(t)
	f.svc.Clients = resolverFunc(func(_ context.Context, id string) (*client.Client, error) {
		switch id {
		case "boom":
			return nil, errors.New("database down")
		default:
			return nil, fmt.Errorf("%w: metadata document %s: fetch failed: 503", client.ErrUnresolvable, id)
		}
	})
	p := mcpParams()
	_, err := f.svc.Begin(f.ctx, p, binding)
	var perr *authorization.Error
	if !errors.As(err, &perr) || perr.Code != authorization.CodeInvalidRequest || perr.Redirectable() ||
		!strings.Contains(perr.Description, "fetch failed: 503") || strings.HasPrefix(perr.Description, "client:") {
		t.Fatalf("got %v (%+v), want non-redirectable invalid_request with the reason", err, perr)
	}
	p.Set("client_id", "boom")
	_, err = f.svc.Begin(f.ctx, p, binding)
	if !errors.As(err, &perr) || perr.Code != authorization.CodeServerError {
		t.Fatalf("got %v, want server_error", err)
	}
}
