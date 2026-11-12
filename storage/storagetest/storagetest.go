// Package storagetest は、全 Store Adapter が通すべき契約テストを提供する。
//
// 使い方（Adapter 側のテスト）:
//
//	func TestContract(t *testing.T) {
//	    storagetest.Run(t, func(t *testing.T) authengine.Store { return openFreshStore(t) })
//	}
//
// open は呼び出しごとに空の Store を返すこと。並行テストを含むので、Adapter は
// 実際の DB（SQLite はファイル DB + WAL）で実行する（docs/adr/0005-storage-port.md §6）。
package storagetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/token"
)

// Run は open が返す Store に対して契約テストを実行する。
func Run(t *testing.T, open func(t *testing.T) authengine.Store) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s authengine.Store)
	}{
		{"Client", testClient},
		{"ClientList", testClientList},
		{"ClientUpdate", testClientUpdate},
		{"ClientRotateSecret", testClientRotateSecret},
		{"ClientDeleteCascades", testClientDeleteCascades},
		{"ClientDeleteVersusIssue", testClientDeleteVersusIssue},
		{"Transaction", testTransaction},
		{"TransactionConcurrentComplete", testTransactionConcurrentComplete},
		{"AuthorizationCode", testAuthorizationCode},
		{"AuthorizationCodeConcurrentConsume", testCodeConcurrentConsume},
		{"Grant", testGrant},
		{"GrantListByClient", testGrantListByClient},
		{"GrantRevokeCascades", testGrantRevokeCascades},
		{"IssueTokens", testIssueTokens},
		{"RotateRefreshToken", testRotateRefreshToken},
		{"RotateConcurrent", testRotateConcurrent},
		{"RevokeGrantVersusIssue", testRevokeGrantVersusIssue},
		{"RotateVersusRevoke", testRotateVersusRevoke},
		{"RevokeTokenFamily", testRevokeTokenFamily},
		{"RevokeAccessToken", testRevokeAccessToken},
		{"Purge", testPurge},
		{"PurgeChildlessParents", testPurgeChildlessParents},
		{"PurgeVersusRotate", testPurgeVersusRotate},
		{"PurgeVersusUpsertGrant", testPurgeVersusUpsertGrant},
		{"ValuesAreCopied", testValuesAreCopied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t, open(t))
		})
	}
}

// --- fixtures ---

var base = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

const concurrency = 16

func newWebClient(t *testing.T, id string) *client.Client {
	t.Helper()
	c, _, err := client.NewWeb(client.WebParams{
		ID: id, Name: "Test " + id,
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid", "profile", "email"},
		Resources:    []string{"https://api.example.com", "urn:example:billing"},
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTxn(id string) *authorization.Transaction {
	return &authorization.Transaction{
		ID:     id,
		Status: authorization.StatusPending,
		Request: authorization.Request{
			ClientID: "c1", RedirectURI: "https://app.example.com/cb", RedirectURIExplicit: true,
			Scopes: []string{"openid", "profile"}, State: "st",
			CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
			Nonce: "n", Prompt: []string{"login"}, MaxAge: 300 * time.Second, HasMaxAge: true,
		},
		BrowserBindingHash: "bind",
		CreatedAt:          base,
		ExpiresAt:          base.Add(10 * time.Minute),
	}
}

func newCode(hash, grantID, familyID string) *authorization.AuthorizationCode {
	return &authorization.AuthorizationCode{
		Hash: hash, TxnID: "t1", ClientID: "c1", GrantID: grantID, FamilyID: familyID,
		Subject: "alice", RedirectURI: "https://app.example.com/cb", RedirectURIExplicit: true,
		Scopes: []string{"openid"}, Resource: []string{"https://api.example.com"},
		CodeChallenge: "ch", CodeChallengeMethod: "S256", Nonce: "n",
		AuthenticatedAt: base, Claims: map[string]any{"name": "Alice"},
		CreatedAt: base, ExpiresAt: base.Add(time.Minute),
	}
}

func newGrant(id, clientID, subject string, scopes ...string) *grant.Grant {
	return &grant.Grant{
		ID: id, ClientID: clientID, Subject: subject, Scopes: scopes,
		Claims: map[string]any{"name": "Alice"}, Status: grant.StatusActive,
		CreatedAt: base, UpdatedAt: base,
	}
}

func newFamily(id, grantID string) *token.Family {
	return &token.Family{
		ID: id, GrantID: grantID, ClientID: "c1", Subject: "alice", Scopes: []string{"openid"},
		Audience:        []string{"https://api.example.com", "https://mcp.example.com"},
		AuthenticatedAt: base.Add(-time.Minute), AMR: []string{"pwd"}, ACR: "urn:acr:1",
		Status: token.FamilyActive, CreatedAt: base, ExpiresAt: base.Add(30 * 24 * time.Hour),
	}
}

func newAccess(hash, familyID, grantID string) *token.AccessToken {
	return &token.AccessToken{
		Hash: hash, FamilyID: familyID, GrantID: grantID, ClientID: "c1", Subject: "alice",
		Scopes: []string{"openid"}, Audience: []string{"https://api.example.com"},
		Status: token.AccessActive, IssuedAt: base, ExpiresAt: base.Add(time.Hour),
	}
}

func newRefresh(hash, familyID string) *token.RefreshToken {
	return &token.RefreshToken{
		Hash: hash, FamilyID: familyID, Status: token.RefreshActive,
		IssuedAt: base, ExpiresAt: base.Add(30 * 24 * time.Hour),
	}
}

// seedGrantWithTokens は Grant、Family、Access Token、Refresh Token を 1 組作る。
func seedGrantWithTokens(t *testing.T, s authengine.Store, suffix string) (*grant.Grant, *token.Family, *token.AccessToken, *token.RefreshToken) {
	t.Helper()
	ctx := context.Background()
	g, err := s.UpsertGrant(ctx, newGrant("g"+suffix, "c"+suffix, "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	f := newFamily("f"+suffix, g.ID)
	at := newAccess("at"+suffix, f.ID, g.ID)
	rt := newRefresh("rt"+suffix, f.ID)
	if err := s.IssueTokens(ctx, f, at, rt); err != nil {
		t.Fatal(err)
	}
	return g, f, at, rt
}

func wantErr(t *testing.T, got, want error, what string) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// --- client ---

func testClient(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	c := newWebClient(t, "c1")
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.CreateClient(ctx, c), storage.ErrAlreadyExists, "duplicate create")

	got, err := s.GetClient(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Profile != c.Profile || got.SecretHash != c.SecretHash ||
		!slices.Equal(got.RedirectURIs, c.RedirectURIs) || !slices.Equal(got.Scopes, c.Scopes) ||
		!slices.Equal(got.Resources, c.Resources) || !got.CreatedAt.Equal(c.CreatedAt) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("restored client must validate: %v", err)
	}
	_, err = s.GetClient(ctx, "missing")
	wantErr(t, err, storage.ErrNotFound, "missing client")

	// resource 制限なし（空）の Client は空のまま戻る
	open, err := client.NewNative(client.NativeParams{ID: "c-open", Name: "Open", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, open); err != nil {
		t.Fatal(err)
	}
	gotOpen, err := s.GetClient(ctx, "c-open")
	if err != nil || len(gotOpen.Resources) != 0 || !gotOpen.AllowsResource("https://any.example.com") {
		t.Fatalf("client without resources: %+v, %v", gotOpen, err)
	}

	// 事前登録した MCP Client（CIMD §7）: URL の client_id、client_uri、scope なし（上限なし）が往復する
	const docURL = "https://mcp-client.example/oauth/client.json"
	mcp, err := client.NewMCP(client.MetadataDocument{ClientID: docURL, ClientName: "MCP", ClientURI: "https://mcp-client.example",
		RedirectURIs: []string{"http://localhost:3000/callback"}}, docURL, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, mcp); err != nil {
		t.Fatal(err)
	}
	gotMCP, err := s.GetClient(ctx, docURL)
	if err != nil || gotMCP.Profile != client.ProfileMCP || gotMCP.ClientURI != "https://mcp-client.example" || len(gotMCP.Scopes) != 0 ||
		!slices.Equal(gotMCP.RedirectURIs, mcp.RedirectURIs) {
		t.Fatalf("mcp client round trip: %+v, %v", gotMCP, err)
	}
	if err := gotMCP.Validate(); err != nil {
		t.Fatalf("restored mcp client must validate: %v", err)
	}
}

// testClientList は ListClients の順序（ID のバイト列としての昇順）、キーセットページング、
// 削除後の一覧を確かめる。大文字と小文字、記号を混ぜるのは、ロケール依存の照合順序を使う
// データベースでも同じ順序になることを確かめるため。
func testClientList(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	ids := func(cs []*client.Client) []string {
		out := make([]string, 0, len(cs))
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	list := func(after string, limit int) []string {
		t.Helper()
		cs, err := s.ListClients(ctx, after, limit)
		if err != nil {
			t.Fatal(err)
		}
		if cs == nil {
			t.Fatal("ListClients must return an empty slice, not nil")
		}
		return ids(cs)
	}
	if got := list("", 10); len(got) != 0 {
		t.Fatalf("empty store: %v", got)
	}

	// 登録順は ID の順と変える。バイト列の昇順は "B" < "_x" < "a" < "b" < "c-1"。
	for _, id := range []string{"b", "_x", "c-1", "B", "a"} {
		if err := s.CreateClient(ctx, newWebClient(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"B", "_x", "a", "b", "c-1"}
	if got := list("", 10); !slices.Equal(got, want) {
		t.Fatalf("order: got %v, want %v", got, want)
	}
	// ページング: 最後の要素の ID を after に渡して続きを読む
	if got := list("", 2); !slices.Equal(got, want[:2]) {
		t.Fatalf("first page: got %v, want %v", got, want[:2])
	}
	if got := list("_x", 2); !slices.Equal(got, want[2:4]) {
		t.Fatalf("second page: got %v, want %v", got, want[2:4])
	}
	if got := list("b", 2); !slices.Equal(got, want[4:]) {
		t.Fatalf("last page: got %v, want %v", got, want[4:])
	}
	if got := list("c-1", 2); len(got) != 0 {
		t.Fatalf("past the end: %v", got)
	}
	// after は登録済みの ID でなくてもよい（途中で削除されても続きを読める）
	if got := list("a0", 10); !slices.Equal(got, want[3:]) {
		t.Fatalf("after a missing id: got %v, want %v", got, want[3:])
	}
	if got := list("", 0); len(got) != 0 {
		t.Fatalf("limit 0: %v", got)
	}

	// 内容は GetClient と同じものが戻る
	cs, err := s.ListClients(ctx, "", 1)
	if err != nil || len(cs) != 1 {
		t.Fatalf("list one: %v, %v", cs, err)
	}
	if err := cs[0].Validate(); err != nil {
		t.Fatalf("listed client must validate: %v", err)
	}
	// 削除した Client は一覧から消える
	if err := s.DeleteClient(ctx, "a", base); err != nil {
		t.Fatal(err)
	}
	if got := list("", 10); !slices.Equal(got, []string{"B", "_x", "b", "c-1"}) {
		t.Fatalf("after delete: %v", got)
	}
}

func testClientUpdate(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	c := newWebClient(t, "c1")
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetClient(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	p := cur.UpdateParams()
	p.Name = "Renamed"
	p.RedirectURIs = []string{"https://app.example.com/cb2", "https://app.example.com/cb3"}
	p.Scopes = []string{"openid"}
	p.Resources = nil // 制限なしに戻す
	p.AccessTokenTTL = 5 * time.Minute
	p.IDTokenAlg = client.AlgES256
	next, err := cur.Update(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateClient(ctx, next); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Renamed" || !slices.Equal(got.RedirectURIs, p.RedirectURIs) || !slices.Equal(got.Scopes, p.Scopes) ||
		len(got.Resources) != 0 || got.AccessTokenTTL != 5*time.Minute || got.IDTokenAlg != client.AlgES256 ||
		got.Profile != client.ProfileWeb || got.SecretHash != c.SecretHash || !got.CreatedAt.Equal(c.CreatedAt) {
		t.Fatalf("updated client mismatch:\n got %+v\nwant %+v", got, next)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("updated client must validate: %v", err)
	}

	// CreatedAt と SecretHash は保存済みの値が残る（別の時刻・別のシークレットで組み立てた同じ ID の
	// Client で置き換えても変わらない。シークレットを書き換えるのは RotateClientSecret だけ）
	later, _, err := client.NewWeb(client.WebParams{ID: "c1", Name: "Later", RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes: []string{"openid"}}, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if later.SecretHash == c.SecretHash {
		t.Fatal("fixture: the second client must have a different secret")
	}
	if err := s.UpdateClient(ctx, later); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetClient(ctx, "c1"); err != nil || got.Name != "Later" || !got.CreatedAt.Equal(c.CreatedAt) || got.SecretHash != c.SecretHash {
		t.Fatalf("created_at and secret_hash must be kept: %+v, %v", got, err)
	}

	// Profile の変更は拒否し、何も変えない（ADR-0004 §4）
	native, err := client.NewNative(client.NativeParams{ID: "c1", Name: "Native", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, base)
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.UpdateClient(ctx, native), storage.ErrStateConflict, "profile change")
	if got, err := s.GetClient(ctx, "c1"); err != nil || got.Profile != client.ProfileWeb || got.Name != "Later" || got.SecretHash != c.SecretHash {
		t.Fatalf("rejected update must not change the client: %+v, %v", got, err)
	}

	wantErr(t, s.UpdateClient(ctx, newWebClient(t, "missing")), storage.ErrNotFound, "update missing client")
	if _, err := s.GetClient(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("update must not create a client: %v", err)
	}
}

// testClientRotateSecret は RotateClientSecret がシークレットだけを置き換えること、public クライアントと
// 空のハッシュを拒否すること、再発行より前に読んだ Client を UpdateClient で保存しても旧シークレットが
// 戻らないことを確かめる。
func testClientRotateSecret(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	c, oldSecret, err := client.NewWeb(client.WebParams{ID: "c1", Name: "Web", RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes: []string{"openid"}, AccessTokenTTL: 5 * time.Minute}, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	// 再発行より前に読んだ値（後で「古い値の保存」に使う）
	stale, err := s.GetClient(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}

	next, newSecret, err := c.RotateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RotateClientSecret(ctx, "c1", next.SecretHash); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.VerifySecret(string(newSecret)) || got.VerifySecret(string(oldSecret)) {
		t.Fatal("after rotation only the new secret must verify")
	}
	// シークレット以外は変わらない
	if got.Name != c.Name || got.Profile != c.Profile || !slices.Equal(got.RedirectURIs, c.RedirectURIs) || !slices.Equal(got.Scopes, c.Scopes) ||
		got.AccessTokenTTL != c.AccessTokenTTL || got.IDTokenAlg != c.IDTokenAlg || !got.CreatedAt.Equal(c.CreatedAt) {
		t.Fatalf("rotation must change only the secret:\n got %+v\nwant %+v", got, c)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("rotated client must validate: %v", err)
	}

	// 古い値を基にした更新は、名前は変えるがシークレットは戻さない
	p := stale.UpdateParams()
	p.Name = "Renamed"
	renamed, err := stale.Update(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateClient(ctx, renamed); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetClient(ctx, "c1")
	if err != nil || got.Name != "Renamed" || !got.VerifySecret(string(newSecret)) || got.VerifySecret(string(oldSecret)) {
		t.Fatalf("a stale update must not bring the old secret back: %+v, %v", got, err)
	}

	// 空のハッシュは拒否し、何も変えない
	wantErr(t, s.RotateClientSecret(ctx, "c1", ""), storage.ErrStateConflict, "empty secret hash")
	if got, err := s.GetClient(ctx, "c1"); err != nil || !got.VerifySecret(string(newSecret)) {
		t.Fatalf("rejected rotation must not change the client: %+v, %v", got, err)
	}

	// public クライアントはシークレットを持たない
	native, err := client.NewNative(client.NativeParams{ID: "c-native", Name: "Native", RedirectURIs: []string{"http://127.0.0.1/cb"}, Scopes: []string{"openid"}}, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, native); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.RotateClientSecret(ctx, "c-native", next.SecretHash), storage.ErrStateConflict, "rotate public client")
	if got, err := s.GetClient(ctx, "c-native"); err != nil || got.SecretHash != "" {
		t.Fatalf("public client must stay without a secret: %+v, %v", got, err)
	}

	wantErr(t, s.RotateClientSecret(ctx, "missing", next.SecretHash), storage.ErrNotFound, "rotate missing client")
	if _, err := s.GetClient(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("rotation must not create a client: %v", err)
	}
}

func testClientDeleteCascades(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	if err := s.CreateClient(ctx, newWebClient(t, "c1")); err != nil {
		t.Fatal(err)
	}
	g, f, at, rt := seedGrantWithTokens(t, s, "1") // Client c1 の Grant
	code := newCode("h1", g.ID, "f-unused")
	if err := s.CreateAuthorizationCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	// 別 Client は巻き込まれない
	if err := s.CreateClient(ctx, newWebClient(t, "c9")); err != nil {
		t.Fatal(err)
	}
	_, _, atOther, _ := seedGrantWithTokens(t, s, "9")

	now := base.Add(time.Minute)
	if err := s.DeleteClient(ctx, "c1", now); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetClient(ctx, "c1")
	wantErr(t, err, storage.ErrNotFound, "deleted client")

	gg, err := s.GetGrant(ctx, g.ID)
	if err != nil || gg.Active() || !gg.RevokedAt.Equal(now) {
		t.Fatalf("grant must be revoked (and kept) with client: %+v, %v", gg, err)
	}
	tok, _, err := s.LookupAccessToken(ctx, at.Hash)
	if err != nil || tok.Status != token.AccessRevoked || !tok.RevokedAt.Equal(now) {
		t.Fatalf("access token must be revoked with client: %+v, %v", tok, err)
	}
	if fam, err := s.GetTokenFamily(ctx, f.ID); err != nil || fam.Active() {
		t.Fatalf("family must be revoked with client: %+v, %v", fam, err)
	}
	if r, err := s.LookupRefreshToken(ctx, rt.Hash); err != nil || r.Status != token.RefreshRevoked {
		t.Fatalf("refresh token must be revoked with client: %+v, %v", r, err)
	}
	wantErr(t, s.RotateRefreshToken(ctx, rt.Hash, newRefresh("rt-next", f.ID), newAccess("at-next", f.ID, g.ID), now),
		storage.ErrFamilyRevoked, "rotate after client delete")
	wantErr(t, s.IssueTokens(ctx, newFamily("f-new", g.ID), newAccess("at-new", "f-new", g.ID), nil),
		storage.ErrGrantRevoked, "issue after client delete")
	_, err = s.ConsumeAuthorizationCode(ctx, code.Hash, now)
	wantErr(t, err, storage.ErrNotFound, "code of deleted client")

	other, og, err := s.LookupAccessToken(ctx, atOther.Hash)
	if err != nil || other.Status != token.AccessActive || !og.Active() {
		t.Fatalf("other client must be untouched: %+v, %v", other, err)
	}

	// 物理削除なので同じ ID で作り直せる。失効済み Grant は同意をやり直すまで active に戻らない。
	wantErr(t, s.DeleteClient(ctx, "c1", now), storage.ErrNotFound, "delete twice")
	if err := s.CreateClient(ctx, newWebClient(t, "c1")); err != nil {
		t.Fatalf("re-create after delete: %v", err)
	}
	if gg, err := s.FindGrant(ctx, "c1", "alice"); err != nil || gg.Active() {
		t.Fatalf("grant must stay revoked after re-create: %+v, %v", gg, err)
	}

	// Client がなければ、同じ client_id の Grant が残っていても何も変えない
	ghost, err := s.UpsertGrant(ctx, newGrant("g-ghost", "ghost", "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.DeleteClient(ctx, "ghost", now), storage.ErrNotFound, "delete missing client")
	if gg, err := s.GetGrant(ctx, ghost.ID); err != nil || !gg.Active() {
		t.Fatalf("failed delete must not revoke grants: %+v, %v", gg, err)
	}
}

func testClientDeleteVersusIssue(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	if err := s.CreateClient(ctx, newWebClient(t, "c1")); err != nil {
		t.Fatal(err)
	}
	g, err := s.UpsertGrant(ctx, newGrant("g1", "c1", "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	// 競合: 削除と発行を同時に走らせる。発行が成功したなら、そのトークンは失効済みでなければならない。
	var wg sync.WaitGroup
	issueErrs := make(chan error, concurrency)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.DeleteClient(ctx, "c1", base); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fid := fmt.Sprint("f", i)
			issueErrs <- s.IssueTokens(ctx, newFamily(fid, g.ID), newAccess(fmt.Sprint("at", i), fid, g.ID), nil)
		}(i)
	}
	wg.Wait()
	close(issueErrs)
	for err := range issueErrs {
		if err != nil && !errors.Is(err, storage.ErrGrantRevoked) {
			t.Fatalf("unexpected issue error: %v", err)
		}
	}
	for i := 0; i < concurrency; i++ {
		tok, gg, err := s.LookupAccessToken(ctx, fmt.Sprint("at", i))
		if errors.Is(err, storage.ErrNotFound) {
			continue // 発行が負けた
		}
		if err != nil {
			t.Fatal(err)
		}
		if tok.Status != token.AccessRevoked || gg.Active() {
			t.Fatalf("token issued concurrently with client delete must end up revoked: %+v grant=%+v", tok, gg)
		}
	}
}

// --- transaction ---

func testTransaction(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	txn := newTxn("t1")
	if err := s.CreateTransaction(ctx, txn); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.CreateTransaction(ctx, txn), storage.ErrAlreadyExists, "duplicate txn")

	got, err := s.GetTransaction(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != authorization.StatusPending || got.Request.CodeChallenge != txn.Request.CodeChallenge ||
		!slices.Equal(got.Request.Scopes, txn.Request.Scopes) || !got.Request.HasMaxAge || got.Request.MaxAge != 300*time.Second ||
		!slices.Equal(got.Request.Prompt, []string{"login"}) || !got.ExpiresAt.Equal(txn.ExpiresAt) || got.BrowserBindingHash != "bind" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Outcome != nil || got.Rejection != nil || got.ResumeTokenHash != "" {
		t.Fatalf("pending txn must not carry outcome: %+v", got)
	}

	// 誤った from は ErrStateConflict
	wantErr(t, s.TransitionTransaction(ctx, "t1", authorization.StatusCompleted, authorization.StatusConsumed, authorization.Patch{}),
		storage.ErrStateConflict, "wrong from")
	// 不明な ID は ErrNotFound
	wantErr(t, s.TransitionTransaction(ctx, "nope", authorization.StatusPending, authorization.StatusCompleted, authorization.Patch{}),
		storage.ErrNotFound, "unknown txn")

	outcome := &authorization.Outcome{
		Subject: "alice", AuthenticatedAt: base, GrantedScopes: []string{"openid"},
		AMR: []string{"pwd"}, ACR: "urn:acr:1", Claims: map[string]any{"name": "Alice", "n": float64(1)},
	}
	if err := s.TransitionTransaction(ctx, "t1", authorization.StatusPending, authorization.StatusCompleted,
		authorization.Patch{Outcome: outcome, ResumeTokenHash: "rh"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTransaction(ctx, "t1")
	if got.Status != authorization.StatusCompleted || got.Outcome == nil || got.Outcome.Subject != "alice" ||
		got.Outcome.Claims["name"] != "Alice" || !slices.Equal(got.Outcome.AMR, []string{"pwd"}) || got.ResumeTokenHash != "rh" ||
		!got.Outcome.AuthenticatedAt.Equal(base) {
		t.Fatalf("after complete: %+v outcome=%+v", got, got.Outcome)
	}

	// 二重 Complete は ErrStateConflict
	wantErr(t, s.TransitionTransaction(ctx, "t1", authorization.StatusPending, authorization.StatusCompleted, authorization.Patch{}),
		storage.ErrStateConflict, "double complete")

	// completed → consumed。patch が空でも既存の Outcome は保持される
	if err := s.TransitionTransaction(ctx, "t1", authorization.StatusCompleted, authorization.StatusConsumed, authorization.Patch{}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTransaction(ctx, "t1")
	if got.Status != authorization.StatusConsumed || got.Outcome == nil || got.ResumeTokenHash != "rh" {
		t.Fatalf("after consume: %+v", got)
	}

	// Reject 経路
	t2 := newTxn("t2")
	if err := s.CreateTransaction(ctx, t2); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionTransaction(ctx, "t2", authorization.StatusPending, authorization.StatusRejected,
		authorization.Patch{Rejection: &authorization.Rejection{Error: "access_denied", Description: "no"}, ResumeTokenHash: "rh2"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTransaction(ctx, "t2")
	if got.Status != authorization.StatusRejected || got.Rejection == nil || got.Rejection.Error != "access_denied" || got.Outcome != nil {
		t.Fatalf("after reject: %+v rejection=%+v", got, got.Rejection)
	}
}

func testTransactionConcurrentComplete(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	if err := s.CreateTransaction(ctx, newTxn("t1")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- s.TransitionTransaction(ctx, "t1", authorization.StatusPending, authorization.StatusCompleted,
				authorization.Patch{Outcome: &authorization.Outcome{Subject: fmt.Sprint("user", i), AuthenticatedAt: base, GrantedScopes: []string{"openid"}}, ResumeTokenHash: fmt.Sprint("rh", i)})
		}(i)
	}
	wg.Wait()
	close(results)
	ok, conflicts := countOutcomes(t, results, storage.ErrStateConflict)
	if ok != 1 || conflicts != concurrency-1 {
		t.Fatalf("concurrent complete: %d succeeded, %d conflicted (want 1 / %d)", ok, conflicts, concurrency-1)
	}
	got, _ := s.GetTransaction(ctx, "t1")
	// 勝者の Outcome と ResumeTokenHash が揃っていること（部分適用がないこと）
	if got.Outcome == nil || fmt.Sprint("rh", got.Outcome.Subject[4:]) != got.ResumeTokenHash {
		t.Fatalf("torn write: outcome=%+v resume=%q", got.Outcome, got.ResumeTokenHash)
	}
}

func countOutcomes(t *testing.T, results <-chan error, expectedFailure error) (ok, expected int) {
	t.Helper()
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, expectedFailure):
			expected++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	return ok, expected
}

// --- authorization code ---

func testAuthorizationCode(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, err := s.UpsertGrant(ctx, newGrant("g1", "c1", "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	code := newCode("h1", g.ID, "f1")
	if err := s.CreateAuthorizationCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.CreateAuthorizationCode(ctx, code), storage.ErrAlreadyExists, "duplicate code")

	// 不明
	_, err = s.ConsumeAuthorizationCode(ctx, "unknown", base)
	wantErr(t, err, storage.ErrNotFound, "unknown code")

	// 期限切れは ErrNotFound（消費もされない）
	_, err = s.ConsumeAuthorizationCode(ctx, "h1", base.Add(time.Minute))
	wantErr(t, err, storage.ErrNotFound, "expired code")

	// 正常消費
	now := base.Add(10 * time.Second)
	got, err := s.ConsumeAuthorizationCode(ctx, "h1", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != "h1" || got.GrantID != g.ID || got.FamilyID != "f1" || got.Subject != "alice" ||
		!got.RedirectURIExplicit || got.Claims["name"] != "Alice" || !got.ConsumedAt.Equal(now) || !got.AuthenticatedAt.Equal(base) ||
		!slices.Equal(got.Resource, code.Resource) {
		t.Fatalf("consumed code mismatch: %+v", got)
	}

	// 再提示: ErrCodeAlreadyUsed と Code（FamilyID を失効に使う）
	again, err := s.ConsumeAuthorizationCode(ctx, "h1", now.Add(time.Second))
	wantErr(t, err, storage.ErrCodeAlreadyUsed, "reused code")
	if again == nil || again.FamilyID != "f1" || !again.ConsumedAt.Equal(now) {
		t.Fatalf("reused code must return the original record: %+v", again)
	}
	// 期限が過ぎた後の再提示も「消費済み」と判定できること（期限まで削除しない）
	_, err = s.ConsumeAuthorizationCode(ctx, "h1", base.Add(2*time.Minute))
	wantErr(t, err, storage.ErrCodeAlreadyUsed, "reused code after expiry")
}

func testCodeConcurrentConsume(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	if _, err := s.UpsertGrant(ctx, newGrant("g1", "c1", "alice", "openid")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthorizationCode(ctx, newCode("h1", "g1", "f1")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ConsumeAuthorizationCode(ctx, "h1", base.Add(time.Second))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok, used := countOutcomes(t, results, storage.ErrCodeAlreadyUsed)
	if ok != 1 || used != concurrency-1 {
		t.Fatalf("concurrent consume: %d succeeded, %d already-used (want 1 / %d)", ok, used, concurrency-1)
	}
}

// --- grant ---

func testGrant(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	_, err := s.FindGrant(ctx, "c1", "alice")
	wantErr(t, err, storage.ErrNotFound, "find before create")
	_, err = s.GetGrant(ctx, "g1")
	wantErr(t, err, storage.ErrNotFound, "get before create")

	g1, err := s.UpsertGrant(ctx, newGrant("g1", "c1", "alice", "openid", "profile"))
	if err != nil {
		t.Fatal(err)
	}
	if g1.ID != "g1" || !g1.Active() || !slices.Equal(g1.Scopes, []string{"openid", "profile"}) {
		t.Fatalf("first upsert: %+v", g1)
	}

	// 同じ client × subject への再同意: ID は保たれ、scope は和集合、Claims は置換
	cand := newGrant("g1-new", "c1", "alice", "email", "openid")
	cand.Claims = map[string]any{"name": "Alice B"}
	cand.UpdatedAt = base.Add(time.Hour)
	g2, err := s.UpsertGrant(ctx, cand)
	if err != nil {
		t.Fatal(err)
	}
	if g2.ID != "g1" || !slices.Equal(g2.Scopes, []string{"openid", "profile", "email"}) || g2.Claims["name"] != "Alice B" ||
		!g2.UpdatedAt.Equal(base.Add(time.Hour)) || !g2.CreatedAt.Equal(base) {
		t.Fatalf("merged upsert: %+v", g2)
	}
	found, err := s.FindGrant(ctx, "c1", "alice")
	if err != nil || found.ID != "g1" || !slices.Equal(found.Scopes, g2.Scopes) {
		t.Fatalf("find: %+v, %v", found, err)
	}
	// 候補の ID "g1-new" は使われていない
	_, err = s.GetGrant(ctx, "g1-new")
	wantErr(t, err, storage.ErrNotFound, "candidate id must not be created")

	// 別 client は別 Grant
	g3, err := s.UpsertGrant(ctx, newGrant("g3", "c2", "alice", "openid"))
	if err != nil || g3.ID != "g3" {
		t.Fatalf("other client: %+v, %v", g3, err)
	}
	// subject による一覧は CreatedAt 昇順（同時刻は ID 順）で、他の subject を含まない
	if _, err := s.UpsertGrant(ctx, newGrant("g4", "c1", "bob", "openid")); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListGrantsBySubject(ctx, "alice")
	if err != nil || len(list) != 2 || list[0].ID != "g1" || list[1].ID != "g3" || list[0].Claims["name"] != "Alice B" {
		t.Fatalf("list by subject: %+v, %v", list, err)
	}
	if empty, err := s.ListGrantsBySubject(ctx, "nobody"); err != nil || len(empty) != 0 {
		t.Fatalf("list unknown subject: %+v, %v", empty, err)
	}

	// 失効と再同意（revive）
	if err := s.RevokeGrant(ctx, "g1", base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetGrant(ctx, "g1")
	if got.Active() || !got.RevokedAt.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("after revoke: %+v", got)
	}
	if err := s.RevokeGrant(ctx, "g1", base.Add(3*time.Hour)); err != nil {
		t.Fatalf("revoke twice must be idempotent: %v", err)
	}
	wantErr(t, s.RevokeGrant(ctx, "nope", base), storage.ErrNotFound, "revoke unknown")

	// 失効済みも一覧に含まれる（呼び出し側が Status で絞る）
	list, _ = s.ListGrantsBySubject(ctx, "alice")
	if len(list) != 2 || list[0].Active() || !list[1].Active() {
		t.Fatalf("list must include revoked grants: %+v", list)
	}

	revived, err := s.UpsertGrant(ctx, newGrant("g1-again", "c1", "alice", "email"))
	if err != nil {
		t.Fatal(err)
	}
	if revived.ID != "g1" || !revived.Active() || !slices.Equal(revived.Scopes, []string{"email"}) || !revived.RevokedAt.IsZero() {
		t.Fatalf("revived grant must drop old scopes and clear revocation: %+v", revived)
	}
}

// testGrantListByClient は ListGrantsByClient の順序（Subject のバイト列としての昇順）、キーセットページング、
// 他の Client を含まないこと、失効済みも含むことを確かめる。Subject の選び方は testClientList と同じ理由。
func testGrantListByClient(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	list := func(clientID, after string, limit int) []string {
		t.Helper()
		gs, err := s.ListGrantsByClient(ctx, clientID, after, limit)
		if err != nil {
			t.Fatal(err)
		}
		if gs == nil {
			t.Fatal("ListGrantsByClient must return an empty slice, not nil")
		}
		out := make([]string, 0, len(gs))
		for _, g := range gs {
			if g.ClientID != clientID {
				t.Fatalf("grant of another client in the list: %+v", g)
			}
			out = append(out, g.Subject)
		}
		return out
	}
	if got := list("c1", "", 10); len(got) != 0 {
		t.Fatalf("empty store: %v", got)
	}

	// 作成順は Subject の順と変える。バイト列の昇順は "B" < "_x" < "a" < "b" < "c-1"。
	for i, sub := range []string{"b", "_x", "c-1", "B", "a"} {
		if _, err := s.UpsertGrant(ctx, newGrant(fmt.Sprintf("g%d", i), "c1", sub, "openid")); err != nil {
			t.Fatal(err)
		}
	}
	// 同じ Subject でも他の Client の Grant は含めない
	if _, err := s.UpsertGrant(ctx, newGrant("g-other", "c2", "a", "openid")); err != nil {
		t.Fatal(err)
	}
	want := []string{"B", "_x", "a", "b", "c-1"}
	if got := list("c1", "", 10); !slices.Equal(got, want) {
		t.Fatalf("order: got %v, want %v", got, want)
	}
	if got := list("c1", "", 2); !slices.Equal(got, want[:2]) {
		t.Fatalf("first page: got %v, want %v", got, want[:2])
	}
	if got := list("c1", "_x", 2); !slices.Equal(got, want[2:4]) {
		t.Fatalf("second page: got %v, want %v", got, want[2:4])
	}
	if got := list("c1", "b", 2); !slices.Equal(got, want[4:]) {
		t.Fatalf("last page: got %v, want %v", got, want[4:])
	}
	if got := list("c1", "c-1", 2); len(got) != 0 {
		t.Fatalf("past the end: %v", got)
	}
	// after は存在する Subject でなくてもよい
	if got := list("c1", "a0", 10); !slices.Equal(got, want[3:]) {
		t.Fatalf("after a missing subject: got %v, want %v", got, want[3:])
	}
	if got := list("c1", "", 0); len(got) != 0 {
		t.Fatalf("limit 0: %v", got)
	}
	if got := list("c2", "", 10); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("other client: %v", got)
	}
	if got := list("nobody", "", 10); len(got) != 0 {
		t.Fatalf("unknown client: %v", got)
	}

	// 失効済みも含み、内容は GetGrant と同じものが戻る
	if err := s.RevokeGrant(ctx, "g4", base.Add(time.Hour)); err != nil { // Subject "a"
		t.Fatal(err)
	}
	gs, err := s.ListGrantsByClient(ctx, "c1", "_x", 1)
	if err != nil || len(gs) != 1 {
		t.Fatalf("list one: %+v, %v", gs, err)
	}
	if g := gs[0]; g.ID != "g4" || g.Active() || !g.RevokedAt.Equal(base.Add(time.Hour)) || !slices.Equal(g.Scopes, []string{"openid"}) ||
		g.Claims["name"] != "Alice" || !g.CreatedAt.Equal(base) {
		t.Fatalf("listed grant must carry the stored content, including revocation: %+v", g)
	}
	if got := list("c1", "", 10); !slices.Equal(got, want) {
		t.Fatalf("revoked grants must stay in the list: %v", got)
	}
}

func testGrantRevokeCascades(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, f, at, rt := seedGrantWithTokens(t, s, "1")
	// 同じ Grant の別 Family も巻き込まれる
	f2 := newFamily("f2", g.ID)
	at2 := newAccess("at2", f2.ID, g.ID)
	if err := s.IssueTokens(ctx, f2, at2, nil); err != nil {
		t.Fatal(err)
	}
	// 別 Grant は巻き込まれない
	_, _, atOther, _ := seedGrantWithTokens(t, s, "9")

	now := base.Add(time.Minute)
	if err := s.RevokeGrant(ctx, g.ID, now); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{at.Hash, at2.Hash} {
		tok, gg, err := s.LookupAccessToken(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Status != token.AccessRevoked || !tok.RevokedAt.Equal(now) || gg.Active() {
			t.Fatalf("access %s must be revoked with grant: tok=%+v grant=%+v", h, tok, gg)
		}
	}
	r, err := s.LookupRefreshToken(ctx, rt.Hash)
	if err != nil || r.Status != token.RefreshRevoked {
		t.Fatalf("refresh must be revoked: %+v, %v", r, err)
	}
	// 失効済み Family では Rotation できない
	wantErr(t, s.RotateRefreshToken(ctx, rt.Hash, newRefresh("rt-next", f.ID), newAccess("at-next", f.ID, g.ID), now),
		storage.ErrFamilyRevoked, "rotate after grant revoke")

	other, og, err := s.LookupAccessToken(ctx, atOther.Hash)
	if err != nil || other.Status != token.AccessActive || !og.Active() {
		t.Fatalf("other grant must be untouched: %+v, %v", other, err)
	}
}

// --- tokens ---

func testIssueTokens(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, f, at, rt := seedGrantWithTokens(t, s, "1")

	gotAT, gotG, err := s.LookupAccessToken(ctx, at.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if gotAT.FamilyID != f.ID || gotAT.GrantID != g.ID || gotAT.Status != token.AccessActive || !slices.Equal(gotAT.Audience, at.Audience) ||
		!gotAT.ExpiresAt.Equal(at.ExpiresAt) || gotG.ID != g.ID || !gotG.Active() {
		t.Fatalf("lookup access: %+v grant=%+v", gotAT, gotG)
	}
	gotRT, err := s.LookupRefreshToken(ctx, rt.Hash)
	if err != nil || gotRT.FamilyID != f.ID || gotRT.Status != token.RefreshActive {
		t.Fatalf("lookup refresh: %+v, %v", gotRT, err)
	}
	_, _, err = s.LookupAccessToken(ctx, "nope")
	wantErr(t, err, storage.ErrNotFound, "unknown access")
	_, err = s.LookupRefreshToken(ctx, "nope")
	wantErr(t, err, storage.ErrNotFound, "unknown refresh")
	gotF, err := s.GetTokenFamily(ctx, f.ID)
	if err != nil || gotF.GrantID != g.ID || gotF.ClientID != "c1" || gotF.Subject != "alice" || !slices.Equal(gotF.Scopes, f.Scopes) ||
		!slices.Equal(gotF.Audience, f.Audience) || !gotF.AuthenticatedAt.Equal(f.AuthenticatedAt) || !slices.Equal(gotF.AMR, f.AMR) || gotF.ACR != f.ACR ||
		!gotF.ExpiresAt.Equal(f.ExpiresAt) || !gotF.Active() {
		t.Fatalf("get family: %+v, %v", gotF, err)
	}
	_, err = s.GetTokenFamily(ctx, "nope")
	wantErr(t, err, storage.ErrNotFound, "unknown family")

	// Refresh なし、Audience なし（resource なしの要求）でも発行でき、Audience は空のまま戻る
	f2 := newFamily("f2", g.ID)
	f2.Audience = nil
	at2 := newAccess("at2", f2.ID, g.ID)
	at2.Audience = nil
	if err := s.IssueTokens(ctx, f2, at2, nil); err != nil {
		t.Fatal(err)
	}
	if gotF2, err := s.GetTokenFamily(ctx, f2.ID); err != nil || len(gotF2.Audience) != 0 {
		t.Fatalf("family without audience: %+v, %v", gotF2, err)
	}
	if gotAT2, _, err := s.LookupAccessToken(ctx, "at2"); err != nil || len(gotAT2.Audience) != 0 {
		t.Fatalf("access token without audience: %+v, %v", gotAT2, err)
	}
	// Family ID の重複
	wantErr(t, s.IssueTokens(ctx, newFamily("f2", g.ID), newAccess("at3", "f2", g.ID), nil), storage.ErrAlreadyExists, "duplicate family")

	// 存在しない Grant / 失効 Grant への発行は ErrGrantRevoked で、何も保存されない
	f3 := newFamily("f3", "no-such-grant")
	wantErr(t, s.IssueTokens(ctx, f3, newAccess("at4", f3.ID, f3.GrantID), nil), storage.ErrGrantRevoked, "issue for missing grant")
	if err := s.RevokeGrant(ctx, g.ID, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	f4 := newFamily("f4", g.ID)
	wantErr(t, s.IssueTokens(ctx, f4, newAccess("at5", f4.ID, g.ID), newRefresh("rt5", f4.ID)), storage.ErrGrantRevoked, "issue for revoked grant")
	_, _, err = s.LookupAccessToken(ctx, "at5")
	wantErr(t, err, storage.ErrNotFound, "rejected issue must not store access token")
	_, err = s.LookupRefreshToken(ctx, "rt5")
	wantErr(t, err, storage.ErrNotFound, "rejected issue must not store refresh token")
}

func testRotateRefreshToken(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, f, _, rt := seedGrantWithTokens(t, s, "1")
	now := base.Add(time.Minute)

	wantErr(t, s.RotateRefreshToken(ctx, "nope", newRefresh("x", f.ID), newAccess("y", f.ID, g.ID), now), storage.ErrNotFound, "rotate unknown")
	wantErr(t, s.RotateRefreshToken(ctx, rt.Hash, newRefresh("x", f.ID), newAccess("y", f.ID, g.ID), rt.ExpiresAt), storage.ErrNotFound, "rotate expired")

	next := newRefresh("rt-2", f.ID)
	at2 := newAccess("at-2", f.ID, g.ID)
	if err := s.RotateRefreshToken(ctx, rt.Hash, next, at2, now); err != nil {
		t.Fatal(err)
	}
	old, _ := s.LookupRefreshToken(ctx, rt.Hash)
	if old.Status != token.RefreshRotated || old.ReplacedByHash != "rt-2" || !old.RotatedAt.Equal(now) {
		t.Fatalf("old after rotate: %+v", old)
	}
	got2, err := s.LookupRefreshToken(ctx, "rt-2")
	if err != nil || got2.Status != token.RefreshActive || got2.FamilyID != f.ID {
		t.Fatalf("next after rotate: %+v, %v", got2, err)
	}
	gotAT, _, err := s.LookupAccessToken(ctx, "at-2")
	if err != nil || gotAT.Status != token.AccessActive || !slices.Equal(gotAT.Audience, at2.Audience) {
		t.Fatalf("access after rotate: %+v, %v", gotAT, err)
	}

	// 旧トークンの再提示 → ErrTokenReused（Family の失効は呼び出し側）
	wantErr(t, s.RotateRefreshToken(ctx, rt.Hash, newRefresh("rt-3", f.ID), newAccess("at-3", f.ID, g.ID), now.Add(time.Second)),
		storage.ErrTokenReused, "reuse old")
	_, err = s.LookupRefreshToken(ctx, "rt-3")
	wantErr(t, err, storage.ErrNotFound, "failed rotate must not store next")

	// Family 失効後は ErrFamilyRevoked
	if err := s.RevokeTokenFamily(ctx, f.ID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.RotateRefreshToken(ctx, "rt-2", newRefresh("rt-4", f.ID), newAccess("at-4", f.ID, g.ID), now.Add(3*time.Second)),
		storage.ErrFamilyRevoked, "rotate in revoked family")
}

func testRotateConcurrent(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, f, _, rt := seedGrantWithTokens(t, s, "1")
	var wg sync.WaitGroup
	results := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- s.RotateRefreshToken(ctx, rt.Hash, newRefresh(fmt.Sprint("next", i), f.ID), newAccess(fmt.Sprint("rot-at", i), f.ID, g.ID), base.Add(time.Second))
		}(i)
	}
	wg.Wait()
	close(results)
	ok, reused := countOutcomes(t, results, storage.ErrTokenReused)
	if ok != 1 || reused != concurrency-1 {
		t.Fatalf("concurrent rotate: %d succeeded, %d reused (want 1 / %d)", ok, reused, concurrency-1)
	}
	// 後継は勝者の 1 本だけ
	active := 0
	for i := 0; i < concurrency; i++ {
		if _, err := s.LookupRefreshToken(ctx, fmt.Sprint("next", i)); err == nil {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("want exactly 1 successor, got %d", active)
	}
}

func testRevokeGrantVersusIssue(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, err := s.UpsertGrant(ctx, newGrant("g1", "c1", "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	// 失効後の発行は必ず失敗する（直列）
	if err := s.RevokeGrant(ctx, g.ID, base); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.IssueTokens(ctx, newFamily("f0", g.ID), newAccess("at0", "f0", g.ID), nil), storage.ErrGrantRevoked, "issue after revoke")

	// 競合: 失効と発行を同時に走らせる。発行が成功したなら、そのトークンは失効済みでなければならない。
	g2, err := s.UpsertGrant(ctx, newGrant("g2", "c2", "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	issueErrs := make(chan error, concurrency)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.RevokeGrant(ctx, g2.ID, base); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fid := fmt.Sprint("f", i)
			issueErrs <- s.IssueTokens(ctx, newFamily(fid, g2.ID), newAccess(fmt.Sprint("at", i), fid, g2.ID), nil)
		}(i)
	}
	wg.Wait()
	close(issueErrs)
	for err := range issueErrs {
		if err != nil && !errors.Is(err, storage.ErrGrantRevoked) {
			t.Fatalf("unexpected issue error: %v", err)
		}
	}
	for i := 0; i < concurrency; i++ {
		tok, gg, err := s.LookupAccessToken(ctx, fmt.Sprint("at", i))
		if errors.Is(err, storage.ErrNotFound) {
			continue // 発行が負けた
		}
		if err != nil {
			t.Fatal(err)
		}
		if tok.Status != token.AccessRevoked || gg.Active() {
			t.Fatalf("token issued concurrently with revoke must end up revoked: %+v grant=%+v", tok, gg)
		}
	}
}

// testRotateVersusRevoke は、Rotation と失効（Grant、Token Family、Client の削除）を同時に走らせる。
//
// どちらが先になってもよいが、終わった時点で失効は全トークンに及んでいなければならない。
// Rotation が成功したなら、その後継の Refresh Token と新しい Access Token も失効していること
// （失効の UPDATE が、同時に挿入された行を取りこぼさないこと）。どちらの操作も、センチネル以外の
// エラー（デッドロックなど）で失敗してはならない。競合は確率的なので回数を重ねる。
func testRotateVersusRevoke(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	const rounds = 20
	revokers := []struct {
		name   string
		revoke func(g *grant.Grant, f *token.Family) error
	}{
		{"grant", func(g *grant.Grant, _ *token.Family) error { return s.RevokeGrant(ctx, g.ID, base) }},
		{"family", func(_ *grant.Grant, f *token.Family) error { return s.RevokeTokenFamily(ctx, f.ID, base) }},
		{"client", func(g *grant.Grant, _ *token.Family) error { return s.DeleteClient(ctx, g.ClientID, base) }},
	}
	for _, rv := range revokers {
		for i := 0; i < rounds; i++ {
			suffix := fmt.Sprintf("-%s-%d", rv.name, i)
			if err := s.CreateClient(ctx, newWebClient(t, "c"+suffix)); err != nil {
				t.Fatal(err)
			}
			g, f, _, rt := seedGrantWithTokens(t, s, suffix)
			next, access := newRefresh("rt2"+suffix, f.ID), newAccess("at2"+suffix, f.ID, g.ID)

			var (
				wg                   sync.WaitGroup
				rotateErr, revokeErr error
				start                = make(chan struct{})
			)
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				rotateErr = s.RotateRefreshToken(ctx, rt.Hash, next, access, base)
			}()
			go func() {
				defer wg.Done()
				<-start
				revokeErr = rv.revoke(g, f)
			}()
			close(start)
			wg.Wait()

			if revokeErr != nil {
				t.Fatalf("%s round %d: revoke failed: %v", rv.name, i, revokeErr)
			}
			if rotateErr != nil && !errors.Is(rotateErr, storage.ErrFamilyRevoked) && !errors.Is(rotateErr, storage.ErrGrantRevoked) {
				t.Fatalf("%s round %d: unexpected rotate error: %v", rv.name, i, rotateErr)
			}
			// Rotation の勝ち負けに関わらず、後継と新しい Access Token が有効なまま残っていてはならない
			if got, err := s.LookupRefreshToken(ctx, next.Hash); err == nil && got.Status == token.RefreshActive {
				t.Fatalf("%s round %d: successor refresh token survived the revocation (rotate err = %v)", rv.name, i, rotateErr)
			} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
				t.Fatal(err)
			}
			if got, _, err := s.LookupAccessToken(ctx, access.Hash); err == nil && got.Status == token.AccessActive {
				t.Fatalf("%s round %d: access token issued by the rotation survived the revocation (rotate err = %v)", rv.name, i, rotateErr)
			} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
				t.Fatal(err)
			}
			if fam, err := s.GetTokenFamily(ctx, f.ID); err != nil || fam.Active() {
				t.Fatalf("%s round %d: family must be revoked: %+v, %v", rv.name, i, fam, err)
			}
		}
	}
}

func testRevokeTokenFamily(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, f, at, rt := seedGrantWithTokens(t, s, "1")
	f2 := newFamily("f2", g.ID)
	at2 := newAccess("at2", f2.ID, g.ID)
	if err := s.IssueTokens(ctx, f2, at2, nil); err != nil {
		t.Fatal(err)
	}
	now := base.Add(time.Minute)
	wantErr(t, s.RevokeTokenFamily(ctx, "nope", now), storage.ErrNotFound, "revoke unknown family")
	if err := s.RevokeTokenFamily(ctx, f.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeTokenFamily(ctx, f.ID, now.Add(time.Second)); err != nil {
		t.Fatalf("revoke twice must be idempotent: %v", err)
	}
	tok, gg, _ := s.LookupAccessToken(ctx, at.Hash)
	if tok.Status != token.AccessRevoked || !tok.RevokedAt.Equal(now) {
		t.Fatalf("access in family must be revoked: %+v", tok)
	}
	if !gg.Active() {
		t.Fatalf("family revoke must not revoke the grant: %+v", gg)
	}
	if fam, err := s.GetTokenFamily(ctx, f.ID); err != nil || fam.Active() || !fam.RevokedAt.Equal(now) {
		t.Fatalf("family must be revoked: %+v, %v", fam, err)
	}
	r, _ := s.LookupRefreshToken(ctx, rt.Hash)
	if r.Status != token.RefreshRevoked {
		t.Fatalf("refresh in family must be revoked: %+v", r)
	}
	other, _, _ := s.LookupAccessToken(ctx, at2.Hash)
	if other.Status != token.AccessActive {
		t.Fatalf("other family must be untouched: %+v", other)
	}
}

func testRevokeAccessToken(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	_, _, at, rt := seedGrantWithTokens(t, s, "1")
	now := base.Add(time.Minute)
	wantErr(t, s.RevokeAccessToken(ctx, "nope", now), storage.ErrNotFound, "revoke unknown access")
	if err := s.RevokeAccessToken(ctx, at.Hash, now); err != nil {
		t.Fatal(err)
	}
	tok, _, _ := s.LookupAccessToken(ctx, at.Hash)
	if tok.Status != token.AccessRevoked || !tok.RevokedAt.Equal(now) || tok.Valid(now) {
		t.Fatalf("access must be revoked: %+v", tok)
	}
	r, _ := s.LookupRefreshToken(ctx, rt.Hash)
	if r.Status != token.RefreshActive {
		t.Fatalf("revoking an access token must not touch the refresh token: %+v", r)
	}
}

// --- purge ---

func testPurge(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	g, err := s.UpsertGrant(ctx, newGrant("g1", "c1", "alice", "openid"))
	if err != nil {
		t.Fatal(err)
	}
	// 期限切れ: txn-old, code-old, at-old, rt-old。有効: txn-new, code-new, at-new, rt-new
	old := newTxn("txn-old")
	old.ExpiresAt = base.Add(time.Minute)
	fresh := newTxn("txn-new")
	fresh.ExpiresAt = base.Add(time.Hour)
	for _, txn := range []*authorization.Transaction{old, fresh} {
		if err := s.CreateTransaction(ctx, txn); err != nil {
			t.Fatal(err)
		}
	}
	codeOld := newCode("code-old", g.ID, "f1")
	codeOld.ExpiresAt = base.Add(time.Minute)
	codeNew := newCode("code-new", g.ID, "f1")
	codeNew.ExpiresAt = base.Add(time.Hour)
	for _, c := range []*authorization.AuthorizationCode{codeOld, codeNew} {
		if err := s.CreateAuthorizationCode(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	f := newFamily("f1", g.ID)
	atOld := newAccess("at-old", f.ID, g.ID)
	atOld.ExpiresAt = base.Add(time.Minute)
	rtOld := newRefresh("rt-old", f.ID)
	rtOld.ExpiresAt = base.Add(time.Minute)
	if err := s.IssueTokens(ctx, f, atOld, rtOld); err != nil {
		t.Fatal(err)
	}
	f2 := newFamily("f2", g.ID)
	atNew := newAccess("at-new", f2.ID, g.ID)
	atNew.ExpiresAt = base.Add(time.Hour)
	rtNew := newRefresh("rt-new", f2.ID)
	rtNew.ExpiresAt = base.Add(time.Hour)
	if err := s.IssueTokens(ctx, f2, atNew, rtNew); err != nil {
		t.Fatal(err)
	}

	if err := s.Purge(ctx, base.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetTransaction(ctx, "txn-old")
	wantErr(t, err, storage.ErrNotFound, "purged txn")
	if _, err := s.GetTransaction(ctx, "txn-new"); err != nil {
		t.Fatalf("live txn must survive: %v", err)
	}
	_, err = s.ConsumeAuthorizationCode(ctx, "code-old", base.Add(31*time.Minute))
	wantErr(t, err, storage.ErrNotFound, "purged code")
	if _, err := s.ConsumeAuthorizationCode(ctx, "code-new", base.Add(31*time.Minute)); err != nil {
		t.Fatalf("live code must survive: %v", err)
	}
	_, _, err = s.LookupAccessToken(ctx, "at-old")
	wantErr(t, err, storage.ErrNotFound, "purged access")
	if _, _, err := s.LookupAccessToken(ctx, "at-new"); err != nil {
		t.Fatalf("live access must survive: %v", err)
	}
	_, err = s.LookupRefreshToken(ctx, "rt-old")
	wantErr(t, err, storage.ErrNotFound, "purged refresh")
	if _, err := s.LookupRefreshToken(ctx, "rt-new"); err != nil {
		t.Fatalf("live refresh must survive: %v", err)
	}
	if _, err := s.GetGrant(ctx, g.ID); err != nil {
		t.Fatalf("grant must survive purge: %v", err)
	}
}

// testPurgeChildlessParents は、子のなくなった親の削除（ADR-0005 §7）を確かめる。
// トークンのない Token Family と、Family のない失効済みの Grant が、トークンと同じ 1 回の Purge で消える。
func testPurgeChildlessParents(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	short, long := base.Add(time.Minute), base.Add(time.Hour)

	upsert := func(id, clientID string) *grant.Grant {
		t.Helper()
		g, err := s.UpsertGrant(ctx, newGrant(id, clientID, "alice", "openid"))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	// issue は g の下に Family を作る。refreshExpires がゼロ値なら Refresh Token を発行しない
	// （client_credentials の Family と同じ形）。
	issue := func(g *grant.Grant, familyID string, accessExpires, refreshExpires time.Time) {
		t.Helper()
		at := newAccess("at-"+familyID, familyID, g.ID)
		at.ExpiresAt = accessExpires
		var rt *token.RefreshToken
		if !refreshExpires.IsZero() {
			rt = newRefresh("rt-"+familyID, familyID)
			rt.ExpiresAt = refreshExpires
		}
		if err := s.IssueTokens(ctx, newFamily(familyID, g.ID), at, rt); err != nil {
			t.Fatal(err)
		}
	}
	wantFamily := func(id string, exists bool) {
		t.Helper()
		_, err := s.GetTokenFamily(ctx, id)
		if exists && err != nil {
			t.Fatalf("family %s must survive: %v", id, err)
		}
		if !exists {
			wantErr(t, err, storage.ErrNotFound, "purged family "+id)
		}
	}
	wantGrant := func(g *grant.Grant, exists bool) {
		t.Helper()
		_, err := s.GetGrant(ctx, g.ID)
		_, findErr := s.FindGrant(ctx, g.ClientID, g.Subject)
		if exists && (err != nil || findErr != nil) {
			t.Fatalf("grant %s must survive: %v / %v", g.ID, err, findErr)
		}
		if !exists {
			wantErr(t, err, storage.ErrNotFound, "purged grant "+g.ID)
			wantErr(t, findErr, storage.ErrNotFound, "purged grant "+g.ID+" by client and subject")
		}
	}

	// active な Grant: Family だけが消え、Grant は Family が 0 件になっても残る
	active := upsert("g-active", "c-active")
	issue(active, "f-expired", short, short)     // 全トークンが期限切れ → 消える
	issue(active, "f-m2m", short, time.Time{})   // Refresh Token なし、期限切れ → 消える
	issue(active, "f-live-refresh", short, long) // Refresh Token が残る → 残る
	issue(active, "f-revoked", long, long)       // 失効済みだがトークンの行が残る → 残る
	if err := s.RevokeTokenFamily(ctx, "f-revoked", base); err != nil {
		t.Fatal(err)
	}
	lonely := upsert("g-lonely", "c-lonely")
	issue(lonely, "f-lonely", short, short)

	// 失効済みの Grant: Family が残っている間は残り、なくなれば消える
	revokedLive := upsert("g-revoked-live", "c-revoked-live")
	issue(revokedLive, "f-revoked-live", long, long)
	revokedDone := upsert("g-revoked-done", "c-revoked-done")
	issue(revokedDone, "f-revoked-done", short, short)
	for _, g := range []*grant.Grant{revokedLive, revokedDone} {
		if err := s.RevokeGrant(ctx, g.ID, base); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.Purge(ctx, base.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	wantFamily("f-expired", false)
	wantFamily("f-m2m", false)
	wantFamily("f-live-refresh", true)
	wantFamily("f-revoked", true)
	wantFamily("f-lonely", false)
	wantFamily("f-revoked-live", true)
	wantFamily("f-revoked-done", false)
	wantGrant(active, true)
	wantGrant(lonely, true) // active な Grant は同意の記録。Family がなくても残る
	wantGrant(revokedLive, true)
	wantGrant(revokedDone, false) // トークン → Family → Grant が 1 回の Purge で消える
	if fam, err := s.GetTokenFamily(ctx, "f-revoked"); err != nil || fam.Active() {
		t.Fatalf("revoked family must stay revoked while its tokens remain: %+v, %v", fam, err)
	}
	if g, err := s.GetGrant(ctx, revokedLive.ID); err != nil || g.Active() {
		t.Fatalf("revoked grant must stay revoked while its families remain: %+v, %v", g, err)
	}
	if rt, err := s.LookupRefreshToken(ctx, "rt-f-live-refresh"); err != nil || rt.Status != token.RefreshActive {
		t.Fatalf("live refresh token must survive: %+v, %v", rt, err)
	}
	list, err := s.ListGrantsBySubject(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range list {
		if g.ID == revokedDone.ID {
			t.Fatal("purged grant must not be listed")
		}
	}

	// 消えた Grant と同じ Client × subject の再同意は、新しい ID の Grant になる
	again, err := s.UpsertGrant(ctx, newGrant("g-revoked-done-2", revokedDone.ClientID, revokedDone.Subject, "openid"))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != "g-revoked-done-2" || !again.Active() {
		t.Fatalf("re-consent after purge must create a fresh grant: %+v", again)
	}
	// 消えた Grant の ID では発行できない（失効前に発行された Code が後から交換された場合）
	stale := newAccess("at-stale", "f-stale", revokedDone.ID)
	wantErr(t, s.IssueTokens(ctx, newFamily("f-stale", revokedDone.ID), stale, nil), storage.ErrGrantRevoked, "issue under a purged grant")
	issue(again, "f-again", long, long)

	// 残りのトークンの期限も過ぎれば、残っていた Family と失効済みの Grant も消える
	if err := s.Purge(ctx, base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"f-live-refresh", "f-revoked", "f-revoked-live", "f-again"} {
		wantFamily(id, false)
	}
	wantGrant(active, true)
	wantGrant(lonely, true)
	wantGrant(again, true)
	wantGrant(revokedLive, false)
}

// testPurgeVersusRotate は、期限の境目で Rotation と Purge が同時に走っても、どちらも失敗せず、
// 後継のトークンが親（Token Family）のないまま残らないことを確かめる。
//
// Rotation の時刻では旧トークンは期限内、Purge の時刻では期限切れにして、両方が同じ行を取り合う
// 状況を作る。Rotation が勝てば後継が残るので Family は消えない。Purge が勝てば旧トークンごと消え、
// Rotation は ErrNotFound になる。
func testPurgeVersusRotate(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	const rounds = 20
	for i := 0; i < rounds; i++ {
		suffix := fmt.Sprintf("-purge-rotate-%d", i)
		g, err := s.UpsertGrant(ctx, newGrant("g"+suffix, "c"+suffix, "alice", "openid"))
		if err != nil {
			t.Fatal(err)
		}
		f := newFamily("f"+suffix, g.ID)
		at, rt := newAccess("at"+suffix, f.ID, g.ID), newRefresh("rt"+suffix, f.ID)
		at.ExpiresAt, rt.ExpiresAt = base.Add(time.Minute), base.Add(time.Minute)
		if err := s.IssueTokens(ctx, f, at, rt); err != nil {
			t.Fatal(err)
		}
		// 後継と新しい Access Token は Purge の時刻でも期限内
		next, access := newRefresh("rt2"+suffix, f.ID), newAccess("at2"+suffix, f.ID, g.ID)

		var (
			wg                  sync.WaitGroup
			rotateErr, purgeErr error
			start               = make(chan struct{})
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			rotateErr = s.RotateRefreshToken(ctx, rt.Hash, next, access, base)
		}()
		go func() {
			defer wg.Done()
			<-start
			purgeErr = s.Purge(ctx, base.Add(30*time.Minute))
		}()
		close(start)
		wg.Wait()

		if purgeErr != nil {
			t.Fatalf("round %d: purge failed: %v", i, purgeErr)
		}
		if rotateErr != nil && !errors.Is(rotateErr, storage.ErrNotFound) {
			t.Fatalf("round %d: unexpected rotate error: %v", i, rotateErr)
		}
		_, nextErr := s.LookupRefreshToken(ctx, next.Hash)
		_, _, accessErr := s.LookupAccessToken(ctx, access.Hash)
		_, familyErr := s.GetTokenFamily(ctx, f.ID)
		if rotateErr == nil {
			// Rotation が成立したなら、後継・Access Token・Family がそろって残る
			if nextErr != nil || accessErr != nil || familyErr != nil {
				t.Fatalf("round %d: rotation succeeded but its rows are gone: refresh=%v access=%v family=%v", i, nextErr, accessErr, familyErr)
			}
			continue
		}
		wantErr(t, nextErr, storage.ErrNotFound, "successor of a failed rotation")
		wantErr(t, accessErr, storage.ErrNotFound, "access token of a failed rotation")
	}
}

// testPurgeVersusUpsertGrant は、失効済みで Family のない Grant の削除と、同じ Client × subject の
// 再同意が同時に走っても、再同意で返った Grant が消えていないことを確かめる。
//
// Purge が先なら新しい ID の Grant ができ、再同意が先なら既存の行が active に戻って Purge の対象から
// 外れる。どちらでも、返った ID でトークンを発行できなければならない。
func testPurgeVersusUpsertGrant(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	const rounds = 20
	for i := 0; i < rounds; i++ {
		suffix := fmt.Sprintf("-purge-upsert-%d", i)
		old, err := s.UpsertGrant(ctx, newGrant("g"+suffix, "c"+suffix, "alice", "openid"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeGrant(ctx, old.ID, base); err != nil {
			t.Fatal(err)
		}

		var (
			wg                  sync.WaitGroup
			got                 *grant.Grant
			upsertErr, purgeErr error
			start               = make(chan struct{})
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			got, upsertErr = s.UpsertGrant(ctx, newGrant("g2"+suffix, "c"+suffix, "alice", "openid"))
		}()
		go func() {
			defer wg.Done()
			<-start
			purgeErr = s.Purge(ctx, base)
		}()
		close(start)
		wg.Wait()

		if upsertErr != nil || purgeErr != nil {
			t.Fatalf("round %d: upsert=%v purge=%v", i, upsertErr, purgeErr)
		}
		if got.ID != old.ID && got.ID != "g2"+suffix {
			t.Fatalf("round %d: unexpected grant id %q", i, got.ID)
		}
		stored, err := s.GetGrant(ctx, got.ID)
		if err != nil || !stored.Active() {
			t.Fatalf("round %d: grant returned by the re-consent must exist and be active: %+v, %v", i, stored, err)
		}
		f := newFamily("f"+suffix, got.ID)
		if err := s.IssueTokens(ctx, f, newAccess("at"+suffix, f.ID, got.ID), newRefresh("rt"+suffix, f.ID)); err != nil {
			t.Fatalf("round %d: issue under the re-consented grant: %v", i, err)
		}
	}
}

// --- aliasing ---

func testValuesAreCopied(t *testing.T, s authengine.Store) {
	ctx := context.Background()
	c := newWebClient(t, "c1")
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Scopes[0] = "mutated-after-create"
	got, _ := s.GetClient(ctx, "c1")
	if got.Scopes[0] != "openid" {
		t.Fatal("store must copy values on create")
	}
	got.Scopes[0] = "mutated-after-get"
	again, _ := s.GetClient(ctx, "c1")
	if again.Scopes[0] != "openid" {
		t.Fatal("store must copy values on get")
	}

	txn := newTxn("t1")
	if err := s.CreateTransaction(ctx, txn); err != nil {
		t.Fatal(err)
	}
	outcome := &authorization.Outcome{Subject: "alice", AuthenticatedAt: base, GrantedScopes: []string{"openid"}, Claims: map[string]any{"k": "v"}}
	if err := s.TransitionTransaction(ctx, "t1", authorization.StatusPending, authorization.StatusCompleted, authorization.Patch{Outcome: outcome}); err != nil {
		t.Fatal(err)
	}
	outcome.Claims["k"] = "mutated"
	got2, _ := s.GetTransaction(ctx, "t1")
	if got2.Outcome.Claims["k"] != "v" {
		t.Fatal("store must copy patch values")
	}
}
