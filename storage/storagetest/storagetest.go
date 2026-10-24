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

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/grant"
	"github.com/muno/auth-engine/storage"
	"github.com/muno/auth-engine/token"
)

// Run は open が返す Store に対して契約テストを実行する。
func Run(t *testing.T, open func(t *testing.T) authengine.Store) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s authengine.Store)
	}{
		{"Client", testClient},
		{"Transaction", testTransaction},
		{"TransactionConcurrentComplete", testTransactionConcurrentComplete},
		{"AuthorizationCode", testAuthorizationCode},
		{"AuthorizationCodeConcurrentConsume", testCodeConcurrentConsume},
		{"Grant", testGrant},
		{"GrantRevokeCascades", testGrantRevokeCascades},
		{"IssueTokens", testIssueTokens},
		{"RotateRefreshToken", testRotateRefreshToken},
		{"RotateConcurrent", testRotateConcurrent},
		{"RevokeGrantVersusIssue", testRevokeGrantVersusIssue},
		{"RevokeTokenFamily", testRevokeTokenFamily},
		{"RevokeAccessToken", testRevokeAccessToken},
		{"Purge", testPurge},
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
		Scopes: []string{"openid"}, CodeChallenge: "ch", CodeChallengeMethod: "S256", Nonce: "n",
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
		AuthenticatedAt: base.Add(-time.Minute), AMR: []string{"pwd"}, ACR: "urn:acr:1",
		Status: token.FamilyActive, CreatedAt: base, ExpiresAt: base.Add(30 * 24 * time.Hour),
	}
}

func newAccess(hash, familyID, grantID string) *token.AccessToken {
	return &token.AccessToken{
		Hash: hash, FamilyID: familyID, GrantID: grantID, ClientID: "c1", Subject: "alice",
		Scopes: []string{"openid"}, Status: token.AccessActive, IssuedAt: base, ExpiresAt: base.Add(time.Hour),
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
		!got.CreatedAt.Equal(c.CreatedAt) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("restored client must validate: %v", err)
	}
	_, err = s.GetClient(ctx, "missing")
	wantErr(t, err, storage.ErrNotFound, "missing client")
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
		!got.RedirectURIExplicit || got.Claims["name"] != "Alice" || !got.ConsumedAt.Equal(now) || !got.AuthenticatedAt.Equal(base) {
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

	revived, err := s.UpsertGrant(ctx, newGrant("g1-again", "c1", "alice", "email"))
	if err != nil {
		t.Fatal(err)
	}
	if revived.ID != "g1" || !revived.Active() || !slices.Equal(revived.Scopes, []string{"email"}) || !revived.RevokedAt.IsZero() {
		t.Fatalf("revived grant must drop old scopes and clear revocation: %+v", revived)
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
	if gotAT.FamilyID != f.ID || gotAT.GrantID != g.ID || gotAT.Status != token.AccessActive ||
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
		!gotF.AuthenticatedAt.Equal(f.AuthenticatedAt) || !slices.Equal(gotF.AMR, f.AMR) || gotF.ACR != f.ACR ||
		!gotF.ExpiresAt.Equal(f.ExpiresAt) || !gotF.Active() {
		t.Fatalf("get family: %+v, %v", gotF, err)
	}
	_, err = s.GetTokenFamily(ctx, "nope")
	wantErr(t, err, storage.ErrNotFound, "unknown family")

	// Refresh なしでも発行できる
	f2 := newFamily("f2", g.ID)
	if err := s.IssueTokens(ctx, f2, newAccess("at2", f2.ID, g.ID), nil); err != nil {
		t.Fatal(err)
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
	if err != nil || gotAT.Status != token.AccessActive {
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
