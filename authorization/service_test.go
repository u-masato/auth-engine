package authorization_test

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/storage/memory"
)

const (
	issuer       = "https://as.example.com"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	binding      = "browser-binding-secret"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type fixture struct {
	svc   *authorization.Service
	store *memory.Store
	clock *clock.Fixed
	ctx   context.Context
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := memory.New()
	clk := clock.NewFixed(now)
	web, _, err := client.NewWeb(client.WebParams{ID: "web", Name: "Web",
		RedirectURIs: []string{"https://app.example.com/cb?env=prod"},
		Scopes:       []string{"openid", "profile", "email"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateClient(context.Background(), web); err != nil {
		t.Fatal(err)
	}
	return &fixture{
		svc:   &authorization.Service{Clients: store, Store: store, Grants: store, Clock: clk, Issuer: issuer},
		store: store, clock: clk, ctx: context.Background(),
	}
}

func params() url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {"web"}, "scope": {"openid profile"}, "state": {"xyz"},
		"code_challenge": {rfcChallenge}, "code_challenge_method": {"S256"}, "nonce": {"n1"}, "max_age": {"600"},
	}
}

func okOutcome() authorization.Outcome {
	return authorization.Outcome{
		Subject: "alice", AuthenticatedAt: now.Add(-time.Minute), GrantedScopes: []string{"openid", "profile"},
		AMR: []string{"pwd"}, ACR: "urn:acr:1", Claims: map[string]any{"name": "Alice"},
	}
}

func (f *fixture) begin(t *testing.T) *authorization.Transaction {
	t.Helper()
	txn, err := f.svc.Begin(f.ctx, params(), binding)
	if err != nil {
		t.Fatal(err)
	}
	return txn
}

func TestBegin(t *testing.T) {
	f := newFixture(t)
	txn := f.begin(t)
	if txn.ID == "" || txn.Status != authorization.StatusPending || txn.Request.ClientID != "web" {
		t.Fatalf("txn: %+v", txn)
	}
	if !txn.ExpiresAt.Equal(now.Add(authorization.DefaultTransactionTTL)) {
		t.Fatalf("expiry: %v", txn.ExpiresAt)
	}
	if txn.BrowserBindingHash != rand.Hash(binding) || txn.BrowserBindingHash == binding {
		t.Fatal("binding must be stored hashed")
	}
	stored, err := f.store.GetTransaction(f.ctx, txn.ID)
	if err != nil || stored.Request.Nonce != "n1" {
		t.Fatalf("stored: %+v, %v", stored, err)
	}
	if _, err := f.svc.Begin(f.ctx, params(), ""); err == nil {
		t.Fatal("empty browser binding must be rejected")
	}
}

func TestBeginProtocolErrors(t *testing.T) {
	f := newFixture(t)
	p := params()
	p.Set("client_id", "nope")
	_, err := f.svc.Begin(f.ctx, p, binding)
	var perr *authorization.Error
	if !errors.As(err, &perr) || perr.Redirectable() {
		t.Fatalf("unknown client: %v", err)
	}
	p = params()
	p.Del("code_challenge")
	_, err = f.svc.Begin(f.ctx, p, binding)
	if !errors.As(err, &perr) || !perr.Redirectable() || perr.Code != authorization.CodeInvalidRequest {
		t.Fatalf("missing pkce: %v", err)
	}
}

func TestCompleteThenResume(t *testing.T) {
	f := newFixture(t)
	txn := f.begin(t)

	resume, err := f.svc.Complete(f.ctx, txn.ID, okOutcome())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resume, authorization.ResumeTokenPrefix) {
		t.Fatalf("resume token: %q", resume)
	}
	stored, _ := f.store.GetTransaction(f.ctx, txn.ID)
	if stored.Status != authorization.StatusCompleted || stored.ResumeTokenHash != rand.Hash(resume) || stored.Outcome.Subject != "alice" {
		t.Fatalf("after complete: %+v", stored)
	}

	// 二重 Complete / Reject は不可
	if _, err := f.svc.Complete(f.ctx, txn.ID, okOutcome()); !errors.Is(err, authorization.ErrTransactionNotPending) {
		t.Fatalf("double complete: %v", err)
	}
	if _, err := f.svc.Reject(f.ctx, txn.ID, authorization.Rejection{Error: "access_denied"}); !errors.Is(err, authorization.ErrTransactionNotPending) {
		t.Fatalf("reject after complete: %v", err)
	}

	f.clock.Advance(5 * time.Second)
	redirect, err := f.svc.Resume(f.ctx, txn.ID, resume, binding)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "app.example.com" || u.Path != "/cb" || u.Fragment != "" {
		t.Fatalf("redirect target: %s", redirect)
	}
	if q.Get("env") != "prod" || q.Get("state") != "xyz" || q.Get("iss") != issuer || q.Get("code") == "" || q.Has("error") {
		t.Fatalf("redirect query: %s", redirect)
	}

	// Code は Hash で保存され、Grant・Family・PKCE・nonce を引き継いでいる
	code := q.Get("code")
	ac, err := f.store.ConsumeAuthorizationCode(f.ctx, rand.Hash(code), f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ac.TxnID != txn.ID || ac.ClientID != "web" || ac.Subject != "alice" || ac.GrantID == "" || ac.FamilyID == "" ||
		ac.CodeChallenge != rfcChallenge || ac.Nonce != "n1" || !slices.Equal(ac.Scopes, []string{"openid", "profile"}) ||
		ac.RedirectURI != "https://app.example.com/cb?env=prod" || ac.RedirectURIExplicit || ac.Claims["name"] != "Alice" ||
		!slices.Equal(ac.AMR, []string{"pwd"}) || !ac.ExpiresAt.Equal(f.clock.Now().Add(authorization.DefaultCodeTTL)) {
		t.Fatalf("code: %+v", ac)
	}
	g, err := f.store.GetGrant(f.ctx, ac.GrantID)
	if err != nil || g.ClientID != "web" || g.Subject != "alice" || !slices.Equal(g.Scopes, []string{"openid", "profile"}) || !g.Active() {
		t.Fatalf("grant: %+v, %v", g, err)
	}

	// Txn は消費済みで、Resume の再利用は拒否
	stored, _ = f.store.GetTransaction(f.ctx, txn.ID)
	if stored.Status != authorization.StatusConsumed {
		t.Fatalf("txn after resume: %s", stored.Status)
	}
	if _, err := f.svc.Resume(f.ctx, txn.ID, resume, binding); !errors.Is(err, authorization.ErrResumeDenied) {
		t.Fatalf("resume reuse: %v", err)
	}
}

func TestResumeMergesGrantAcrossTransactions(t *testing.T) {
	f := newFixture(t)
	for _, scopes := range [][]string{{"openid"}, {"openid", "profile"}} {
		txn := f.begin(t)
		out := okOutcome()
		out.GrantedScopes = scopes
		resume, err := f.svc.Complete(f.ctx, txn.ID, out)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Resume(f.ctx, txn.ID, resume, binding); err != nil {
			t.Fatal(err)
		}
	}
	g, err := f.store.FindGrant(f.ctx, "web", "alice")
	if err != nil || !slices.Equal(g.Scopes, []string{"openid", "profile"}) {
		t.Fatalf("grant must be a single merged record: %+v, %v", g, err)
	}
}

func TestCompleteValidation(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name string
		mod  func(*authorization.Outcome)
	}{
		{"empty subject", func(o *authorization.Outcome) { o.Subject = "" }},
		{"zero auth time", func(o *authorization.Outcome) { o.AuthenticatedAt = time.Time{} }},
		{"no scopes", func(o *authorization.Outcome) { o.GrantedScopes = nil }},
		{"scope not requested", func(o *authorization.Outcome) { o.GrantedScopes = []string{"openid", "email"} }},
		{"older than max_age", func(o *authorization.Outcome) { o.AuthenticatedAt = now.Add(-11 * time.Minute) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := f.begin(t)
			out := okOutcome()
			tt.mod(&out)
			_, err := f.svc.Complete(f.ctx, txn.ID, out)
			if !errors.Is(err, authorization.ErrInvalidOutcome) {
				t.Fatalf("want ErrInvalidOutcome, got %v", err)
			}
			stored, _ := f.store.GetTransaction(f.ctx, txn.ID)
			if stored.Status != authorization.StatusPending {
				t.Fatal("failed complete must leave txn pending")
			}
		})
	}
	// 部分集合なら OK（重複は除去）
	txn := f.begin(t)
	out := okOutcome()
	out.GrantedScopes = []string{"openid", "openid"}
	if _, err := f.svc.Complete(f.ctx, txn.ID, out); err != nil {
		t.Fatal(err)
	}
	stored, _ := f.store.GetTransaction(f.ctx, txn.ID)
	if !slices.Equal(stored.Outcome.GrantedScopes, []string{"openid"}) {
		t.Fatalf("granted scopes: %v", stored.Outcome.GrantedScopes)
	}
}

func TestCompleteUnknownAndExpired(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Complete(f.ctx, "missing", okOutcome()); !errors.Is(err, authorization.ErrTransactionNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	txn := f.begin(t)
	f.clock.Advance(authorization.DefaultTransactionTTL)
	if _, err := f.svc.Complete(f.ctx, txn.ID, okOutcome()); !errors.Is(err, authorization.ErrTransactionExpired) {
		t.Fatalf("expired complete: %v", err)
	}
	if _, err := f.svc.Reject(f.ctx, txn.ID, authorization.Rejection{Error: "access_denied"}); !errors.Is(err, authorization.ErrTransactionExpired) {
		t.Fatalf("expired reject: %v", err)
	}
}

func TestRejectThenResume(t *testing.T) {
	f := newFixture(t)
	txn := f.begin(t)
	if _, err := f.svc.Reject(f.ctx, txn.ID, authorization.Rejection{Error: "not_a_code"}); !errors.Is(err, authorization.ErrInvalidOutcome) {
		t.Fatalf("bad rejection code: %v", err)
	}
	resume, err := f.svc.Reject(f.ctx, txn.ID, authorization.Rejection{Error: "access_denied", Description: "user said no"})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := f.svc.Resume(f.ctx, txn.ID, resume, binding)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if q.Get("error") != "access_denied" || q.Get("error_description") != "user said no" || q.Get("state") != "xyz" || q.Get("iss") != issuer || q.Has("code") || q.Get("env") != "prod" {
		t.Fatalf("error redirect: %s", redirect)
	}
	stored, _ := f.store.GetTransaction(f.ctx, txn.ID)
	if stored.Status != authorization.StatusConsumed {
		t.Fatalf("rejected txn must be consumed by resume: %s", stored.Status)
	}
	if _, err := f.store.FindGrant(f.ctx, "web", "alice"); err == nil {
		t.Fatal("rejection must not create a grant")
	}
}

func TestResumeDenied(t *testing.T) {
	f := newFixture(t)

	// 未知の Txn
	if _, err := f.svc.Resume(f.ctx, "missing", "rs_x", binding); !errors.Is(err, authorization.ErrTransactionNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	// pending（Complete 前）
	txn := f.begin(t)
	if _, err := f.svc.Resume(f.ctx, txn.ID, "rs_x", binding); !errors.Is(err, authorization.ErrResumeDenied) {
		t.Fatalf("pending: %v", err)
	}
	resume, err := f.svc.Complete(f.ctx, txn.ID, okOutcome())
	if err != nil {
		t.Fatal(err)
	}
	// 誤った Resume Token
	if _, err := f.svc.Resume(f.ctx, txn.ID, resume+"x", binding); !errors.Is(err, authorization.ErrResumeDenied) {
		t.Fatalf("wrong token: %v", err)
	}
	// 別ブラウザ（結合 Cookie 不一致）
	if _, err := f.svc.Resume(f.ctx, txn.ID, resume, "other-browser"); !errors.Is(err, authorization.ErrResumeDenied) {
		t.Fatalf("wrong binding: %v", err)
	}
	// 拒否された試行で Txn は消費されていない
	stored, _ := f.store.GetTransaction(f.ctx, txn.ID)
	if stored.Status != authorization.StatusCompleted {
		t.Fatalf("denied resume must not consume: %s", stored.Status)
	}
	// 期限切れ
	f.clock.Advance(authorization.DefaultTransactionTTL)
	if _, err := f.svc.Resume(f.ctx, txn.ID, resume, binding); !errors.Is(err, authorization.ErrTransactionExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestCustomTTLs(t *testing.T) {
	f := newFixture(t)
	f.svc.TransactionTTL = 2 * time.Minute
	f.svc.CodeTTL = 30 * time.Second
	txn := f.begin(t)
	if !txn.ExpiresAt.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("txn ttl: %v", txn.ExpiresAt)
	}
	resume, _ := f.svc.Complete(f.ctx, txn.ID, okOutcome())
	redirect, err := f.svc.Resume(f.ctx, txn.ID, resume, binding)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	ac, err := f.store.ConsumeAuthorizationCode(f.ctx, rand.Hash(u.Query().Get("code")), now)
	if err != nil || !ac.ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("code ttl: %+v, %v", ac, err)
	}
}
