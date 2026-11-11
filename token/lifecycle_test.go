package token_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/token"
)

func TestInspect(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)

	at, err := f.svc.Inspect(f.ctx, res.AccessToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if !at.Active || at.TokenType != "Bearer" || at.ClientID != "web" || at.Subject != "alice" || len(at.Scopes) != 2 ||
		!at.IssuedAt.Equal(now) || !at.ExpiresAt.Equal(now.Add(time.Hour)) || at.Kind != token.HintAccessToken {
		t.Fatalf("access introspection: %+v", at)
	}
	// hint が外れていても見つかる
	rt, err := f.svc.Inspect(f.ctx, res.RefreshToken, token.HintAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !rt.Active || rt.TokenType != "" || rt.ClientID != "web" || rt.Subject != "alice" || rt.Kind != token.HintRefreshToken ||
		!rt.ExpiresAt.Equal(now.Add(14*24*time.Hour)) {
		t.Fatalf("refresh introspection: %+v", rt)
	}
	// 不明・空は active:false でエラーにしない
	for _, tok := range []string{"", "at_unknown"} {
		in, err := f.svc.Inspect(f.ctx, tok, "")
		if err != nil || in.Active {
			t.Fatalf("unknown token %q: %+v %v", tok, in, err)
		}
	}
	// 期限切れ
	f.clock.Advance(time.Hour)
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("expired access token must be inactive")
	}
	if in, _ := f.svc.Inspect(f.ctx, res.RefreshToken, ""); !in.Active {
		t.Fatal("refresh token must still be active")
	}
	// Grant の失効で両方とも inactive
	if err := f.store.RevokeGrant(f.ctx, f.grantID, f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.RefreshToken, ""); in.Active {
		t.Fatal("refresh token must be inactive after grant revocation")
	}
}

func TestRevokeAccessTokenOnly(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.AccessToken, Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("access token must be revoked")
	}
	// Access Token の失効は Refresh Token に及ばず、Refresh は続けられる
	if in, _ := f.svc.Inspect(f.ctx, res.RefreshToken, ""); !in.Active {
		t.Fatal("refresh token must survive access token revocation")
	}
	if _, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, "")); err != nil {
		t.Fatal(err)
	}
	// 二重失効・不明なトークンも成功
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.AccessToken, Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: "at_nope", TokenTypeHint: "refresh_token", Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeRefreshTokenRevokesFamily(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	second, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, ""))
	if err != nil {
		t.Fatal(err)
	}
	// 後継の Refresh Token を失効 → Family の全 Access Token も失効、Grant は残る
	if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: second.RefreshToken, TokenTypeHint: token.HintRefreshToken, Credentials: f.webCreds()}); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{res.AccessToken, second.AccessToken, second.RefreshToken} {
		if in, _ := f.svc.Inspect(f.ctx, tok, ""); in.Active {
			t.Fatalf("%s must be inactive after refresh token revocation", tok[:3])
		}
	}
	g, _ := f.store.GetGrant(f.ctx, f.grantID)
	if !g.Active() {
		t.Fatal("revoking a refresh token must not revoke the grant")
	}
	wantProtocolErr(t, mustErr(f.svc.Exchange(f.ctx, f.refreshRequest(second.RefreshToken, ""))), token.CodeInvalidGrant)
}

func TestRevokeOtherClientsTokenIsSilentlyIgnored(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	cli := token.Credentials{ClientID: "cli", Method: client.AuthNone}
	for _, tok := range []string{res.AccessToken, res.RefreshToken} {
		if err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: tok, Credentials: cli}); err != nil {
			t.Fatal(err)
		}
		if in, _ := f.svc.Inspect(f.ctx, tok, ""); !in.Active {
			t.Fatal("another client must not be able to revoke the token")
		}
	}
	// 認証失敗は invalid_client、token なしは invalid_request
	wantProtocolErr(t, f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.AccessToken, Credentials: token.Credentials{ClientID: "web", Secret: "bad", Method: client.AuthClientSecretBasic}}), token.CodeInvalidClient)
	wantProtocolErr(t, f.svc.Revoke(f.ctx, token.RevocationRequest{Credentials: f.webCreds()}), token.CodeInvalidRequest)

	// Go API の RevokeToken は所有者を問わない
	found, err := f.svc.RevokeToken(f.ctx, res.AccessToken, "")
	if err != nil || !found {
		t.Fatalf("management revoke: %v %v", found, err)
	}
	if in, _ := f.svc.Inspect(f.ctx, res.AccessToken, ""); in.Active {
		t.Fatal("management revoke must revoke")
	}
	found, _ = f.svc.RevokeToken(f.ctx, "at_nope", "")
	if found {
		t.Fatal("unknown token must report not found")
	}
}

func TestIntrospectRequiresConfidentialClient(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	m2m := f.machineCreds(t)

	// Machine Client（Resource Server）は他 Client のトークンを検証できる
	in, err := f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: res.AccessToken, Credentials: m2m})
	if err != nil || !in.Active || in.ClientID != "web" {
		t.Fatalf("introspect by resource server: %+v %v", in, err)
	}
	// Web Client も可
	if in, err := f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: res.AccessToken, Credentials: f.webCreds()}); err != nil || !in.Active {
		t.Fatalf("introspect by web: %+v %v", in, err)
	}
	// public Client は invalid_client
	_, err = f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: res.AccessToken, Credentials: token.Credentials{ClientID: "cli", Method: client.AuthNone}})
	wantProtocolErr(t, err, token.CodeInvalidClient)
	_, err = f.svc.Introspect(f.ctx, token.IntrospectionRequest{Credentials: m2m})
	wantProtocolErr(t, err, token.CodeInvalidRequest)
	// 平文ではなくハッシュで検索しているので、ハッシュ値を提示しても見つからない
	if in, _ := f.svc.Introspect(f.ctx, token.IntrospectionRequest{Token: rand.Hash(res.AccessToken), Credentials: m2m}); in.Active {
		t.Fatal("hash must not be accepted as a token")
	}
}

// missingFamilyStore は Refresh Token は残っているが Family 行だけが欠けた、不整合な Store を模す。
type missingFamilyStore struct{ token.Store }

func (missingFamilyStore) GetTokenFamily(context.Context, string) (*token.Family, error) {
	return nil, storage.ErrNotFound
}

func (missingFamilyStore) RevokeTokenFamily(context.Context, string, time.Time) error {
	return storage.ErrNotFound
}

// Family の欠落を「このトークンは存在しない」と取り違えて、黙って成功にしない。
func TestRevokeRefreshTokenWithMissingFamilyIsInternalError(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	f.svc.Store = missingFamilyStore{f.store}

	// RFC 7009 のエンドポイント（所有者を確かめる経路）: プロトコルエラーではなく内部エラー（HTTP 層で 500）
	err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.RefreshToken, TokenTypeHint: token.HintRefreshToken, Credentials: f.webCreds()})
	var perr *token.Error
	if err == nil || errors.As(err, &perr) || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("revoke with a missing family: want an internal error, got %v", err)
	}
	// Go API（所有者を問わない経路）も同じ。found=true を返さない
	found, err := f.svc.RevokeToken(f.ctx, res.RefreshToken, "")
	if err == nil || found {
		t.Fatalf("RevokeToken with a missing family: want an internal error, got found=%v err=%v", found, err)
	}
}

// Introspection も同じ: 有効な Refresh Token の Family が欠けているのは不整合であり、
// 「この種別ではない」と取り違えて active: false を返さない。
func TestInspectRefreshTokenWithMissingFamilyIsInternalError(t *testing.T) {
	f := newFixture(t)
	res := f.exchangeForRefresh(t)
	f.svc.Store = missingFamilyStore{f.store}

	in, err := f.svc.Inspect(f.ctx, res.RefreshToken, token.HintRefreshToken)
	var perr *token.Error
	if err == nil || errors.As(err, &perr) || !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("inspect with a missing family: want an internal error, got %+v %v", in, err)
	}
	// Access Token は Family を引かないので影響を受けない
	if in, err := f.svc.Inspect(f.ctx, res.AccessToken, ""); err != nil || !in.Active {
		t.Fatalf("access token must still be inspectable: %+v %v", in, err)
	}
}

// purgeAfterLookupStore は、Refresh Token を引いた直後に Purge が走った状況を模す。
// Purge は期限切れの Refresh Token と、子のなくなった Family を同じ操作で消す（ADR-0005 §7）。
type purgeAfterLookupStore struct {
	token.Store
	purge func()
	once  sync.Once
}

func (s *purgeAfterLookupStore) LookupRefreshToken(ctx context.Context, hash string) (*token.RefreshToken, error) {
	rt, err := s.Store.LookupRefreshToken(ctx, hash)
	s.once.Do(s.purge)
	return rt, err
}

// 引いた直後に Purge で Refresh Token ごと Family が消えたのは不整合ではない。Family の欠落
// （上の 2 つのテスト）と区別して、不明なトークンと同じ扱いにする。
func TestRefreshTokenPurgedAfterLookupIsUnknownToken(t *testing.T) {
	purged := func(t *testing.T) (*fixture, *token.Response) {
		t.Helper()
		f := newFixture(t)
		res := f.exchangeForRefresh(t)
		f.svc.Store = &purgeAfterLookupStore{Store: f.store, purge: func() {
			if err := f.store.Purge(f.ctx, now.Add(365*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}}
		return f, res
	}
	t.Run("inspect", func(t *testing.T) {
		f, res := purged(t)
		in, err := f.svc.Inspect(f.ctx, res.RefreshToken, token.HintRefreshToken)
		if err != nil || in.Active {
			t.Fatalf("want inactive without an error, got %+v %v", in, err)
		}
	})
	t.Run("revoke", func(t *testing.T) {
		f, res := purged(t)
		// RFC 7009 §2.2: 不明なトークンの失効は成功として扱う
		err := f.svc.Revoke(f.ctx, token.RevocationRequest{Token: res.RefreshToken, TokenTypeHint: token.HintRefreshToken, Credentials: f.webCreds()})
		if err != nil {
			t.Fatalf("want success, got %v", err)
		}
	})
	t.Run("revoke token", func(t *testing.T) {
		f, res := purged(t)
		found, err := f.svc.RevokeToken(f.ctx, res.RefreshToken, token.HintRefreshToken)
		if err != nil || found {
			t.Fatalf("want found=false without an error, got found=%v err=%v", found, err)
		}
	})
	t.Run("refresh", func(t *testing.T) {
		f, res := purged(t)
		_, err := f.svc.Exchange(f.ctx, f.refreshRequest(res.RefreshToken, ""))
		wantProtocolErr(t, err, token.CodeInvalidGrant)
	})
}
