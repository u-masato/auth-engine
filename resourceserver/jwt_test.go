package resourceserver_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/u-masato/auth-engine/internal/clock"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resourceserver"
)

// jwksServer は JWKS だけを配信し、取得回数を数え、障害を模せる認可サーバー。
type jwksServer struct {
	t    *testing.T
	srv  *httptest.Server
	keys *keys.Set
	hits atomic.Int32
	down atomic.Bool // true なら 500 を返す
}

func newJWKSServer(t *testing.T) *jwksServer {
	t.Helper()
	j := &jwksServer{t: t, keys: keys.NewSet()}
	j.addKey()
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.hits.Add(1)
		if j.down.Load() {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		body, err := j.keys.JWKS()
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(j.srv.Close)
	return j
}

// addKey は新しい署名鍵を足す（鍵ローテーション）。以後の sign はこの鍵で署名する。
func (j *jwksServer) addKey() {
	j.t.Helper()
	k, err := keys.Generate(keys.AlgRS256, time.Now())
	if err != nil {
		j.t.Fatal(err)
	}
	if err := j.keys.AddSigning(k); err != nil {
		j.t.Fatal(err)
	}
}

func (j *jwksServer) sign() string {
	j.t.Helper()
	tok, err := j.keys.SignTyped(keys.AlgRS256, "at+jwt", map[string]any{
		"iss": "https://as.example.com", "sub": "alice", "client_id": "c", "aud": "https://rs.example.com",
		"exp": time.Now().Add(24 * time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	if err != nil {
		j.t.Fatal(err)
	}
	return tok
}

func newJWKSVerifier(j *jwksServer, clk *clock.Fixed) *resourceserver.JWTVerifier {
	return &resourceserver.JWTVerifier{Issuer: "https://as.example.com", JWKSURI: j.srv.URL, Now: clk.Now}
}

// 認可サーバーの障害中は手元の JWKS で検証を続け、再取得は MinRefresh に 1 回だけ試す。
func TestJWTVerifierBacksOffWhileJWKSIsDown(t *testing.T) {
	j := newJWKSServer(t)
	clk := clock.NewFixed(time.Now())
	v := newJWKSVerifier(j, clk)
	ctx := context.Background()
	tok := j.sign()
	if _, err := v.Verify(ctx, tok); err != nil || j.hits.Load() != 1 {
		t.Fatalf("first verify: %v hits=%d", err, j.hits.Load())
	}

	j.down.Store(true)
	clk.Advance(2 * resourceserver.DefaultJWKSTTL) // TTL 切れ
	if _, err := v.Verify(ctx, tok); err != nil || j.hits.Load() != 2 {
		t.Fatalf("verify with the cached jwks while down: %v hits=%d", err, j.hits.Load())
	}
	// MinRefresh の間は再取得しない（要求ごとに認可サーバーを叩かない）
	for range 3 {
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if j.hits.Load() != 2 {
		t.Fatalf("jwks must not be refetched within MinRefresh while down: hits=%d", j.hits.Load())
	}
	clk.Advance(resourceserver.DefaultJWKSMinRefresh)
	if _, err := v.Verify(ctx, tok); err != nil || j.hits.Load() != 3 {
		t.Fatalf("retry after MinRefresh: %v hits=%d", err, j.hits.Load())
	}
}

// 手元に JWKS がなければ、障害はそのままエラー（fail-closed）で、間引かずに次の要求で再試行する。
func TestJWTVerifierWithoutCachedJWKSFailsClosed(t *testing.T) {
	j := newJWKSServer(t)
	j.down.Store(true)
	clk := clock.NewFixed(time.Now())
	v := newJWKSVerifier(j, clk)
	tok := j.sign()
	for i := range 2 {
		_, err := v.Verify(context.Background(), tok)
		if err == nil || errors.Is(err, resourceserver.ErrInvalidToken) {
			t.Fatalf("attempt %d: want a verifier failure (503), got %v", i, err)
		}
	}
	if j.hits.Load() != 2 {
		t.Fatalf("each request must retry while nothing is cached: hits=%d", j.hits.Load())
	}
}

// 呼び出し側の ctx が終わっただけの失敗では再取得を間引かない。鍵ローテーション直後に最初の要求が
// 切断されても、次の要求は新しい kid の JWKS を取り直して通る。
func TestJWTVerifierCanceledRequestDoesNotBackOff(t *testing.T) {
	j := newJWKSServer(t)
	clk := clock.NewFixed(time.Now())
	v := newJWKSVerifier(j, clk)
	if _, err := v.Verify(context.Background(), j.sign()); err != nil {
		t.Fatal(err)
	}
	j.addKey()
	fresh := j.sign() // 検証側にはまだない kid
	clk.Advance(resourceserver.DefaultJWKSMinRefresh)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(canceled, fresh); !errors.Is(err, resourceserver.ErrInvalidToken) {
		t.Fatalf("canceled request: want invalid token (unknown kid), got %v", err)
	}
	if _, err := v.Verify(context.Background(), fresh); err != nil {
		t.Fatalf("the next request must refetch the jwks: %v (hits=%d)", err, j.hits.Load())
	}
}

// 許可リストは署名検証に使われた alg で判定する。ヘッダに "alg" と大文字の "ALG" を並べると、
// encoding/json は後者を、JOSE ライブラリは前者を採るので、事前確認だけでは RS256 の署名が
// ES256 だけを許す Verifier を通ってしまう（RFC 8725 §3.1）。
func TestJWTVerifierAllowListUsesVerifiedAlgorithm(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":%q,"e":%q}]}`,
		b64(priv.N.Bytes()), b64(big.NewInt(int64(priv.E)).Bytes()))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(jwks)) }))
	t.Cleanup(srv.Close)

	sign := func(header string) string {
		payload := fmt.Sprintf(`{"iss":"https://as.example.com","sub":"alice","client_id":"c","aud":"https://rs.example.com","exp":%d}`,
			time.Now().Add(time.Hour).Unix())
		input := b64([]byte(header)) + "." + b64([]byte(payload))
		sum := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return input + "." + b64(sig)
	}
	plain := sign(`{"alg":"RS256","kid":"k1","typ":"at+jwt"}`)
	smuggled := sign(`{"alg":"RS256","ALG":"ES256","kid":"k1","typ":"at+jwt"}`)
	ctx := context.Background()

	// 前提の確認: RS256 を許す Verifier は、この手組みのトークンを受理する
	rs256 := &resourceserver.JWTVerifier{Issuer: "https://as.example.com", JWKSURI: srv.URL}
	if _, err := rs256.Verify(ctx, plain); err != nil {
		t.Fatalf("hand-built RS256 token must verify: %v", err)
	}
	es256Only := &resourceserver.JWTVerifier{Issuer: "https://as.example.com", JWKSURI: srv.URL, Algorithms: []string{keys.AlgES256}}
	for name, tok := range map[string]string{"plain": plain, "smuggled": smuggled} {
		if _, err := es256Only.Verify(ctx, tok); !errors.Is(err, resourceserver.ErrInvalidToken) {
			t.Errorf("%s RS256 token passed an ES256-only verifier: %v", name, err)
		}
	}
}
