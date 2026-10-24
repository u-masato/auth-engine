package resourceserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/keys"
)

// JWT Access Token の typ（RFC 9068 §2.1）。token.JWTAccessTokenType と同じ値だが、
// このパッケージは認可サーバー側のパッケージに依存しないので独立に定義する。
const jwtAccessTokenType = "at+jwt"

// JWKS キャッシュの既定値。
const (
	DefaultJWKSTTL        = time.Hour
	MinJWKSTTL            = time.Minute
	MaxJWKSTTL            = 24 * time.Hour
	DefaultJWKSMinRefresh = time.Minute
)

// JWTVerifier は RFC 9068 の JWT Access Token を認可サーバーの JWKS でローカル検証する。
//
// 失効は exp まで伝播しない（ADR-0006 §1、ADR-0008 §3）。即時の失効が要るなら IntrospectionVerifier を使う。
type JWTVerifier struct {
	// Issuer は期待する iss。必須。JWKSURI が空ならメタデータ（RFC 8414）から jwks_uri を得る。
	Issuer string
	// JWKSURI は JWKS の URL。指定すればメタデータを取得しない。
	JWKSURI string
	// Algorithms は受理する署名アルゴリズムの許可リスト（RFC 8725 §3.1）。空なら RS256 と ES256。
	Algorithms []string
	// HTTPClient は nil なら 10 秒タイムアウトの既定。
	HTTPClient *http.Client
	// JWKSTTL は JWKS を再取得する間隔の既定（Cache-Control: max-age があれば [1 分, 24 時間] で尊重）。0 なら 1 時間。
	JWKSTTL time.Duration
	// MinRefresh は未知の kid を見たときに再取得する最短間隔（再取得の連打で認可サーバーを叩かないため）。0 なら 1 分。
	MinRefresh time.Duration
	// Now は現在時刻。nil なら time.Now。
	Now func() time.Time

	mu        sync.Mutex
	as        *asClient
	set       *keys.Set
	fetchedAt time.Time
	expires   time.Time
}

var _ TokenVerifier = (*JWTVerifier)(nil)

// jwtClaims は RFC 9068 §2.2 の Claims のうち検証に使うもの。aud は文字列か配列。
type jwtClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	IssuedAt  int64           `json:"iat"`
	NotBefore int64           `json:"nbf"`
	ClientID  string          `json:"client_id"`
	Scope     string          `json:"scope"`
}

// Verify は署名・typ・iss・exp・nbf・alg を検証して Principal を返す（RFC 9068 §4）。
// aud は Principal.Audience として返し、Protector が自分の resource を含むことを確認する。
func (v *JWTVerifier) Verify(ctx context.Context, token string) (*Principal, error) {
	if v.Issuer == "" {
		return nil, errors.New("resourceserver: JWTVerifier requires Issuer")
	}
	// 署名の前にヘッダの alg を許可リストで確かめる（RFC 8725 §3.1）。
	alg, err := jwtHeaderAlg(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !slices.Contains(v.algorithms(), alg) {
		return nil, fmt.Errorf("%w: algorithm %q is not allowed", ErrInvalidToken, alg)
	}

	set, err := v.keySet(ctx, false)
	if err != nil {
		return nil, err
	}
	var claims jwtClaims
	h, err := set.Verify(token, &claims)
	if errors.Is(err, keys.ErrUnknownKey) {
		// 鍵ローテーション直後。間隔を守って再取得し、もう一度だけ試す。
		if set, err = v.keySet(ctx, true); err != nil {
			return nil, err
		}
		h, err = set.Verify(token, &claims)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !strings.EqualFold(h.Type, jwtAccessTokenType) {
		// ID Token（typ=JWT）などとの混同を防ぐ（RFC 9068 §4）。
		return nil, fmt.Errorf("%w: typ %q is not %s", ErrInvalidToken, h.Type, jwtAccessTokenType)
	}
	if claims.Issuer != v.Issuer {
		return nil, fmt.Errorf("%w: issuer %q is not %q", ErrInvalidToken, claims.Issuer, v.Issuer)
	}
	now := v.now()
	if claims.ExpiresAt == 0 || !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return nil, fmt.Errorf("%w: token has expired", ErrInvalidToken)
	}
	if claims.NotBefore != 0 && now.Before(time.Unix(claims.NotBefore, 0)) {
		return nil, fmt.Errorf("%w: token is not yet valid", ErrInvalidToken)
	}
	aud, err := parseAudience(claims.Audience)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(aud) == 0 {
		return nil, fmt.Errorf("%w: aud is required", ErrInvalidToken)
	}
	if claims.Subject == "" || claims.ClientID == "" {
		return nil, fmt.Errorf("%w: sub and client_id are required (RFC 9068 §2.2)", ErrInvalidToken)
	}
	p := &Principal{Subject: claims.Subject, ClientID: claims.ClientID, Scopes: strings.Fields(claims.Scope), Audience: aud,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0)}
	if claims.IssuedAt != 0 {
		p.IssuedAt = time.Unix(claims.IssuedAt, 0)
	}
	return p, nil
}

func (v *JWTVerifier) algorithms() []string {
	if len(v.Algorithms) == 0 {
		return []string{keys.AlgRS256, keys.AlgES256}
	}
	return v.Algorithms
}

func (v *JWTVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// keySet はキャッシュした JWKS を返す。期限切れ、または force（未知の kid）で MinRefresh を過ぎていれば再取得する。
func (v *JWTVerifier) keySet(ctx context.Context, force bool) (*keys.Set, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	minRefresh := v.MinRefresh
	if minRefresh == 0 {
		minRefresh = DefaultJWKSMinRefresh
	}
	switch {
	case v.set == nil:
	case force && now.Sub(v.fetchedAt) >= minRefresh:
	case !force && !now.Before(v.expires):
	default:
		return v.set, nil
	}
	// 再取得に失敗したとき、手元に JWKS があればそれで続ける。手元になければ err を返す（fail-closed）。
	// 認可サーバーの障害中に要求ごとの取得が続かないよう、次の再試行は MinRefresh の後にする。
	// ただし呼び出し側の ctx が終わっただけ（切断・期限）なら認可サーバーの障害ではないので間引かない。
	// 間引くと、鍵ローテーション直後の正しいトークンを MinRefresh の間「未知の kid」で拒否してしまう。
	fail := func(err error) (*keys.Set, error) {
		if v.set == nil {
			return nil, err
		}
		if ctx.Err() == nil {
			v.fetchedAt = now
			if retry := now.Add(minRefresh); v.expires.Before(retry) {
				v.expires = retry
			}
		}
		return v.set, nil
	}
	uri, err := v.jwksURI(ctx)
	if err != nil {
		return fail(err)
	}
	body, h, err := getJSON(ctx, httpClientOr(v.HTTPClient), uri)
	if err != nil {
		return fail(fmt.Errorf("resourceserver: jwks: %w", err))
	}
	set, err := keys.ImportJWKS(body)
	if err != nil {
		return fail(fmt.Errorf("resourceserver: jwks: %w", err))
	}
	v.set, v.fetchedAt, v.expires = set, now, now.Add(v.jwksTTL(h))
	return v.set, nil
}

func (v *JWTVerifier) jwksURI(ctx context.Context) (string, error) {
	if v.JWKSURI != "" {
		return v.JWKSURI, nil
	}
	if v.as == nil {
		v.as = newASClient(v.Issuer, httpClientOr(v.HTTPClient))
	}
	m, err := v.as.metadata(ctx)
	if err != nil {
		return "", err
	}
	if m.JWKSURI == "" {
		return "", errors.New("resourceserver: authorization server metadata has no jwks_uri")
	}
	return m.JWKSURI, nil
}

// jwksTTL は Cache-Control: max-age を [MinJWKSTTL, MaxJWKSTTL] に収めて返す。なければ JWKSTTL（既定 1 時間）。
func (v *JWTVerifier) jwksTTL(h http.Header) time.Duration {
	ttl := v.JWKSTTL
	if ttl == 0 {
		ttl = DefaultJWKSTTL
	}
	for d := range strings.SplitSeq(h.Get("Cache-Control"), ",") {
		name, val, _ := strings.Cut(strings.TrimSpace(d), "=")
		if strings.EqualFold(strings.TrimSpace(name), "max-age") {
			if sec, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(val), `"`), 10, 64); err == nil && sec >= 0 {
				ttl = time.Duration(sec) * time.Second
			}
		}
	}
	return min(max(ttl, MinJWKSTTL), MaxJWKSTTL)
}

// jwtHeaderAlg は compact JWS のヘッダから alg を読む（署名検証の前に許可リストで落とすため）。
func jwtHeaderAlg(token string) (string, error) {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", errors.New("malformed token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return "", errors.New("malformed token header")
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || h.Alg == "" {
		return "", errors.New("malformed token header")
	}
	return h.Alg, nil
}
