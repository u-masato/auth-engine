// Package keys は ID Token と JWT Access Token（RFC 9068）の署名鍵セットを管理する。
//
// go-jose/v4 の利用はこのパッケージに閉じ込める（docs/adr/0002-tech-stack.md）。
// 他のパッケージは Set.Sign / Set.Verify / Set.JWKS だけを使い、JOSE の型を直接扱わない。
//
// 対応する仕様:
//   - RFC 7515 JWS（compact serialization）、RFC 7517 JWK / JWK Set、RFC 7518 JWA
//   - RFC 7519 JWT、RFC 8725 §3 アルゴリズムの固定（none / HS* を使わない、kid と alg を鍵側で検証）
//   - RFC 9068 §2.1 JWT Access Token の typ ヘッダ（at+jwt。SignTyped / Header.Type）
//   - RFC 7638 JWK Thumbprint（kid の生成）
//   - OIDC Core §15.1 RS256 は OP の必須サポート
//
// ローテーション: 署名鍵はアルゴリズムごとに 1 本。AddSigning で差し替えると、旧鍵は
// 検証鍵として残り、JWKS にも含まれ続ける。古い鍵は Remove で外す。
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// サポートする署名アルゴリズム。
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// supportedAlgs はサポートする署名アルゴリズムの一覧。順序は Discovery に載せる順。
var supportedAlgs = []string{AlgRS256, AlgES256}

var (
	// ErrNoSigningKey は、指定アルゴリズムの署名鍵がない。
	ErrNoSigningKey = errors.New("keys: no signing key for algorithm")
	// ErrUnknownKey は、トークンの kid に対応する鍵がない。
	ErrUnknownKey = errors.New("keys: unknown key id")
	// ErrInvalidToken は、署名・形式・アルゴリズムの検証に失敗した。
	ErrInvalidToken = errors.New("keys: invalid token")
)

// Key は 1 本の鍵。private が nil なら検証専用。
type Key struct {
	ID        string
	Alg       string
	CreatedAt time.Time

	private crypto.Signer
	public  crypto.PublicKey
}

// HasPrivate は署名に使えるかを返す。
func (k *Key) HasPrivate() bool { return k.private != nil }

// Generate は alg の鍵を生成する。RS256 は RSA 2048、ES256 は P-256。
// kid は公開鍵の RFC 7638 サムプリント（SHA-256、base64url）。
func Generate(alg string, now time.Time) (*Key, error) {
	var signer crypto.Signer
	switch alg {
	case AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		signer = k
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = k
	default:
		return nil, fmt.Errorf("keys: unsupported algorithm %q", alg)
	}
	return newKey(alg, signer, now)
}

func newKey(alg string, signer crypto.Signer, now time.Time) (*Key, error) {
	kid, err := thumbprint(signer.Public())
	if err != nil {
		return nil, err
	}
	return &Key{ID: kid, Alg: alg, CreatedAt: now, private: signer, public: signer.Public()}, nil
}

func thumbprint(pub crypto.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("keys: thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// Header は検証したトークンの JOSE ヘッダのうち、呼び出し側が使う部分。
type Header struct {
	KeyID string
	Alg   string
	// Type は typ ヘッダ（RFC 7515 §4.1.9）。ID Token は "JWT"、JWT Access Token は "at+jwt"（RFC 9068 §2.1）。
	// Resource Server は at+jwt 以外を拒否して ID Token との混同を防ぐ（RFC 9068 §4）。
	Type string
}

// Set は署名鍵と検証鍵の集まり。複数 goroutine から同時に使える。
type Set struct {
	mu      sync.RWMutex
	signing map[string]string // alg → kid
	keys    map[string]*Key   // kid → key
	order   []string          // kid の登録順（JWKS の出力順を安定させる）
}

// NewSet は空の Set を返す。
func NewSet() *Set {
	return &Set{signing: map[string]string{}, keys: map[string]*Key{}}
}

// AddSigning は k を alg の署名鍵にする。既存の署名鍵は検証鍵として残る。
func (s *Set) AddSigning(k *Key) error {
	if !k.HasPrivate() {
		return errors.New("keys: signing key requires a private key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(k)
	s.signing[k.Alg] = k.ID
	return nil
}

// AddVerification は k を検証鍵として追加する（公開鍵だけでもよい）。
func (s *Set) AddVerification(k *Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(k)
}

func (s *Set) addLocked(k *Key) {
	if _, exists := s.keys[k.ID]; !exists {
		s.order = append(s.order, k.ID)
	}
	s.keys[k.ID] = k
}

// Remove は kid の鍵を外す。署名鍵だった場合はそのアルゴリズムの署名鍵がなくなる。
func (s *Set) Remove(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[kid]; ok {
		if s.signing[k.Alg] == kid {
			delete(s.signing, k.Alg)
		}
		delete(s.keys, kid)
		s.order = slices.DeleteFunc(s.order, func(id string) bool { return id == kid })
	}
}

// SigningKey は alg の署名鍵を返す。
func (s *Set) SigningKey(alg string) (*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kid, ok := s.signing[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSigningKey, alg)
	}
	return s.keys[kid], nil
}

// Key は kid の鍵を返す。
func (s *Set) Key(kid string) (*Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	return k, ok
}

// SigningAlgorithms は署名鍵があるアルゴリズムを返す（Discovery の
// id_token_signing_alg_values_supported 用）。順序は固定。
func (s *Set) SigningAlgorithms() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, alg := range supportedAlgs {
		if _, ok := s.signing[alg]; ok {
			out = append(out, alg)
		}
	}
	return out
}

// Sign は claims（複数可。後の値が前の値を上書き）を alg の署名鍵で署名した
// compact JWS を返す。ヘッダには typ=JWT と kid を入れる。
func (s *Set) Sign(alg string, claims ...any) (string, error) {
	return s.SignTyped(alg, "JWT", claims...)
}

// SignTyped は typ ヘッダを指定して署名する。JWT Access Token は "at+jwt"（RFC 9068 §2.1）。
func (s *Set) SignTyped(alg, typ string, claims ...any) (string, error) {
	if typ == "" {
		return "", errors.New("keys: typ header is required")
	}
	k, err := s.SigningKey(alg)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), k.ID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: k.private}, opts)
	if err != nil {
		return "", fmt.Errorf("keys: signer: %w", err)
	}
	b := jwt.Signed(signer)
	for _, c := range claims {
		b = b.Claims(c)
	}
	tok, err := b.Serialize()
	if err != nil {
		return "", fmt.Errorf("keys: sign: %w", err)
	}
	return tok, nil
}

// Verify は compact JWS の署名を検証し、ペイロードを out（複数可）に展開する。
//
// 鍵は kid で選び、ヘッダの alg がその鍵のアルゴリズムと一致することを要求する
// （RFC 8725 §3.1 アルゴリズム混同対策）。有効期限などのクレームの検証は呼び出し側が行う。
func (s *Set) Verify(token string, out ...any) (*Header, error) {
	// 許可リストは supportedAlgs と同じ。
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}
	h := parsed.Headers[0]
	k, ok := s.Key(h.KeyID)
	if !ok {
		return nil, ErrUnknownKey
	}
	if h.Algorithm != k.Alg {
		return nil, fmt.Errorf("%w: algorithm %q does not match key %q", ErrInvalidToken, h.Algorithm, k.Alg)
	}
	if err := parsed.Claims(k.public, out...); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	return &Header{KeyID: k.ID, Alg: k.Alg, Type: typ}, nil
}

// JWKS は公開鍵だけを含む JWK Set（RFC 7517 §5）の JSON を返す。/jwks の応答に使う。
func (s *Set) JWKS() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := jose.JSONWebKeySet{}
	for _, kid := range s.order {
		k := s.keys[kid]
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.public, KeyID: k.ID, Algorithm: k.Alg, Use: "sig"})
	}
	return json.Marshal(set)
}

// privateSet は ExportPrivate / ImportPrivate の形式。JWK Set に署名鍵の指定と
// 各鍵の created_at を足したもの。jose.JSONWebKey は独自の MarshalJSON を持つため、
// 鍵ごとの JSON をマップに展開してから created_at を加える。
type privateSet struct {
	Keys    []json.RawMessage `json:"keys"`
	Signing map[string]string `json:"signing"` // alg → kid
}

// ExportPrivate は秘密鍵を含む鍵セットを JSON で返す。ファイルに保存して再起動後に
// ImportPrivate で復元する用途（examples）。保存先の保護は利用者の責務。
func (s *Set) ExportPrivate() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := privateSet{Signing: maps.Clone(s.signing)}
	for _, kid := range s.order {
		k := s.keys[kid]
		var key any = k.public
		if k.private != nil {
			key = k.private
		}
		jwkJSON, err := json.Marshal(jose.JSONWebKey{Key: key, KeyID: k.ID, Algorithm: k.Alg, Use: "sig"})
		if err != nil {
			return nil, fmt.Errorf("keys: export: %w", err)
		}
		var fields map[string]any
		if err := json.Unmarshal(jwkJSON, &fields); err != nil {
			return nil, fmt.Errorf("keys: export: %w", err)
		}
		fields["created_at"] = k.CreatedAt
		raw, err := json.Marshal(fields)
		if err != nil {
			return nil, fmt.Errorf("keys: export: %w", err)
		}
		out.Keys = append(out.Keys, raw)
	}
	return json.Marshal(out)
}

// ImportPrivate は ExportPrivate の出力から Set を復元する。
func ImportPrivate(data []byte) (*Set, error) {
	var in privateSet
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("keys: import: %w", err)
	}
	s := NewSet()
	for _, raw := range in.Keys {
		var pk jose.JSONWebKey
		if err := json.Unmarshal(raw, &pk); err != nil {
			return nil, fmt.Errorf("keys: import: %w", err)
		}
		var meta struct {
			CreatedAt time.Time `json:"created_at"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("keys: import: %w", err)
		}
		if !slices.Contains(supportedAlgs, pk.Algorithm) {
			return nil, fmt.Errorf("keys: import: unsupported algorithm %q", pk.Algorithm)
		}
		k := &Key{ID: pk.KeyID, Alg: pk.Algorithm, CreatedAt: meta.CreatedAt}
		if signer, ok := pk.Key.(crypto.Signer); ok {
			k.private, k.public = signer, signer.Public()
		} else {
			k.public = pk.Key
		}
		if k.ID == "" {
			return nil, errors.New("keys: import: key without kid")
		}
		s.AddVerification(k)
	}
	for alg, kid := range in.Signing {
		k, ok := s.keys[kid]
		if !ok || k.Alg != alg {
			return nil, fmt.Errorf("keys: import: signing key %q for %s not found", kid, alg)
		}
		if err := s.AddSigning(k); err != nil {
			return nil, err
		}
	}
	return s, nil
}
