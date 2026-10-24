package resource

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Format は Resource Server 向けに発行する Access Token の形式（ADR-0008 §3）。
// 形式は Resource Server がローカル検証するか Introspection するかの都合で決まるため、
// Client ではなく Resource の属性とする。
type Format string

const (
	// FormatOpaque はランダム文字列の Access Token。Resource Server は Introspection で検証する（既定）。
	FormatOpaque Format = "opaque"
	// FormatJWT は RFC 9068 の JWT Access Token。Resource Server は JWKS でローカル検証できる。
	FormatJWT Format = "jwt"
)

// Valid は既知の形式かを返す。空文字は既定（Opaque）として扱うので true。
func (f Format) Valid() bool {
	return f == "" || f == FormatOpaque || f == FormatJWT
}

var (
	// ErrInvalid は resource indicator の構文違反、または Resource 設定の不備を表す。
	ErrInvalid = errors.New("resource: invalid resource indicator")
	// ErrDuplicate は同じ resource URI が設定に 2 回現れたことを表す。
	ErrDuplicate = errors.New("resource: duplicate resource")
)

// Resource は 1 つの Resource Server の静的設定。
type Resource struct {
	// URI は RFC 8707 §2 の resource indicator。絶対 URI で fragment を含まない。
	// Set に登録するとき scheme と host を小文字に正規化する（Normalize）。
	URI string

	// Name は表示名。RFC 9728 の resource_name に使う（M3 タスク 6）。省略可。
	Name string

	// AccessTokenFormat はこの resource 向け Access Token の形式。空なら FormatOpaque。
	AccessTokenFormat Format

	// Scopes はこの resource 向けのトークンに付けられる scope の上限。空なら制限しない。
	// 要求の絞り込みはトークン発行側（M3 タスク 2）で行う。
	Scopes []string
}

// Validate は設定値の形式を検証する。
func (r *Resource) Validate() error {
	if _, err := Normalize(r.URI); err != nil {
		return err
	}
	if !r.AccessTokenFormat.Valid() {
		return fmt.Errorf("%w: unknown access token format %q for %s", ErrInvalid, r.AccessTokenFormat, r.URI)
	}
	seen := make(map[string]struct{}, len(r.Scopes))
	for _, s := range r.Scopes {
		if !validScopeToken(s) {
			return fmt.Errorf("%w: invalid scope token %q for %s", ErrInvalid, s, r.URI)
		}
		if _, dup := seen[s]; dup {
			return fmt.Errorf("%w: duplicate scope %q for %s", ErrInvalid, s, r.URI)
		}
		seen[s] = struct{}{}
	}
	return nil
}

// EffectiveFormat は既定値を適用した Access Token の形式を返す。
func (r *Resource) EffectiveFormat() Format {
	if r.AccessTokenFormat == "" {
		return FormatOpaque
	}
	return r.AccessTokenFormat
}

// Normalize は resource indicator を検証し、比較に使う正規形を返す。
//
// RFC 8707 §2: 絶対 URI（RFC 3986 §4.3）であり fragment を含まないこと。query は許すが推奨しない。
// 正規化は scheme と host の小文字化だけ（RFC 3986 §6.2.2.1）。MCP 仕様「Canonical Server URI」が
// 大文字の受理を求めるため。path の大文字小文字と末尾スラッシュの有無は区別する
// （https://mcp.example.com と https://mcp.example.com/ は別の resource）。
func Normalize(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalid)
	}
	// "#" は fragment の区切りにしか使えないので、空 fragment（末尾の "#"）も含めて拒否する。
	if strings.Contains(raw, "#") {
		return "", fmt.Errorf("%w: %q must not contain a fragment", ErrInvalid, raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrInvalid, raw, err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("%w: %q must be an absolute URI", ErrInvalid, raw)
	}
	// scheme ":" だけ、または "scheme:///path" のような authority も opaque 部分もない URI は拒否する。
	if u.Host == "" && u.Opaque == "" {
		return "", fmt.Errorf("%w: %q must have a host", ErrInvalid, raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

// Set は設定された Resource の集合。URI の正規形で引く。
//
// nil の *Set は空集合として振る舞う（Resource Server を 1 つも設定していない構成）。
type Set struct {
	byURI map[string]*Resource
	uris  []string // 設定順
}

// NewSet は Resource の一覧を検証し、URI を正規化して Set を作る。
func NewSet(rs []Resource) (*Set, error) {
	s := &Set{byURI: make(map[string]*Resource, len(rs))}
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		uri, _ := Normalize(r.URI) // Validate 済み
		if _, dup := s.byURI[uri]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicate, uri)
		}
		stored := r
		stored.URI = uri
		stored.Scopes = slices.Clone(r.Scopes)
		s.byURI[uri] = &stored
		s.uris = append(s.uris, uri)
	}
	return s, nil
}

// Lookup は resource indicator に対応する設定を返す。raw は正規化して照合する。
// 構文違反、または未設定なら ok が false。
func (s *Set) Lookup(raw string) (r *Resource, ok bool) {
	if s == nil {
		return nil, false
	}
	uri, err := Normalize(raw)
	if err != nil {
		return nil, false
	}
	r, ok = s.byURI[uri]
	return r, ok
}

// Len は設定された Resource の数を返す。
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.uris)
}

// URIs は設定順の正規化済み URI を返す。
func (s *Set) URIs() []string {
	if s == nil {
		return nil
	}
	return slices.Clone(s.uris)
}

// validScopeToken は RFC 6749 §3.3 の scope-token 構文（client.ValidScopeToken と同じ規則）。
// このパッケージは client を import しない葉パッケージなので、規則をここにも持つ。
func validScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == 0x21, ch >= 0x23 && ch <= 0x5B, ch >= 0x5D && ch <= 0x7E:
		default:
			return false
		}
	}
	return true
}
