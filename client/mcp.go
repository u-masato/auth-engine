package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// MetadataDocument は CIMD（Client ID Metadata Document）の内容。フィールド名は RFC 7591 §2 の
// クライアントメタデータに従う（CIMD §4）。cimd パッケージが取得して JSON を復号し、NewMCP が検証する。
//
// ここに挙げないフィールド（jwks、jwks_uri、contacts、software_id 等）は無視する。
type MetadataDocument struct {
	// ClientID は文書の URL と単純文字列比較で一致しなければならない（CIMD §4）。
	ClientID string `json:"client_id"`
	// ClientName は同意画面に表示する名前。必須（MCP 仕様「Client Registration」）。
	ClientName string `json:"client_name"`
	ClientURI  string `json:"client_uri,omitempty"`
	LogoURI    string `json:"logo_uri,omitempty"`
	PolicyURI  string `json:"policy_uri,omitempty"`
	// RedirectURIs は必須。認可要求の redirect_uri はこのいずれかと完全一致すること（CIMD §4.2）。
	RedirectURIs []string `json:"redirect_uris"`
	// Scope は空白区切り。省略なら Client の scope 上限を持たない（resource ごとの上限だけが効く）。
	Scope string `json:"scope,omitempty"`
	// GrantTypes / ResponseTypes は Profile の固定値（authorization_code, refresh_token / code）と
	// 矛盾しないことだけを確認する。Profile は変えない（ADR-0004 §5）。
	GrantTypes    []string `json:"grant_types,omitempty"`
	ResponseTypes []string `json:"response_types,omitempty"`
	// TokenEndpointAuthMethod は省略か none。private_key_jwt は M4 で受理する（CIMD §4.1、ADR-0008 §5）。
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// 共有シークレットは CIMD 文書に置けない（CIMD §4.1）。存在すれば拒否するためだけに復号する。
	ClientSecret          string          `json:"client_secret,omitempty"`
	ClientSecretExpiresAt json.RawMessage `json:"client_secret_expires_at,omitempty"`
}

// ErrNotMetadataURL は client_id が CIMD の Client Identifier URL の形式（CIMD §3）でないことを表す。
// cimd.Resolver はこのとき storage.ErrNotFound を返し、Store だけで解決した場合と区別しない。
var ErrNotMetadataURL = errors.New("client: client_id is not a client id metadata document url")

// ParseClientIDURL は client_id が CIMD の Client Identifier URL（CIMD §3）かを判定し、解析結果を返す。
//
//   - https であること
//   - userinfo を含まないこと
//   - path を持つこと（"/" だけは NOT RECOMMENDED だが受理する）
//   - "." / ".." のパスセグメントを含まないこと
//   - fragment を含まないこと
//
// query は SHOULD NOT だが拒否しない。これらを満たさない値は ErrNotMetadataURL で、Store に登録された
// 通常の client_id として扱う。Store が発行する client_id は https:// で始めない（CIMD §7）。
func ParseClientIDURL(id string) (*url.URL, error) {
	if !strings.HasPrefix(id, "https://") {
		return nil, fmt.Errorf("%w: scheme must be https", ErrNotMetadataURL)
	}
	u, err := url.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotMetadataURL, err)
	}
	switch {
	case u.Hostname() == "": // scheme は上の接頭辞で https に決まっている
		return nil, fmt.Errorf("%w: scheme must be https with a host", ErrNotMetadataURL)
	case u.User != nil:
		return nil, fmt.Errorf("%w: userinfo is not allowed", ErrNotMetadataURL)
	case u.Path == "":
		return nil, fmt.Errorf("%w: a path component is required", ErrNotMetadataURL)
	case strings.Contains(id, "#"): // 空の fragment（末尾の "#"）も拒否する
		return nil, fmt.Errorf("%w: fragment is not allowed", ErrNotMetadataURL)
	}
	// パーセントエンコードした "."（%2e）は "." と同じ（RFC 3986 §2.3、§6.2.2.2）。文書サーバーが復号して
	// 別の path を返したり、path で判断する TrustPolicy をすり抜けたりしないよう、復号後の path も確かめる。
	// 復号で %2F が "/" に変わり、エンコードした形では 1 セグメントだったものも拒否されるが、安全側に倒す。
	for _, p := range []string{u.EscapedPath(), u.Path} {
		for seg := range strings.SplitSeq(p, "/") {
			if seg == "." || seg == ".." {
				return nil, fmt.Errorf("%w: dot segments are not allowed", ErrNotMetadataURL)
			}
		}
	}
	return u, nil
}

// NewMCP は CIMD 文書から MCP Client Profile の public クライアントを組み立てる（ADR-0008 §4、§5）。
//
// documentURL は文書を取得した URL。文書の client_id はこれと単純文字列比較で一致しなければならない
// （CIMD §4）。ネットワークには触れず、検証だけを行う。失敗は ErrInvalid。
func NewMCP(doc MetadataDocument, documentURL string, now time.Time) (*Client, error) {
	if _, err := ParseClientIDURL(doc.ClientID); err != nil {
		return nil, fmt.Errorf("%w: client_id %q: %v", ErrInvalid, doc.ClientID, err)
	}
	if doc.ClientID != documentURL {
		return nil, fmt.Errorf("%w: client_id %q does not match the document url %q", ErrInvalid, doc.ClientID, documentURL)
	}
	// 文書の値は Profile 表の固定値と矛盾しないことだけを確認する（ADR-0004 §1）。
	rules := ProfileMCP.rules()
	// CIMD §4.1: 共有シークレットに基づく認証方式とシークレット自体を含む文書は拒否する
	// （MCP Profile の認証方式は none だけ）。
	if m := doc.TokenEndpointAuthMethod; m != "" && !slices.Contains(rules.authMethods, AuthMethod(m)) {
		return nil, fmt.Errorf("%w: token_endpoint_auth_method %q is not supported for metadata document clients", ErrInvalid, doc.TokenEndpointAuthMethod)
	}
	if doc.ClientSecret != "" || len(doc.ClientSecretExpiresAt) != 0 {
		return nil, fmt.Errorf("%w: a metadata document must not contain client_secret", ErrInvalid)
	}
	for _, gt := range doc.GrantTypes {
		if !slices.Contains(rules.grantTypes, GrantType(gt)) {
			return nil, fmt.Errorf("%w: grant_type %q is not supported for mcp clients", ErrInvalid, gt)
		}
	}
	for _, rt := range doc.ResponseTypes {
		if rt != "code" {
			return nil, fmt.Errorf("%w: response_type %q is not supported", ErrInvalid, rt)
		}
	}
	if doc.ClientURI != "" {
		if u, err := url.Parse(doc.ClientURI); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("%w: client_uri must be an absolute http(s) URL", ErrInvalid)
		}
	}

	c := &Client{
		ID:           doc.ClientID,
		Profile:      ProfileMCP,
		Name:         doc.ClientName,
		ClientURI:    doc.ClientURI,
		LogoURI:      doc.LogoURI,
		PolicyURI:    doc.PolicyURI,
		RedirectURIs: slices.Clone(doc.RedirectURIs),
		Scopes:       strings.Fields(doc.Scope),
		CreatedAt:    now,
	}
	if _, err := c.finish(""); err != nil {
		return nil, err
	}
	return c, nil
}
