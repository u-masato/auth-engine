package client

import (
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode"

	"github.com/muno/auth-engine/internal/rand"
)

// トークン有効期間の既定値と上限（ADR-0004 §2）。
const (
	DefaultAccessTokenTTL = time.Hour
	MinAccessTokenTTL     = time.Minute
	MaxAccessTokenTTL     = 24 * time.Hour
)

// ID Token の署名アルゴリズム（ADR-0002）。
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// ErrInvalid は Client の登録情報が Profile の規則に違反していることを表す。
// 具体的な違反内容は fmt.Errorf で付加される。
var ErrInvalid = errors.New("client: invalid client")

// Secret はクライアントシークレットの平文。生成時に 1 回だけ返し、保存はハッシュのみ。
type Secret string

// Client は登録済みの OAuth 2.0 クライアント。
//
// 構築は NewWeb / NewNative / NewMachine で行う。フィールドは Adapter の直列化・復元の
// ために公開しているが、コア内では直接代入せず、復元後は Validate で検証する。
type Client struct {
	ID      string
	Profile Profile

	// 表示情報。Interaction App が同意画面で使う。
	Name      string
	LogoURI   string
	PolicyURI string

	// RedirectURIs は登録済みの redirect URI。Machine では空。
	RedirectURIs []string

	// Scopes はこのクライアントが要求できる scope の上限。
	Scopes []string

	// SecretHash はクライアントシークレットの SHA-256（16 進）。public クライアントでは空。
	SecretHash string

	// AccessTokenTTL は Access Token の有効期間。0 なら DefaultAccessTokenTTL。
	AccessTokenTTL time.Duration

	// IDTokenAlg は ID Token の署名アルゴリズム。Web / Native では RS256 か ES256、Machine では空。
	IDTokenAlg string

	// AllowInsecureLocalhost は開発用の緩和。Web では http://localhost と http loopback を、
	// Native では http://localhost（RFC 8252 §8.3 で非推奨）を redirect URI として許可する。
	AllowInsecureLocalhost bool

	CreatedAt time.Time
}

// WebParams は NewWeb の入力。
type WebParams struct {
	ID                     string // 空なら生成
	Name                   string
	RedirectURIs           []string
	Scopes                 []string
	LogoURI                string
	PolicyURI              string
	AccessTokenTTL         time.Duration // 0 なら既定
	IDTokenAlg             string        // 空なら RS256
	AllowInsecureLocalhost bool
}

// NativeParams は NewNative の入力。
type NativeParams struct {
	ID                     string
	Name                   string
	RedirectURIs           []string
	Scopes                 []string
	LogoURI                string
	PolicyURI              string
	AccessTokenTTL         time.Duration
	IDTokenAlg             string
	AllowInsecureLocalhost bool
}

// MachineParams は NewMachine の入力。
type MachineParams struct {
	ID             string
	Name           string
	Scopes         []string
	AccessTokenTTL time.Duration
}

// NewWeb は Web Application Profile の confidential クライアントを作る。
// 生成したシークレットの平文は戻り値でのみ得られる。
func NewWeb(p WebParams, now time.Time) (*Client, Secret, error) {
	c := &Client{
		ID:                     p.ID,
		Profile:                ProfileWeb,
		Name:                   p.Name,
		LogoURI:                p.LogoURI,
		PolicyURI:              p.PolicyURI,
		RedirectURIs:           slices.Clone(p.RedirectURIs),
		Scopes:                 slices.Clone(p.Scopes),
		AccessTokenTTL:         p.AccessTokenTTL,
		IDTokenAlg:             p.IDTokenAlg,
		AllowInsecureLocalhost: p.AllowInsecureLocalhost,
		CreatedAt:              now,
	}
	secret, err := c.finish()
	if err != nil {
		return nil, "", err
	}
	return c, secret, nil
}

// NewNative は Native / CLI Profile の public クライアントを作る。
func NewNative(p NativeParams, now time.Time) (*Client, error) {
	c := &Client{
		ID:                     p.ID,
		Profile:                ProfileNative,
		Name:                   p.Name,
		LogoURI:                p.LogoURI,
		PolicyURI:              p.PolicyURI,
		RedirectURIs:           slices.Clone(p.RedirectURIs),
		Scopes:                 slices.Clone(p.Scopes),
		AccessTokenTTL:         p.AccessTokenTTL,
		IDTokenAlg:             p.IDTokenAlg,
		AllowInsecureLocalhost: p.AllowInsecureLocalhost,
		CreatedAt:              now,
	}
	if _, err := c.finish(); err != nil {
		return nil, err
	}
	return c, nil
}

// NewMachine は Machine to Machine Profile の confidential クライアントを作る。
func NewMachine(p MachineParams, now time.Time) (*Client, Secret, error) {
	c := &Client{
		ID:             p.ID,
		Profile:        ProfileMachine,
		Name:           p.Name,
		Scopes:         slices.Clone(p.Scopes),
		AccessTokenTTL: p.AccessTokenTTL,
		CreatedAt:      now,
	}
	secret, err := c.finish()
	if err != nil {
		return nil, "", err
	}
	return c, secret, nil
}

// finish は既定値の補完、ID・シークレットの生成、検証を行う。
func (c *Client) finish() (Secret, error) {
	r := c.Profile.rules()

	if c.ID == "" {
		id, err := rand.Token("")
		if err != nil {
			return "", err
		}
		c.ID = id
	}
	if r.issuesIDToken && c.IDTokenAlg == "" {
		c.IDTokenAlg = AlgRS256
	}

	var secret Secret
	if r.confidential {
		s, err := rand.Token("")
		if err != nil {
			return "", err
		}
		secret = Secret(s)
		c.SecretHash = rand.Hash(s)
	}

	if err := c.Validate(); err != nil {
		return "", err
	}
	return secret, nil
}

// Validate は Client が Profile の規則を満たすかを検証する。
// コンストラクタが呼ぶほか、Adapter から復元した値の防御的検証にも使う。
func (c *Client) Validate() error {
	if !c.Profile.Valid() {
		return fmt.Errorf("%w: unknown profile %q", ErrInvalid, c.Profile)
	}
	r := c.Profile.rules()

	if err := validateID(c.ID); err != nil {
		return err
	}
	if c.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if err := validateScopes(c.Scopes); err != nil {
		return err
	}
	if err := validateRedirectURIs(r.redirect, c.RedirectURIs, c.AllowInsecureLocalhost); err != nil {
		return err
	}

	if r.confidential && c.SecretHash == "" {
		return fmt.Errorf("%w: confidential client requires a secret", ErrInvalid)
	}
	if !r.confidential && c.SecretHash != "" {
		return fmt.Errorf("%w: public client must not have a secret", ErrInvalid)
	}

	if c.AccessTokenTTL != 0 && (c.AccessTokenTTL < MinAccessTokenTTL || c.AccessTokenTTL > MaxAccessTokenTTL) {
		return fmt.Errorf("%w: access token ttl must be within [%s, %s]", ErrInvalid, MinAccessTokenTTL, MaxAccessTokenTTL)
	}

	switch {
	case r.issuesIDToken && c.IDTokenAlg != AlgRS256 && c.IDTokenAlg != AlgES256:
		return fmt.Errorf("%w: id token alg must be %s or %s", ErrInvalid, AlgRS256, AlgES256)
	case !r.issuesIDToken && c.IDTokenAlg != "":
		return fmt.Errorf("%w: profile %q does not issue id tokens", ErrInvalid, c.Profile)
	}
	return nil
}

func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if len(id) > 255 {
		return fmt.Errorf("%w: id longer than 255 bytes", ErrInvalid)
	}
	for _, ch := range id {
		if ch > unicode.MaxASCII || unicode.IsControl(ch) || unicode.IsSpace(ch) {
			return fmt.Errorf("%w: id must be printable ASCII without whitespace", ErrInvalid)
		}
	}
	return nil
}

// IsPublic は RFC 6749 §2.1 の public クライアントかを返す。
func (c *Client) IsPublic() bool { return !c.Profile.rules().confidential }

// Allows は grant_type をこのクライアントに許可しているかを返す。
func (c *Client) Allows(gt GrantType) bool {
	return slices.Contains(c.Profile.rules().grantTypes, gt)
}

// AcceptsAuthMethod はトークンエンドポイントでの認証方式を受理するかを返す。
func (c *Client) AcceptsAuthMethod(m AuthMethod) bool {
	return slices.Contains(c.Profile.rules().authMethods, m)
}

// RequiresPKCE は Authorization Code Grant で PKCE（S256）を必須とするかを返す。
func (c *Client) RequiresPKCE() bool { return c.Profile.rules().requirePKCE }

// IssuesRefreshToken は Refresh Token を発行するかを返す。
func (c *Client) IssuesRefreshToken() bool { return c.Profile.rules().issuesRefreshToken }

// IssuesIDToken は openid scope 要求時に ID Token を発行できるかを返す。
func (c *Client) IssuesIDToken() bool { return c.Profile.rules().issuesIDToken }

// EffectiveAccessTokenTTL は Access Token の有効期間（既定値を適用済み）を返す。
func (c *Client) EffectiveAccessTokenTTL() time.Duration {
	if c.AccessTokenTTL == 0 {
		return DefaultAccessTokenTTL
	}
	return c.AccessTokenTTL
}

// VerifySecret は提示されたシークレットを定数時間で検証する。public クライアントでは常に false。
func (c *Client) VerifySecret(presented string) bool {
	if c.SecretHash == "" || presented == "" {
		return false
	}
	return rand.HashEqual(c.SecretHash, presented)
}
