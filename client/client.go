package client

import (
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode"

	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/resource"
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

// Client は登録済み、または CIMD 文書から解決した OAuth 2.0 クライアント。
//
// 構築は NewWeb / NewNative / NewMachine / NewMCP で行う。フィールドは Adapter の直列化・復元の
// ために公開しているが、コア内では直接代入せず、復元後は Validate で検証する。
type Client struct {
	ID      string
	Profile Profile

	// 表示情報。Interaction App が同意画面で使う。
	Name      string
	LogoURI   string
	PolicyURI string
	// ClientURI はクライアントのホームページ（RFC 7591 §2 の client_uri）。CIMD 文書から組み立てた
	// MCP Client だけが持ち、登録済み Client では空（ADR-0008 §6）。
	ClientURI string

	// RedirectURIs は登録済みの redirect URI。Machine では空。
	RedirectURIs []string

	// Scopes はこのクライアントが要求できる scope の上限。
	Scopes []string

	// Resources はこのクライアントが要求できる resource（RFC 8707）の上限（ADR-0004 §2、ADR-0008 §2）。
	// 空なら Engine に設定された全 resource を要求できる。値は resource.Normalize の正規形で保持する。
	Resources []string

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
	ID   string // 空なら生成
	Name string
	// Secret は空なら生成する。既存システムからの移行や Conformance Suite のように
	// 事前に決まったシークレットが必要なときだけ指定する。32 バイト以上であること。
	Secret                 string
	RedirectURIs           []string
	Scopes                 []string
	Resources              []string // 空なら制限なし
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
	Resources              []string // 空なら制限なし
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
	Secret         string // 空なら生成（WebParams.Secret と同じ）
	Scopes         []string
	Resources      []string // 空なら制限なし
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
		Resources:              slices.Clone(p.Resources),
		AccessTokenTTL:         p.AccessTokenTTL,
		IDTokenAlg:             p.IDTokenAlg,
		AllowInsecureLocalhost: p.AllowInsecureLocalhost,
		CreatedAt:              now,
	}
	secret, err := c.finish(p.Secret)
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
		Resources:              slices.Clone(p.Resources),
		AccessTokenTTL:         p.AccessTokenTTL,
		IDTokenAlg:             p.IDTokenAlg,
		AllowInsecureLocalhost: p.AllowInsecureLocalhost,
		CreatedAt:              now,
	}
	if _, err := c.finish(""); err != nil {
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
		Resources:      slices.Clone(p.Resources),
		AccessTokenTTL: p.AccessTokenTTL,
		CreatedAt:      now,
	}
	secret, err := c.finish(p.Secret)
	if err != nil {
		return nil, "", err
	}
	return c, secret, nil
}

// MinSecretLength は利用者が指定するシークレットの最小長（バイト）。生成するシークレットは
// 256 bit 乱数の base64url（43 文字）なので、それに見合う長さを求める。
const MinSecretLength = 32

// finish は既定値の補完、ID・シークレットの生成（presented が空のとき）、検証を行う。
func (c *Client) finish(presented string) (Secret, error) {
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
	for i, res := range c.Resources {
		n, err := resource.Normalize(res)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		c.Resources[i] = n
	}

	var secret Secret
	switch {
	case r.confidential && presented != "":
		if len(presented) < MinSecretLength {
			return "", fmt.Errorf("%w: secret must be at least %d bytes", ErrInvalid, MinSecretLength)
		}
		secret = Secret(presented)
		c.SecretHash = rand.Hash(presented)
	case r.confidential:
		s, err := rand.Token("")
		if err != nil {
			return "", err
		}
		secret = Secret(s)
		c.SecretHash = rand.Hash(s)
	case presented != "":
		return "", fmt.Errorf("%w: public client must not have a secret", ErrInvalid)
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
	if err := validateScopes(c.Scopes, r.scopesOptional); err != nil {
		return err
	}
	if err := validateRedirectURIs(r.redirect, c.RedirectURIs, c.AllowInsecureLocalhost); err != nil {
		return err
	}
	if err := validateResources(c.Resources); err != nil {
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

// RequiresResource は認可要求に resource（RFC 8707）を必須とするかを返す（MCP Profile。ADR-0008 §4）。
func (c *Client) RequiresResource() bool { return c.Profile.rules().requiresResource }

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
