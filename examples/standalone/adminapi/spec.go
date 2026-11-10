package adminapi

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/client"
)

// ClientSpec は Client の JSON 表現。管理 API の登録・取得・更新と、cmd/server の -clients で読む
// ファイルの 1 要素が同じ形を使う。GET で得たものを書き換えて PUT に渡せる。
//
// SecretHash は含めない。シークレットの平文（client_secret）は、登録と再発行の応答にだけ入る。
type ClientSpec struct {
	// ClientID は登録時に省略すると生成する。更新時は省略するか、パスの client_id と同じ値にする。
	ClientID string `json:"client_id,omitempty"`
	// Profile は web / native / machine / mcp。登録後は変えられない（ADR-0004 §4）。
	Profile string `json:"profile"`
	Name    string `json:"name"`
	// RedirectURIs は Machine では空。
	RedirectURIs []string `json:"redirect_uris"`
	// Scopes はこの Client が要求できる scope の上限。
	Scopes []string `json:"scopes"`
	// Resources は要求できる resource（RFC 8707）の上限。空なら設定済みの全部。
	Resources []string `json:"resources"`
	LogoURI   string   `json:"logo_uri,omitempty"`
	PolicyURI string   `json:"policy_uri,omitempty"`
	// ClientURI は mcp だけが持つ（CIMD 文書の client_uri）。登録後は変えられない。
	ClientURI string `json:"client_uri,omitempty"`
	// AccessTokenTTL は Access Token の有効期間（秒）。0 なら既定値（client.DefaultAccessTokenTTL）。
	AccessTokenTTL int64 `json:"access_token_ttl"`
	// IDTokenAlg は RS256 / ES256。ID Token を発行する Profile で省略すると RS256。
	IDTokenAlg             string `json:"id_token_alg,omitempty"`
	AllowInsecureLocalhost bool   `json:"allow_insecure_localhost"`

	// ClientSecret は web / machine のシークレット。登録時に指定すると（32 バイト以上）その値を使い、
	// 省略すると生成する。応答では登録と再発行のときだけ入る。更新では指定できない。
	ClientSecret string `json:"client_secret,omitempty"`

	// CreatedAt は応答にだけ入る。要求にあっても無視する（GET の結果をそのまま PUT に渡せるようにするため）。
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// SpecOf は Client を ClientSpec にする。シークレットは含めない。
func SpecOf(c *client.Client) ClientSpec {
	created := c.CreatedAt.UTC() // 登録直後（ローカル時刻）と Store から読んだ後で同じ表記にする
	return ClientSpec{
		ClientID:               c.ID,
		Profile:                string(c.Profile),
		Name:                   c.Name,
		RedirectURIs:           nonNil(c.RedirectURIs),
		Scopes:                 nonNil(c.Scopes),
		Resources:              nonNil(c.Resources),
		LogoURI:                c.LogoURI,
		PolicyURI:              c.PolicyURI,
		ClientURI:              c.ClientURI,
		AccessTokenTTL:         int64(c.AccessTokenTTL / time.Second),
		IDTokenAlg:             c.IDTokenAlg,
		AllowInsecureLocalhost: c.AllowInsecureLocalhost,
		CreatedAt:              &created,
	}
}

// nonNil は nil を空のスライスにする（JSON で null ではなく [] を返すため）。
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ttl は access_token_ttl（秒）を time.Duration にする。範囲の検査は client.Client.Validate が行うが、
// 秒からの換算で桁あふれしないよう、明らかに範囲外の値はここで落とす。
func (sp ClientSpec) ttl() (time.Duration, error) {
	if sp.AccessTokenTTL < 0 || sp.AccessTokenTTL > int64(client.MaxAccessTokenTTL/time.Second) {
		return 0, fmt.Errorf("%w: access_token_ttl must be within [%d, %d] seconds (0 means the default)", client.ErrInvalid,
			int64(client.MinAccessTokenTTL/time.Second), int64(client.MaxAccessTokenTTL/time.Second))
	}
	return time.Duration(sp.AccessTokenTTL) * time.Second, nil
}

// NewClient は Profile ごとのコンストラクタで Client を作る。grant_type・認証方式・redirect URI の
// 規則はコンストラクタが検証する（docs/adr/0004-client-profiles.md）。
//
// Profile が持たない項目（native の client_secret、machine の redirect_uris など）が指定されていたら、
// 黙って捨てずに client.ErrInvalid にする。API の呼び出し側が、指定した内容で登録されたと誤解しないため。
func (sp ClientSpec) NewClient(now time.Time) (*client.Client, client.Secret, error) {
	ttl, err := sp.ttl()
	if err != nil {
		return nil, "", err
	}
	unsupported := func(fields ...string) error {
		return fmt.Errorf("%w: profile %q does not take %s", client.ErrInvalid, sp.Profile, strings.Join(fields, ", "))
	}
	profile := client.Profile(sp.Profile)
	if sp.ClientURI != "" && profile != client.ProfileMCP {
		return nil, "", unsupported("client_uri")
	}
	switch profile {
	case client.ProfileWeb:
		return client.NewWeb(client.WebParams{ID: sp.ClientID, Name: sp.Name, Secret: sp.ClientSecret, RedirectURIs: sp.RedirectURIs,
			Scopes: sp.Scopes, Resources: sp.Resources, LogoURI: sp.LogoURI, PolicyURI: sp.PolicyURI, AccessTokenTTL: ttl,
			IDTokenAlg: sp.IDTokenAlg, AllowInsecureLocalhost: sp.AllowInsecureLocalhost}, now)
	case client.ProfileNative:
		if sp.ClientSecret != "" {
			return nil, "", unsupported("client_secret")
		}
		c, err := client.NewNative(client.NativeParams{ID: sp.ClientID, Name: sp.Name, RedirectURIs: sp.RedirectURIs,
			Scopes: sp.Scopes, Resources: sp.Resources, LogoURI: sp.LogoURI, PolicyURI: sp.PolicyURI, AccessTokenTTL: ttl,
			IDTokenAlg: sp.IDTokenAlg, AllowInsecureLocalhost: sp.AllowInsecureLocalhost}, now)
		return c, "", err
	case client.ProfileMachine:
		if len(sp.RedirectURIs) > 0 || sp.LogoURI != "" || sp.PolicyURI != "" || sp.IDTokenAlg != "" || sp.AllowInsecureLocalhost {
			return nil, "", unsupported("redirect_uris", "logo_uri", "policy_uri", "id_token_alg", "allow_insecure_localhost")
		}
		return client.NewMachine(client.MachineParams{ID: sp.ClientID, Name: sp.Name, Secret: sp.ClientSecret, Scopes: sp.Scopes,
			Resources: sp.Resources, AccessTokenTTL: ttl}, now)
	case client.ProfileMCP:
		// URL 形式の client_id を事前登録する経路（CIMD §7）。文書は取得せず、ここに書いた内容が登録情報になる。
		// Store にあるものが CIMD より優先される（client.ChainResolver）。NewMCP は CIMD 文書の項目だけを
		// 受け取るので、それ以外の開放項目は、組み立てた後に Update で当てる（検証は同じものが通る）。
		if sp.ClientSecret != "" {
			return nil, "", unsupported("client_secret")
		}
		// CIMD 文書の scope は空白区切りの 1 つの文字列なので、空白を含む値は 2 つの scope に分かれてしまう
		if slices.ContainsFunc(sp.Scopes, func(s string) bool { return s == "" || strings.ContainsAny(s, " \t\r\n") }) {
			return nil, "", fmt.Errorf("%w: scopes must not be empty or contain whitespace", client.ErrInvalid)
		}
		c, err := client.NewMCP(client.MetadataDocument{ClientID: sp.ClientID, ClientName: sp.Name, ClientURI: sp.ClientURI,
			LogoURI: sp.LogoURI, PolicyURI: sp.PolicyURI, RedirectURIs: sp.RedirectURIs, Scope: strings.Join(sp.Scopes, " ")}, sp.ClientID, now)
		if err != nil {
			return nil, "", err
		}
		p := c.UpdateParams()
		p.Resources, p.AccessTokenTTL, p.AllowInsecureLocalhost = sp.Resources, ttl, sp.AllowInsecureLocalhost
		if sp.IDTokenAlg != "" {
			p.IDTokenAlg = sp.IDTokenAlg
		}
		c, err = c.Update(p)
		return c, "", err
	}
	return nil, "", fmt.Errorf("%w: unknown profile %q", client.ErrInvalid, sp.Profile)
}

// UpdateParams は cur を sp の内容で置き換えるための client.UpdateParams を返す。
// 開放項目（ADR-0004 §2）はすべて sp の値になる（部分更新ではない）。変えられない項目は、
// 省略するか現在値と同じでなければ client.ErrInvalid。
func (sp ClientSpec) UpdateParams(cur *client.Client) (client.UpdateParams, error) {
	immutable := func(field string) error {
		return fmt.Errorf("%w: %s cannot be changed", client.ErrInvalid, field)
	}
	switch {
	case sp.ClientID != "" && sp.ClientID != cur.ID:
		return client.UpdateParams{}, immutable("client_id")
	case sp.Profile != "" && sp.Profile != string(cur.Profile):
		return client.UpdateParams{}, immutable("profile (register a new client instead)")
	case sp.ClientURI != "" && sp.ClientURI != cur.ClientURI:
		return client.UpdateParams{}, immutable("client_uri")
	case sp.ClientSecret != "":
		return client.UpdateParams{}, immutable("client_secret (use POST /clients/{id}/secret to rotate it)")
	}
	ttl, err := sp.ttl()
	if err != nil {
		return client.UpdateParams{}, err
	}
	return client.UpdateParams{
		Name:                   sp.Name,
		LogoURI:                sp.LogoURI,
		PolicyURI:              sp.PolicyURI,
		RedirectURIs:           sp.RedirectURIs,
		Scopes:                 sp.Scopes,
		Resources:              sp.Resources,
		AccessTokenTTL:         ttl,
		IDTokenAlg:             sp.IDTokenAlg,
		AllowInsecureLocalhost: sp.AllowInsecureLocalhost,
	}, nil
}
