package client

// Profile はクライアントの用途を表し、RFC 6749 の個別設定を一括で決める。
type Profile string

const (
	// ProfileWeb はサーバー側でシークレットを保持できる Web アプリケーション（confidential）。
	ProfileWeb Profile = "web"
	// ProfileNative はモバイル・デスクトップ・CLI などシークレットを保持できないアプリ（public）。
	ProfileNative Profile = "native"
	// ProfileMachine はユーザーを介さないサービス間通信（confidential、client_credentials のみ）。
	ProfileMachine Profile = "machine"
)

// GrantType は RFC 6749 §4 / §6 の grant_type パラメータ値。
type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantClientCredentials GrantType = "client_credentials"
)

// AuthMethod はトークンエンドポイントでのクライアント認証方式
// （OIDC Core §9 / RFC 7591 の token_endpoint_auth_method 値）。
type AuthMethod string

const (
	AuthClientSecretBasic AuthMethod = "client_secret_basic"
	AuthClientSecretPost  AuthMethod = "client_secret_post"
	AuthNone              AuthMethod = "none"
)

// redirectPolicy は redirect URI の登録・照合規則の種別。
type redirectPolicy int

const (
	// redirectNone は redirect URI を持たない（Machine）。
	redirectNone redirectPolicy = iota
	// redirectWeb は https の完全一致。開発用に http://localhost / loopback を許可できる。
	redirectWeb
	// redirectNative は https（クレーム URL）、カスタムスキーム、http loopback（port 無視）。
	redirectNative
)

// rules は Profile ごとに固定する条件表。ADR-0004 §1 の表と 1 対 1 で対応する。
// 実装がこの表に従っていることは profile_test.go で検証する。
type rules struct {
	confidential       bool
	grantTypes         []GrantType
	authMethods        []AuthMethod
	requirePKCE        bool
	issuesRefreshToken bool
	issuesIDToken      bool
	redirect           redirectPolicy
}

var profileRules = map[Profile]rules{
	ProfileWeb: {
		confidential:       true,
		grantTypes:         []GrantType{GrantAuthorizationCode, GrantRefreshToken},
		authMethods:        []AuthMethod{AuthClientSecretBasic, AuthClientSecretPost},
		requirePKCE:        true,
		issuesRefreshToken: true,
		issuesIDToken:      true,
		redirect:           redirectWeb,
	},
	ProfileNative: {
		confidential:       false,
		grantTypes:         []GrantType{GrantAuthorizationCode, GrantRefreshToken},
		authMethods:        []AuthMethod{AuthNone},
		requirePKCE:        true,
		issuesRefreshToken: true,
		issuesIDToken:      true,
		redirect:           redirectNative,
	},
	ProfileMachine: {
		confidential:       true,
		grantTypes:         []GrantType{GrantClientCredentials},
		authMethods:        []AuthMethod{AuthClientSecretBasic, AuthClientSecretPost},
		requirePKCE:        false,
		issuesRefreshToken: false,
		issuesIDToken:      false,
		redirect:           redirectNone,
	},
}

// Valid は既知の Profile かを返す。
func (p Profile) Valid() bool {
	_, ok := profileRules[p]
	return ok
}

func (p Profile) rules() rules {
	return profileRules[p]
}
