package oidc

// StandardScopes は OIDC Core §5.4 で定義される scope。Discovery の scopes_supported に使う。
var StandardScopes = []string{"openid", "profile", "email", "address", "phone"}

// scopeClaims は OIDC Core §5.4 の scope → Claims 対応表。
var scopeClaims = map[string][]string{
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username",
		"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// standardClaims は上の表の全 Claims 名。
var standardClaims = func() map[string]string {
	m := map[string]string{}
	for scope, names := range scopeClaims {
		for _, n := range names {
			m[n] = scope
		}
	}
	return m
}()

// reservedClaims は Interaction App が上書きできない、エンジンが決める Claims（RFC 7519 §4.1、OIDC §2）。
var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
	"auth_time": true, "nonce": true, "at_hash": true, "c_hash": true, "azp": true, "amr": true, "acr": true,
}

// ClaimsSupported は Discovery の claims_supported に載せる Claims 名。
func ClaimsSupported() []string {
	out := []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "amr", "acr"}
	for _, scope := range []string{"profile", "email", "address", "phone"} {
		out = append(out, scopeClaims[scope]...)
	}
	return out
}

// FilterClaims は Grant に保存された Claims を、付与された scope で絞る。
//
//   - OIDC Core §5.4 の標準 Claims は、対応する scope が付与されているときだけ残す。
//   - 標準外の Claims（Interaction App 独自のもの）はそのまま残す。渡すかどうかの判断は
//     Interaction App 側で行う（docs/interaction-api.md）。
//   - iss / sub / aud などエンジンが決める予約 Claims は常に除く。
func FilterClaims(claims map[string]any, grantedScopes []string) map[string]any {
	granted := map[string]bool{}
	for _, s := range grantedScopes {
		granted[s] = true
	}
	out := make(map[string]any, len(claims))
	for name, v := range claims {
		if reservedClaims[name] {
			continue
		}
		if scope, standard := standardClaims[name]; standard && !granted[scope] {
			continue
		}
		out[name] = v
	}
	return out
}
