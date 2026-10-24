package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
)

// verifyIDToken は RP の手順で ID Token を検証し、header・claims・各検査の結果を 1 段階にまとめる
// （OIDC Core §3.1.3.7）。エンジンの keys パッケージではなく、公開 JWKS と go-jose だけで検証する。
// 署名が検証できなくても、何が入っているかを見られるよう claims は表示する。
// refresh が true なら Refresh で得た ID Token として nonce を扱う（OIDC Core §12.2）。
func (a *App) verifyIDToken(ctx context.Context, md *oauthclient.Metadata, raw, clientID, nonce string, refresh bool) step {
	s := step{Title: "ID Token の検証", Ref: "OIDC Core §3.1.3.7"}
	if refresh {
		s.Title, s.Ref = "ID Token の検証（Refresh）", "OIDC Core §12.2 / §3.1.3.7"
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		s.Err = "JWS として解釈できない: " + err.Error()
		return s
	}
	h := parsed.Headers[0]
	s.Body = prettyJSON(map[string]any{"alg": h.Algorithm, "kid": h.KeyID, "typ": h.ExtraHeaders["typ"]})

	var claims map[string]any
	sigErr := a.verifySignature(ctx, md, parsed, &claims)
	if sigErr != nil {
		_ = parsed.UnsafeClaimsWithoutVerification(&claims)
	}
	s.Extra = prettyJSON(claims)

	now := time.Now()
	exp, _ := claims["exp"].(float64)
	s.Checks = []check{
		{"署名を jwks_uri の公開鍵で検証できる", sigErr == nil, errDetail(sigErr, "kid "+h.KeyID+" / "+h.Algorithm)},
		{"iss が Issuer と一致", claims["iss"] == md.Issuer, "期待値 " + md.Issuer},
		{"aud に client_id が含まれる", audienceContains(claims["aud"], clientID), "期待値 " + clientID},
		{"exp が現在より後", float64(now.Unix()) < exp, "exp " + unixTime(claims["exp"])},
		{"iat がある", claims["iat"] != nil, "iat " + unixTime(claims["iat"])},
	}
	got, _ := claims["nonce"].(string)
	switch {
	case refresh:
		s.Checks = append(s.Checks, check{"nonce がないか、最初の ID Token と同じ", got == "" || got == nonce, fmt.Sprintf("nonce %q", got)})
	case nonce != "":
		s.Checks = append(s.Checks, check{"nonce が認可要求と一致", got == nonce, "期待値 " + nonce})
	}
	if v, ok := claims["auth_time"]; ok {
		s.Checks = append(s.Checks, check{"auth_time（参考）", true, unixTime(v)})
	}
	return s
}

// verifySignature は jwks_uri から公開鍵を取り、kid の鍵で署名を検証して claims を取り出す。
func (a *App) verifySignature(ctx context.Context, md *oauthclient.Metadata, parsed *jwt.JSONWebToken, out *map[string]any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, md.JWKSURI, nil)
	if err != nil {
		return err
	}
	res, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks returned %d", res.StatusCode)
	}
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return err
	}
	keys := jwks.Key(parsed.Headers[0].KeyID)
	if len(keys) != 1 {
		return fmt.Errorf("kid %q not found in jwks", parsed.Headers[0].KeyID)
	}
	return parsed.Claims(keys[0].Key, out)
}

func audienceContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		return slices.Contains(v, any(clientID))
	}
	return false
}

func errDetail(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}
