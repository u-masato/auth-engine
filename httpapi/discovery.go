package httpapi

import (
	"encoding/json"
	"net/http"
)

// metadata は RFC 8414 §2 の Authorization Server Metadata。M1 では OAuth 2.0 の範囲のみ。
// OIDC Discovery（/.well-known/openid-configuration、jwks_uri、userinfo_endpoint）は M2。
type metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	// RFC 9207 §3
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	m := metadata{
		Issuer:                                     s.engine.Issuer,
		AuthorizationEndpoint:                      s.endpoint(PathAuthorize),
		TokenEndpoint:                              s.endpoint(PathToken),
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		AuthorizationResponseIssParameterSupported: true,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(m)
}
