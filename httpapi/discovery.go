package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/u-masato/auth-engine/oidc"
)

// metadata は RFC 8414 §2 の Authorization Server Metadata と OIDC Discovery 1.0 §3 の
// OpenID Provider Metadata を兼ねる。両者はほぼ同じ語彙で、OIDC 側が項目を追加する。
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`

	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// RFC 8414 §2: revocation は public クライアントも呼べる（none）。introspection は confidential のみ
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	// RFC 9207 §3
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	// CIMD §6。Config.CIMD を与えたときだけ true を載せる（無効な構成では省略。ADR-0008 §5）。
	ClientIDMetadataDocumentSupported *bool `json:"client_id_metadata_document_supported,omitempty"`

	// OIDC Discovery 1.0 §3 の追加項目。openid-configuration でのみ返す。
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	ClaimsParameterSupported         *bool    `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported        *bool    `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported     *bool    `json:"request_uri_parameter_supported,omitempty"`
}

func (s *Server) baseMetadata() metadata {
	var cimdSupported *bool
	if s.engine.CIMD != nil {
		t := true
		cimdSupported = &t
	}
	return metadata{
		Issuer:                                     s.engine.Issuer,
		AuthorizationEndpoint:                      s.endpoint(PathAuthorize),
		TokenEndpoint:                              s.endpoint(PathToken),
		JWKSURI:                                    s.endpoint(PathJWKS),
		UserInfoEndpoint:                           s.endpoint(PathUserInfo),
		RevocationEndpoint:                         s.endpoint(PathRevoke),
		IntrospectionEndpoint:                      s.endpoint(PathIntrospect),
		ScopesSupported:                            oidc.StandardScopes,
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token", "client_credentials"},
		TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post", "none"},
		RevocationEndpointAuthMethodsSupported:     []string{"client_secret_basic", "client_secret_post", "none"},
		IntrospectionEndpointAuthMethodsSupported:  []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		AuthorizationResponseIssParameterSupported: true,
		ClientIDMetadataDocumentSupported:          cimdSupported,
	}
}

// handleMetadata は RFC 8414 の /.well-known/oauth-authorization-server。
func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	writeMetadata(w, s.baseMetadata())
}

// handleOpenIDConfiguration は OIDC Discovery 1.0 の /.well-known/openid-configuration。
func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	m := s.baseMetadata()
	f := false
	m.SubjectTypesSupported = []string{"public"}
	m.IDTokenSigningAlgValuesSupported = s.engine.Keys.SigningAlgorithms()
	m.ClaimsSupported = oidc.ClaimsSupported()
	m.ClaimsParameterSupported = &f
	m.RequestParameterSupported = &f
	m.RequestURIParameterSupported = &f
	writeMetadata(w, m)
}

func writeMetadata(w http.ResponseWriter, m metadata) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(m)
}

// handleJWKS は公開鍵の JWK Set（RFC 7517 §5）。鍵ローテーションは新旧の鍵を重複期間
// 両方公開することで吸収するので、1 時間のキャッシュを許す。
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	body, err := s.engine.Keys.JWKS()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(body)
}
