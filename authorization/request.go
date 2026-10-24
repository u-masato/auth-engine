package authorization

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/storage"
)

// promptValues は OIDC Core §3.1.2.1 の prompt パラメータの許容値。
var promptValues = map[string]bool{"none": true, "login": true, "consent": true, "select_account": true}

// multiValuedParams は複数回出現してよいパラメータ。それ以外の重複は invalid_request
// （RFC 6749 §3.1: Parameters sent without a value MUST be treated as if they were omitted ...
// Request and response parameters MUST NOT be included more than once）。
var multiValuedParams = map[string]bool{"resource": true}

// parseRequest は /authorize のクエリを検証し、Request を組み立てる。
//
// 検証順序は RFC 6749 §4.1.2.1 の規則に従う。client_id と redirect_uri が確定するまでは
// Client へリダイレクトできないので、その段階のエラーは RedirectURI を空にして返す。
// それ以降のエラーは RedirectURI と state を持ち、Client へリダイレクトして返す。
func parseRequest(ctx context.Context, clients client.Resolver, values url.Values) (*Request, *client.Client, *Error) {
	// --- 1. client_id（リダイレクト不可の段階） ---
	if len(values["client_id"]) != 1 || values.Get("client_id") == "" {
		return nil, nil, &Error{Code: CodeInvalidRequest, Description: "client_id is required exactly once"}
	}
	c, err := clients.GetClient(ctx, values.Get("client_id"))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, &Error{Code: CodeInvalidRequest, Description: "unknown client_id"}
		}
		return nil, nil, &Error{Code: CodeServerError, Description: "client lookup failed", Cause: err}
	}

	// --- 2. redirect_uri（リダイレクト不可の段階） ---
	if len(values["redirect_uri"]) > 1 {
		return nil, nil, &Error{Code: CodeInvalidRequest, Description: "redirect_uri must not be repeated"}
	}
	redirectURI, err := c.ResolveRedirectURI(values.Get("redirect_uri"))
	if err != nil {
		return nil, nil, &Error{Code: CodeInvalidRequest, Description: err.Error()}
	}
	// OIDC Core §3.1.2.1: OpenID Connect の認可要求では redirect_uri は必須。RFC 6749 だけの要求
	// （openid なし）では登録 URI が 1 つなら省略できる（§3.1.2.3）。要求元が確定できないので
	// リダイレクトせずエラーページにする。
	if values.Get("redirect_uri") == "" && slices.Contains(strings.Fields(values.Get("scope")), "openid") {
		return nil, nil, &Error{Code: CodeInvalidRequest, Description: "redirect_uri is required for OpenID Connect requests"}
	}

	// --- 3. ここからは Client へリダイレクトして返せる ---
	state := values.Get("state")
	fail := func(code, desc string) (*Request, *client.Client, *Error) {
		return nil, nil, &Error{Code: code, Description: desc, RedirectURI: redirectURI, State: state}
	}

	for k, vs := range values {
		if len(vs) > 1 && !multiValuedParams[k] {
			return fail(CodeInvalidRequest, "parameter "+k+" must not be repeated")
		}
	}
	if values.Has("request") {
		return fail(CodeRequestNotSupported, "request parameter is not supported")
	}
	if values.Has("request_uri") {
		return fail(CodeRequestURINotSupported, "request_uri parameter is not supported")
	}

	switch values.Get("response_type") {
	case "":
		return fail(CodeInvalidRequest, "response_type is required")
	case "code":
	default:
		return fail(CodeUnsupportedResponseType, "only response_type=code is supported")
	}
	if !c.Allows(client.GrantAuthorizationCode) {
		return fail(CodeUnauthorizedClient, "client is not allowed to use the authorization code grant")
	}
	if m := values.Get("response_mode"); m != "" && m != "query" {
		return fail(CodeInvalidRequest, "only response_mode=query is supported")
	}

	// scope（RFC 6749 §3.3）。必須とし、Client の許可範囲内に限る。
	scopes, bad := parseScopes(values.Get("scope"))
	if bad != "" {
		return fail(CodeInvalidScope, "malformed scope token")
	}
	if len(scopes) == 0 {
		return fail(CodeInvalidScope, "scope is required")
	}
	if dis := c.DisallowedScopes(scopes); len(dis) > 0 {
		return fail(CodeInvalidScope, "scope not allowed for this client: "+strings.Join(dis, " "))
	}
	if slices.Contains(scopes, "openid") && !c.IssuesIDToken() {
		return fail(CodeInvalidScope, "client cannot request openid")
	}

	// PKCE（RFC 7636、RFC 9700 §2.1.1）。全 Profile で S256 必須。
	challenge := values.Get("code_challenge")
	if challenge == "" {
		return fail(CodeInvalidRequest, "code_challenge is required")
	}
	if values.Get("code_challenge_method") != CodeChallengeMethodS256 {
		return fail(CodeInvalidRequest, "code_challenge_method must be S256")
	}
	if !ValidCodeChallenge(challenge) {
		return fail(CodeInvalidRequest, "malformed code_challenge")
	}

	// OIDC のヒント群。エンジンは構文だけ確認し、意味は Interaction App に委ねる。
	req := &Request{
		ClientID:            c.ID,
		RedirectURI:         redirectURI,
		RedirectURIExplicit: values.Get("redirect_uri") != "",
		Scopes:              scopes,
		State:               state,
		CodeChallenge:       challenge,
		CodeChallengeMethod: CodeChallengeMethodS256,
		Nonce:               values.Get("nonce"),
		LoginHint:           values.Get("login_hint"),
		UILocales:           values.Get("ui_locales"),
		ACRValues:           values.Get("acr_values"),
		Resource:            slices.Clone(values["resource"]),
	}
	if p := values.Get("prompt"); p != "" {
		prompts := strings.Fields(p)
		for _, v := range prompts {
			if !promptValues[v] {
				return fail(CodeInvalidRequest, "unknown prompt value")
			}
		}
		if slices.Contains(prompts, "none") && len(prompts) > 1 {
			return fail(CodeInvalidRequest, "prompt=none cannot be combined with other values")
		}
		req.Prompt = prompts
	}
	if m := values.Get("max_age"); m != "" {
		sec, err := strconv.ParseInt(m, 10, 64)
		if err != nil || sec < 0 {
			return fail(CodeInvalidRequest, "max_age must be a non-negative integer")
		}
		req.MaxAge = time.Duration(sec) * time.Second
		req.HasMaxAge = true
	}
	return req, c, nil
}

// parseScopes は空白区切りの scope を分解し、重複を除いて返す。
// 構文違反のトークンがあればそれを bad として返す。
func parseScopes(raw string) (scopes []string, bad string) {
	for _, s := range strings.Split(raw, " ") {
		if s == "" {
			continue
		}
		if !client.ValidScopeToken(s) {
			return nil, s
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return scopes, ""
}
