package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
	"github.com/u-masato/auth-engine/storage"
)

// flow は 1 回分のフローの記録。Code フロー（Web / Native）か Client Credentials（Machine）。
// mu はトークン操作の直列化にも使う。Refresh Token は Rotation されるので、同じ値で 2 回
// 要求すると再利用検知で Token Family ごと失効する（RFC 9700 §4.14.2）。
type flow struct {
	mu sync.Mutex

	ID       string
	ClientID string
	Profile  client.Profile
	Public   bool // public クライアント（Client 認証をしない）か。client.Client.IsPublic の値
	Created  time.Time

	oc         *oauthclient.CodeFlow
	AuthURL    string
	AuthParams []kv
	Nonce      string
	Called     bool // コールバックを受けた

	AccessToken  string
	RefreshToken string
	Steps        []step
}

// Confidential は Client 認証を行う Client か（Introspection を呼べるか）。
func (f *flow) Confidential() bool { return !f.Public }

// CodeFlow は認可エンドポイントを経由するフローか。
func (f *flow) CodeFlow() bool { return f.Profile != client.ProfileMachine }

type kv struct{ K, V string }

type check struct {
	Name   string
	OK     bool
	Detail string
}

// step は画面に出す 1 段階。Ref は対応する仕様の節。
type step struct {
	Title  string
	Ref    string
	At     time.Time
	Params []kv
	Checks []check
	Body   string // 応答本文（整形した JSON）
	Extra  string // ID Token の claims など、本文とは別に見せたいもの
	Err    string
}

func (f *flow) add(s step) {
	s.At = time.Now()
	f.Steps = append(f.Steps, s)
}

// handleStart は開始フォームを受け、Code フローなら認可要求を組み立て、Machine ならその場で
// トークンを要求する。どちらもフロー画面へリダイレクトする。
func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	ctx := r.Context()
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	secret := strings.TrimSpace(r.PostForm.Get("secret"))
	scopes := strings.Fields(r.PostForm.Get("scope"))

	c, err := a.cfg.Store.GetClient(ctx, clientID)
	if errors.Is(err, storage.ErrNotFound) {
		a.renderError(w, http.StatusNotFound, "client_id "+clientID+" は Store に登録されていない")
		return
	} else if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	switch {
	case c.IsPublic() && secret != "":
		a.renderError(w, http.StatusBadRequest, string(c.Profile)+" Profile は public クライアントなので Client Secret を使わない（RFC 8252 §8.5）")
		return
	case !c.IsPublic() && secret == "":
		a.renderError(w, http.StatusBadRequest, string(c.Profile)+" Profile は confidential クライアントなので Client Secret が必要（RFC 6749 §2.3.1）")
		return
	}
	md, err := a.metadata(ctx)
	if err != nil {
		a.renderError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.remember(KnownClient{ID: c.ID, Secret: secret})

	oc, err := oauthclient.NewCodeFlow(md, c.ID, a.RedirectURI(), scopes)
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	oc.ClientSecret = secret
	oc.HTTPClient = a.hc
	id, err := randomID()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	f := &flow{ID: id, ClientID: c.ID, Profile: c.Profile, Public: c.IsPublic(), Created: time.Now(), oc: oc}

	if c.Profile == client.ProfileMachine {
		a.clientCredentials(ctx, f, strings.Join(scopes, " "))
	} else if err := a.prepareAuthorization(f, scopes, r.PostForm); err != nil {
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.mu.Lock()
	a.flows[f.ID] = f
	if f.CodeFlow() {
		a.byState[oc.State()] = f
	}
	a.flowList = append([]*flow{f}, a.flowList...)
	a.mu.Unlock()
	http.Redirect(w, r, "/flows/"+f.ID, http.StatusSeeOther)
}

// prepareAuthorization は認可要求 URL を組み立て、送るパラメータを記録する（RFC 6749 §4.1.1、
// RFC 7636 §4.3）。ブラウザを遷移させるのは利用者がリンクを押したときで、要求内容を先に見せる。
func (a *App) prepareAuthorization(f *flow, scopes []string, form url.Values) error {
	extra := url.Values{}
	if slices.Contains(scopes, "openid") {
		// OIDC Core §3.1.2.1: ID Token と要求を結びつける nonce。ID Token の検証で照合する
		n, err := randomID()
		if err != nil {
			return err
		}
		f.Nonce = n
		extra.Set("nonce", n)
	}
	for _, k := range []string{"prompt", "login_hint", "max_age"} {
		if v := strings.TrimSpace(form.Get(k)); v != "" {
			extra.Set(k, v)
		}
	}
	f.oc.Extra = extra
	f.AuthURL = f.oc.AuthorizationURL()
	u, err := url.Parse(f.AuthURL)
	if err != nil {
		return err
	}
	f.AuthParams = sortedParams(u.Query())
	return nil
}

func (a *App) clientCredentials(ctx context.Context, f *flow, scope string) {
	s := step{Title: "トークン要求（client_credentials）", Ref: "RFC 6749 §4.4.2 / §4.4.3",
		Params: []kv{{"grant_type", "client_credentials"}, {"scope", scope}, {"client authentication", "client_secret_basic（RFC 6749 §2.3.1）"}}}
	tok, err := f.oc.ClientCredentials(ctx, scope)
	if err != nil {
		s.Err = err.Error()
		f.add(s)
		return
	}
	f.AccessToken = tok.AccessToken
	s.Body = prettyJSON(tok)
	f.add(s)
}

// handleCallback は redirect URI に戻ってきた認可応答を受ける。state でフローを引き当て、
// state と iss を検証してから Code を交換し、ID Token があれば検証する。
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.mu.Lock()
	f := a.byState[q.Get("state")]
	a.mu.Unlock()
	if f == nil {
		a.renderError(w, http.StatusBadRequest, "state に対応するフローがない。コンソールを再起動したか、このコンソールが出した要求ではない（RFC 6749 §10.12）")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Called {
		// Code は 1 回しか使えない（RFC 6749 §4.1.2）。再読み込みでは交換し直さない
		http.Redirect(w, r, "/flows/"+f.ID, http.StatusSeeOther)
		return
	}
	f.Called = true
	ctx := r.Context()
	md := f.oc.Metadata

	cb := step{Title: "認可応答（コールバック）", Ref: "RFC 6749 §4.1.2 / §4.1.2.1、RFC 9207", Params: sortedParams(q)}
	cb.Checks = []check{
		{"state が要求時と一致", true, "RFC 6749 §10.12。一致したのでこのフローを引き当てた"},
		{"iss が Issuer と一致", q.Get("iss") == md.Issuer, "RFC 9207 §2.4。期待値 " + md.Issuer},
	}
	code, err := f.oc.HandleCallback(q)
	if err != nil {
		cb.Err = err.Error()
		f.add(cb)
		http.Redirect(w, r, "/flows/"+f.ID, http.StatusSeeOther)
		return
	}
	f.add(cb)

	ex := step{Title: "トークン要求（authorization_code）", Ref: "RFC 6749 §4.1.3 / §4.1.4、RFC 7636 §4.5",
		Params: []kv{{"grant_type", "authorization_code"}, {"code", code}, {"redirect_uri", f.oc.RedirectURI},
			{"code_verifier", "（認可要求の code_challenge に対応する値）"}, {"client authentication", authMethod(f)}}}
	tok, err := f.oc.Exchange(ctx, code)
	if err != nil {
		ex.Err = err.Error()
		f.add(ex)
		http.Redirect(w, r, "/flows/"+f.ID, http.StatusSeeOther)
		return
	}
	f.AccessToken, f.RefreshToken = tok.AccessToken, tok.RefreshToken
	ex.Body = prettyJSON(tok)
	f.add(ex)
	if tok.IDToken != "" {
		f.add(a.verifyIDToken(ctx, md, tok.IDToken, f.ClientID, f.Nonce, false))
	}
	http.Redirect(w, r, "/flows/"+f.ID, http.StatusSeeOther)
}

func authMethod(f *flow) string {
	if f.Confidential() {
		return "client_secret_basic（RFC 6749 §2.3.1）"
	}
	return "none（public。client_id をフォームに入れる）"
}

func (a *App) lookup(id string) *flow {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flows[id]
}

func (a *App) handleFlow(w http.ResponseWriter, r *http.Request) {
	f := a.lookup(r.PathValue("id"))
	if f == nil {
		a.renderError(w, http.StatusNotFound, "フローが見つからない（コンソールを再起動すると消える）")
		return
	}
	f.mu.Lock()
	var buf bytes.Buffer
	err := pages.ExecuteTemplate(&buf, "flow", struct {
		Issuer string
		Flow   *flow
	}{a.cfg.Issuer, f})
	f.mu.Unlock()
	if err != nil {
		a.logger.Error("console: render flow", "error", err)
		a.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// handleAction はトークン操作を 1 つ実行して記録し、フロー画面に戻す（POST-redirect-GET）。
func (a *App) handleAction(w http.ResponseWriter, r *http.Request) {
	f := a.lookup(r.PathValue("id"))
	if f == nil {
		a.renderError(w, http.StatusNotFound, "フローが見つからない（コンソールを再起動すると消える）")
		return
	}
	ctx := r.Context()
	f.mu.Lock()
	switch r.PathValue("action") {
	case "userinfo":
		a.userInfo(ctx, f)
	case "refresh":
		a.refresh(ctx, f)
	case "revoke-access":
		a.revoke(ctx, f, f.AccessToken, "access_token")
	case "revoke-refresh":
		a.revoke(ctx, f, f.RefreshToken, "refresh_token")
	case "introspect-access":
		a.introspect(ctx, f, f.AccessToken, "access_token")
	case "introspect-refresh":
		a.introspect(ctx, f, f.RefreshToken, "refresh_token")
	default:
		f.mu.Unlock()
		a.renderError(w, http.StatusNotFound, "unknown action")
		return
	}
	n := len(f.Steps)
	f.mu.Unlock()
	http.Redirect(w, r, fmt.Sprintf("/flows/%s#step-%d", f.ID, n), http.StatusSeeOther)
}

func (a *App) userInfo(ctx context.Context, f *flow) {
	s := step{Title: "UserInfo", Ref: "OIDC Core §5.3", Params: []kv{{"Authorization", "Bearer <access_token>"}}}
	claims, err := f.oc.UserInfo(ctx, f.AccessToken)
	if err != nil {
		s.Err = err.Error()
	} else {
		s.Body = prettyJSON(claims)
	}
	f.add(s)
}

func (a *App) refresh(ctx context.Context, f *flow) {
	s := step{Title: "トークン要求（refresh_token）", Ref: "RFC 6749 §6、RFC 9700 §4.14.2（Rotation）",
		Params: []kv{{"grant_type", "refresh_token"}, {"refresh_token", f.RefreshToken}, {"client authentication", authMethod(f)}}}
	if f.RefreshToken == "" {
		s.Err = "Refresh Token がない"
		f.add(s)
		return
	}
	tok, err := f.oc.Refresh(ctx, f.RefreshToken, "")
	if err != nil {
		s.Err = err.Error()
		f.add(s)
		return
	}
	// Rotation された後継に差し替える。古い Refresh Token をもう一度使うと再利用として検知される
	s.Checks = []check{{"Refresh Token が Rotation された", tok.RefreshToken != "" && tok.RefreshToken != f.RefreshToken, "以降の操作は新しい値を使う"}}
	f.AccessToken, f.RefreshToken = tok.AccessToken, tok.RefreshToken
	s.Body = prettyJSON(tok)
	f.add(s)
	if tok.IDToken != "" {
		f.add(a.verifyIDToken(ctx, f.oc.Metadata, tok.IDToken, f.ClientID, f.Nonce, true))
	}
}

func (a *App) revoke(ctx context.Context, f *flow, token, hint string) {
	s := step{Title: "失効（" + hint + "）", Ref: "RFC 7009 §2.1 / §2.2",
		Params: []kv{{"token", token}, {"token_type_hint", hint}, {"client authentication", authMethod(f)}}}
	if token == "" {
		s.Err = hint + " がない"
	} else if err := f.oc.Revoke(ctx, token, hint); err != nil {
		s.Err = err.Error()
	} else {
		s.Body = "200 OK（本文なし）。Introspection で active=false になったことを確かめられる"
	}
	f.add(s)
}

func (a *App) introspect(ctx context.Context, f *flow, token, hint string) {
	s := step{Title: "Introspection（" + hint + "）", Ref: "RFC 7662 §2.1 / §2.2",
		Params: []kv{{"token", token}, {"token_type_hint", hint}, {"client authentication", authMethod(f)}}}
	switch {
	case !f.Confidential():
		s.Err = "Introspection は confidential クライアントだけが呼べる（httpapi/discovery.go の introspection_endpoint_auth_methods_supported）"
	case token == "":
		s.Err = hint + " がない"
	default:
		out, err := f.oc.Introspect(ctx, token, hint)
		if err != nil {
			s.Err = err.Error()
		} else {
			s.Body = prettyJSON(out)
		}
	}
	f.add(s)
}

func sortedParams(q url.Values) []kv {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]kv, 0, len(keys))
	for _, k := range keys {
		out = append(out, kv{k, strings.Join(q[k], " ")})
	}
	return out
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// unixTime は JWT の数値日付（RFC 7519 §2 NumericDate）を表示用に整える。
func unixTime(v any) string {
	f, ok := v.(float64)
	if !ok {
		return fmt.Sprint(v)
	}
	return strconv.FormatInt(int64(f), 10) + "（" + time.Unix(int64(f), 0).Format(time.DateTime) + "）"
}
