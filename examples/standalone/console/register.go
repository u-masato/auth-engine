package console

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

// clientForm は登録・編集フォームの入力値。エラー時に入力を残して再表示するために持つ。
type clientForm struct {
	Profile                string
	ClientID               string
	Name                   string
	RedirectURIs           string // 改行区切り
	Scopes                 string // 空白区切り
	Resources              string // 改行区切り。空なら制限なし
	AccessTokenTTL         string // time.ParseDuration の表記（15m、1h）。空なら既定
	IDTokenAlg             string
	LogoURI                string
	PolicyURI              string
	AllowInsecureLocalhost bool
}

func parseClientForm(r *http.Request) clientForm {
	get := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	return clientForm{
		Profile:                get("profile"),
		ClientID:               get("client_id"),
		Name:                   get("name"),
		RedirectURIs:           r.PostForm.Get("redirect_uris"),
		Scopes:                 r.PostForm.Get("scopes"),
		Resources:              r.PostForm.Get("resources"),
		AccessTokenTTL:         get("access_token_ttl"),
		IDTokenAlg:             get("id_token_alg"),
		LogoURI:                get("logo_uri"),
		PolicyURI:              get("policy_uri"),
		AllowInsecureLocalhost: r.PostForm.Get("allow_insecure_localhost") == "on",
	}
}

// ttl は Access Token の有効期間を返す。空なら 0（既定値）。範囲の検査は client.Client.Validate が行う。
func (f clientForm) ttl() (time.Duration, error) {
	if f.AccessTokenTTL == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(f.AccessTokenTTL)
	if err != nil {
		return 0, fmt.Errorf("有効期間 %q を解釈できない（例: 15m、1h）", f.AccessTokenTTL)
	}
	return d, nil
}

type registerPage struct {
	Layout layout
	Form   clientForm
	Error  string
}

// handleNewClient は登録フォーム。既定値はコンソール自身でフローを試せる Web Client にしてある。
func (a *App) handleNewClient(w http.ResponseWriter, _ *http.Request) {
	a.renderRegister(w, clientForm{Profile: string(client.ProfileWeb), Name: "Console Client", RedirectURIs: a.RedirectURI(),
		Scopes: "openid profile email", IDTokenAlg: client.AlgRS256, AllowInsecureLocalhost: true}, "", http.StatusOK)
}

func (a *App) renderRegister(w http.ResponseWriter, f clientForm, errMsg string, status int) {
	a.render(w, "client-new", registerPage{Layout: a.layout("クライアントを登録", "clients"), Form: f, Error: errMsg}, status)
}

// handleRegister は運用者として Client を Store に登録する。Profile ごとのコンストラクタが
// grant_type・認証方式・redirect URI の規則を検証する（docs/adr/0004-client-profiles.md）。
func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	f := parseClientForm(r)
	c, secret, err := newClient(f, time.Now())
	if err != nil {
		a.renderRegister(w, f, "登録できない: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.cfg.Store.CreateClient(r.Context(), c); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			a.renderRegister(w, f, "client_id "+c.ID+" は登録済み。内容を変えるなら詳細画面の「編集」を使う", http.StatusConflict)
			return
		}
		a.logger.Error("console: create client", "error", err)
		a.renderRegister(w, f, "登録に失敗した: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.rememberSecret(c.ID, string(secret))
	a.logger.Info("console: registered client", "client_id", c.ID, "profile", c.Profile)
	// POST の再送で二重登録しないよう、詳細画面へリダイレクトする（シークレットはメモリから表示）
	http.Redirect(w, r, clientPath(c.ID)+"?notice=registered", http.StatusSeeOther)
}

// newClient はフォームの内容から Profile ごとのコンストラクタで Client を作る。
// MCP Profile は CIMD 文書から組み立てるもので（client.NewMCP）、画面からは登録しない。
func newClient(f clientForm, now time.Time) (*client.Client, client.Secret, error) {
	ttl, err := f.ttl()
	if err != nil {
		return nil, "", err
	}
	redirects, scopes, resources := strings.Fields(f.RedirectURIs), strings.Fields(f.Scopes), strings.Fields(f.Resources)
	switch client.Profile(f.Profile) {
	case client.ProfileWeb:
		return client.NewWeb(client.WebParams{ID: f.ClientID, Name: f.Name, RedirectURIs: redirects, Scopes: scopes, Resources: resources,
			LogoURI: f.LogoURI, PolicyURI: f.PolicyURI, AccessTokenTTL: ttl, IDTokenAlg: f.IDTokenAlg, AllowInsecureLocalhost: f.AllowInsecureLocalhost}, now)
	case client.ProfileNative:
		c, err := client.NewNative(client.NativeParams{ID: f.ClientID, Name: f.Name, RedirectURIs: redirects, Scopes: scopes, Resources: resources,
			LogoURI: f.LogoURI, PolicyURI: f.PolicyURI, AccessTokenTTL: ttl, IDTokenAlg: f.IDTokenAlg, AllowInsecureLocalhost: f.AllowInsecureLocalhost}, now)
		return c, "", err
	case client.ProfileMachine:
		// Machine は redirect URI・ID Token・表示用 URL を持たない。フォームの値は使わない
		return client.NewMachine(client.MachineParams{ID: f.ClientID, Name: f.Name, Scopes: scopes, Resources: resources, AccessTokenTTL: ttl}, now)
	}
	return nil, "", fmt.Errorf("unknown profile: %q", f.Profile)
}
