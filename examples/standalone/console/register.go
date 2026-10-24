package console

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

// registerForm は登録フォームの入力値。エラー時に入力を残して再表示するために持つ。
type registerForm struct {
	Profile                string
	ClientID               string
	Name                   string
	RedirectURIs           string // 改行区切り
	Scopes                 string // 空白区切り
	IDTokenAlg             string
	AllowInsecureLocalhost bool
}

func newRegisterForm(redirectURI string) registerForm {
	return registerForm{Profile: string(client.ProfileWeb), Name: "Console Client", RedirectURIs: redirectURI,
		Scopes: "openid profile email", IDTokenAlg: client.AlgRS256, AllowInsecureLocalhost: true}
}

// handleRegister は運用者として Client を Store に登録する。Profile ごとのコンストラクタが
// grant_type・認証方式・redirect URI の規則を検証する（docs/adr/0004-client-profiles.md）。
func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	f := registerForm{
		Profile:                r.PostForm.Get("profile"),
		ClientID:               strings.TrimSpace(r.PostForm.Get("client_id")),
		Name:                   strings.TrimSpace(r.PostForm.Get("name")),
		RedirectURIs:           r.PostForm.Get("redirect_uris"),
		Scopes:                 r.PostForm.Get("scopes"),
		IDTokenAlg:             r.PostForm.Get("id_token_alg"),
		AllowInsecureLocalhost: r.PostForm.Get("allow_insecure_localhost") == "on",
	}
	redirects := strings.Fields(f.RedirectURIs)
	scopes := strings.Fields(f.Scopes)
	now := time.Now()

	var (
		c      *client.Client
		secret client.Secret
		err    error
	)
	switch client.Profile(f.Profile) {
	case client.ProfileWeb:
		c, secret, err = client.NewWeb(client.WebParams{ID: f.ClientID, Name: f.Name, RedirectURIs: redirects, Scopes: scopes,
			IDTokenAlg: f.IDTokenAlg, AllowInsecureLocalhost: f.AllowInsecureLocalhost}, now)
	case client.ProfileNative:
		c, err = client.NewNative(client.NativeParams{ID: f.ClientID, Name: f.Name, RedirectURIs: redirects, Scopes: scopes,
			IDTokenAlg: f.IDTokenAlg, AllowInsecureLocalhost: f.AllowInsecureLocalhost}, now)
	case client.ProfileMachine:
		// Machine は redirect URI と ID Token を持たない。フォームの値は使わない
		c, secret, err = client.NewMachine(client.MachineParams{ID: f.ClientID, Name: f.Name, Scopes: scopes}, now)
	default:
		a.renderIndex(w, r, f, "unknown profile: "+f.Profile, http.StatusBadRequest)
		return
	}
	if err != nil {
		a.renderIndex(w, r, f, "登録できない: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.cfg.Store.CreateClient(r.Context(), c); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			a.renderIndex(w, r, f, "client_id "+c.ID+" は登録済み。Store に更新操作はないので、変えるときは別の client_id にするか demo.sh reset で DB を作り直す", http.StatusConflict)
			return
		}
		a.logger.Error("console: create client", "error", err)
		a.renderIndex(w, r, f, "登録に失敗した: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.remember(KnownClient{ID: c.ID, Secret: string(secret)})
	a.logger.Info("console: registered client", "client_id", c.ID, "profile", c.Profile)
	// POST の再送で二重登録しないよう、詳細画面へリダイレクトする（シークレットはメモリから表示）
	http.Redirect(w, r, "/clients/"+url.PathEscape(c.ID)+"?registered=1", http.StatusSeeOther)
}
