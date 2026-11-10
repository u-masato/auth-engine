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

type editPage struct {
	Layout layout
	Client *client.Client
	Form   clientForm
	Error  string
}

// formFromClient は現在の登録内容を編集フォームの初期値にする。
func formFromClient(c *client.Client) clientForm {
	f := clientForm{
		Profile:                string(c.Profile),
		ClientID:               c.ID,
		Name:                   c.Name,
		RedirectURIs:           strings.Join(c.RedirectURIs, "\n"),
		Scopes:                 strings.Join(c.Scopes, " "),
		Resources:              strings.Join(c.Resources, "\n"),
		IDTokenAlg:             c.IDTokenAlg,
		LogoURI:                c.LogoURI,
		PolicyURI:              c.PolicyURI,
		AllowInsecureLocalhost: c.AllowInsecureLocalhost,
	}
	if c.AccessTokenTTL != 0 {
		f.AccessTokenTTL = shortDuration(c.AccessTokenTTL)
	}
	return f
}

// handleEditClient は編集フォーム。変えられるのは Profile が開放する項目だけ（ADR-0004 §2）。
func (a *App) handleEditClient(w http.ResponseWriter, r *http.Request) {
	c, ok := a.findClient(w, r)
	if !ok {
		return
	}
	a.renderEdit(w, c, formFromClient(c), "", http.StatusOK)
}

func (a *App) renderEdit(w http.ResponseWriter, c *client.Client, f clientForm, errMsg string, status int) {
	a.render(w, "client-edit", editPage{Layout: a.layout(c.Name+" を編集", "clients"), Client: c, Form: f, Error: errMsg}, status)
}

// handleUpdateClient は開放項目を置き換える。Client.Update がコンストラクタと同じ検証を通し、
// Store.UpdateClient が保存済みの Profile と照合してから書き込む（ADR-0004 §4）。
//
// 読んでから書くまでの間に他の運用者が変更していれば、後から保存した方が勝つ。
// 本番の管理画面で同時編集を防ぐなら、利用者側で版番号などを持つ。
func (a *App) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	c, ok := a.findClient(w, r)
	if !ok {
		return
	}
	f := parseClientForm(r)
	f.Profile, f.ClientID = string(c.Profile), c.ID // 変更できない項目は現在値のまま表示する

	ttl, err := f.ttl()
	if err != nil {
		a.renderEdit(w, c, f, "保存できない: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 現在値から始め、フォームに出している項目だけを置き換える。Profile が持たない項目
	// （Machine の redirect URI など）はフォームに出していないので触らない。
	p := c.UpdateParams()
	p.Name, p.Scopes, p.Resources, p.AccessTokenTTL = f.Name, strings.Fields(f.Scopes), strings.Fields(f.Resources), ttl
	if c.Profile != client.ProfileMachine {
		p.RedirectURIs, p.LogoURI, p.PolicyURI = strings.Fields(f.RedirectURIs), f.LogoURI, f.PolicyURI
		p.AllowInsecureLocalhost = f.AllowInsecureLocalhost
	}
	if c.IssuesIDToken() {
		p.IDTokenAlg = f.IDTokenAlg
	}
	next, err := c.Update(p)
	if err != nil {
		a.renderEdit(w, c, f, "保存できない: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.cfg.Store.UpdateClient(r.Context(), next); err != nil {
		// ErrNotFound / ErrStateConflict は、フォームを開いた後に削除・作り直しされた場合
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrStateConflict) {
			a.renderError(w, http.StatusConflict, "client_id "+c.ID+" は編集中に削除されたか、別の Profile で作り直された")
			return
		}
		a.logger.Error("console: update client", "client_id", c.ID, "error", err)
		a.renderEdit(w, c, f, "保存に失敗した: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.logger.Info("console: updated client", "client_id", c.ID)
	http.Redirect(w, r, clientPath(c.ID)+"?notice=updated", http.StatusSeeOther)
}

// handleDeleteClient は Client を削除する。Store.DeleteClient は同じ操作で、その Client の全 Grant と
// 配下の Token Family・トークンを失効させ、Authorization Code を削除する。
// 取り違えを防ぐため、確認欄に client_id を入力させる。
func (a *App) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	id := r.PathValue("id")
	if strings.TrimSpace(r.PostForm.Get("confirm")) != id {
		a.renderError(w, http.StatusBadRequest, "確認欄の client_id が一致しない。削除していない")
		return
	}
	if err := a.cfg.Store.DeleteClient(r.Context(), id, time.Now()); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "client_id "+id+" は Store に登録されていない")
			return
		}
		a.logger.Error("console: delete client", "client_id", id, "error", err)
		a.renderError(w, http.StatusInternalServerError, "削除に失敗した: "+err.Error())
		return
	}
	a.forgetSecret(id)
	a.logger.Info("console: deleted client", "client_id", id)
	http.Redirect(w, r, "/?deleted="+url.QueryEscape(id), http.StatusSeeOther)
}
