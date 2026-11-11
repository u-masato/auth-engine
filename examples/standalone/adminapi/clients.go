package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

// clientsBody は GET /clients の応答。
type clientsBody struct {
	Clients []ClientSpec `json:"clients"`
	// NextAfter は次のページの after に渡す値。最後のページでは省略する。
	NextAfter string `json:"next_after,omitempty"`
}

// handleListClients は GET /clients?after=&limit=。Store.ListClients のキーセットページングを
// そのまま使う。CIMD で解決した Client は Store にないので含まれない。
func (a *API) handleListClients(w http.ResponseWriter, r *http.Request) {
	after, limit, err := pageParams(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// 次のページがあるかを知るために 1 件多く読む
	cs, err := a.cfg.Store.ListClients(r.Context(), after, limit+1)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	body := clientsBody{Clients: make([]ClientSpec, 0, len(cs))}
	if len(cs) > limit {
		cs = cs[:limit]
		body.NextAfter = cs[len(cs)-1].ID
	}
	for _, c := range cs {
		body.Clients = append(body.Clients, SpecOf(c))
	}
	writeJSON(w, http.StatusOK, body)
}

// handleCreateClient は POST /clients。成功は 201 で、Location に Client の URL、本文に登録内容を返す。
// confidential クライアントでは client_secret に平文が入る。平文が得られるのはこの応答だけである
// （Store はハッシュだけを保存する）。
func (a *API) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var sp ClientSpec
	if !decodeJSON(w, r, &sp) {
		return
	}
	c, secret, err := sp.NewClient(time.Now())
	if err != nil {
		a.clientError(w, r, err)
		return
	}
	if err := a.cfg.Store.CreateClient(r.Context(), c); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "conflict", "client_id "+c.ID+" is already registered")
			return
		}
		a.internalError(w, r, err)
		return
	}
	a.logger.InfoContext(r.Context(), "admin: client created", "event", "admin.client_created", "client_id", c.ID, "profile", c.Profile)
	out := SpecOf(c)
	out.ClientSecret = string(secret)
	w.Header().Set("Location", ClientPath(c.ID))
	writeJSON(w, http.StatusCreated, out)
}

// handleGetClient は GET /clients/{id}。
func (a *API) handleGetClient(w http.ResponseWriter, r *http.Request) {
	c, ok := a.findClient(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, SpecOf(c))
}

// handleUpdateClient は PUT /clients/{id}。開放項目（ADR-0004 §2）を本文の値で置き換える。
// 部分更新ではないので、GET で得た内容を書き換えて送る。Client.Update がコンストラクタと同じ検証を
// 通し、Store.UpdateClient が保存済みの Profile と照合してから書き込む（ADR-0004 §4）。
//
// 発行済みのトークンはそのまま有効で、次の要求から新しい設定が使われる。
func (a *API) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var sp ClientSpec
	if !decodeJSON(w, r, &sp) {
		return
	}
	cur, ok := a.findClient(w, r)
	if !ok {
		return
	}
	p, err := sp.UpdateParams(cur)
	if err != nil {
		a.clientError(w, r, err)
		return
	}
	next, err := cur.Update(p)
	if err != nil {
		a.clientError(w, r, err)
		return
	}
	if err := a.cfg.Store.UpdateClient(r.Context(), next); err != nil {
		a.storeError(w, r, err, cur.ID)
		return
	}
	a.logger.InfoContext(r.Context(), "admin: client updated", "event", "admin.client_updated", "client_id", next.ID)
	writeJSON(w, http.StatusOK, SpecOf(next))
}

// handleDeleteClient は DELETE /clients/{id}。Store.DeleteClient は同じ操作で、その Client の全 Grant と
// 配下の Token Family・トークンを失効させ、Authorization Code を削除する。成功は 204。
func (a *API) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.cfg.Store.DeleteClient(r.Context(), id, time.Now()); err != nil {
		a.storeError(w, r, err, id)
		return
	}
	a.logger.InfoContext(r.Context(), "admin: client deleted", "event", "admin.client_deleted", "client_id", id)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// findClient はパスの client_id で Client を引く。見つからなければ 404 を書いて false を返す。
func (a *API) findClient(w http.ResponseWriter, r *http.Request) (*client.Client, bool) {
	id := r.PathValue("id")
	c, err := a.cfg.Store.GetClient(r.Context(), id)
	if err != nil {
		a.storeError(w, r, err, id)
		return nil, false
	}
	return c, true
}

// clientError は Client の組み立て・検証の失敗を応答にする。client.ErrInvalid は呼び出し側の
// 入力の問題なので、理由をそのまま返す。
func (a *API) clientError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, client.ErrInvalid) {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	a.internalError(w, r, err)
}

// storeError は Store のセンチネルエラーをステータスに写す。
func (a *API) storeError(w http.ResponseWriter, r *http.Request, err error, id string) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "client_id "+id+" is not registered")
	case errors.Is(err, storage.ErrStateConflict):
		// 読んでから書くまでの間に、削除されて別の Profile で作り直された
		writeError(w, http.StatusConflict, "conflict", "client_id "+id+" was replaced during the operation")
	default:
		a.internalError(w, r, err)
	}
}
