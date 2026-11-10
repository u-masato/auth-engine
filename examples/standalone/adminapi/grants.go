package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/u-masato/auth-engine/grant"
)

// grantView は GET /clients/{id}/grants の 1 要素。Claims は含めない（Interaction App が渡した
// 利用者の属性であり、運用者の一覧には subject と scope で足りる）。
type grantView struct {
	ClientID string   `json:"client_id"`
	Subject  string   `json:"subject"`
	Scopes   []string `json:"scopes"`
	// Status は active か revoked。
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type grantsBody struct {
	Grants []grantView `json:"grants"`
	// NextAfter は次のページの after に渡す値（最後の要素の subject）。最後のページでは省略する。
	NextAfter string `json:"next_after,omitempty"`
}

// handleListGrants は GET /clients/{id}/grants?after=&limit=。この Client に対する Grant を subject の
// 昇順で返す（「この Client を利用しているユーザー」の一覧）。失効済みも含むので、status で見分ける。
//
// Client が Store にあるかは見ない。CIMD で解決した Client（Store にない）や、削除済みの Client の
// Grant も client_id で引ける。該当がなければ空の一覧を返す。
func (a *API) handleListGrants(w http.ResponseWriter, r *http.Request) {
	after, limit, err := pageParams(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	gs, err := a.cfg.Grants.ListByClient(r.Context(), r.PathValue("id"), after, limit+1)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	body := grantsBody{Grants: make([]grantView, 0, len(gs))}
	if len(gs) > limit {
		gs = gs[:limit]
		body.NextAfter = gs[len(gs)-1].Subject
	}
	for _, g := range gs {
		v := grantView{ClientID: g.ClientID, Subject: g.Subject, Scopes: nonNil(g.Scopes), Status: string(g.Status),
			CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
		if !g.RevokedAt.IsZero() {
			revoked := g.RevokedAt
			v.RevokedAt = &revoked
		}
		body.Grants = append(body.Grants, v)
	}
	writeJSON(w, http.StatusOK, body)
}

// handleRevokeGrant は DELETE /clients/{id}/grants?subject=...。1 人のユーザーとの連携を解除する。
// Grant と配下の全 Token Family・全トークンが失効する（Interaction API の DELETE /grants と同じ操作）。
// subject は必須（取り違えて Client の全 Grant を消さないよう、一括の解除は置かない。全員を
// 解除するのは Client の削除である）。成功は 204。既に失効済みでも 204（冪等）。Grant がなければ 404。
func (a *API) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	id, subject := r.PathValue("id"), r.URL.Query().Get("subject")
	if subject == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "subject is required")
		return
	}
	err := a.cfg.Grants.Revoke(r.Context(), id, subject)
	switch {
	case err == nil:
		a.logger.InfoContext(r.Context(), "admin: grant revoked", "event", "admin.grant_revoked", "client_id", id, "subject", subject)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, grant.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "grant not found")
	default:
		a.internalError(w, r, err)
	}
}
