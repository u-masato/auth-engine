package console

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/u-masato/auth-engine/grant"
)

// handleRevokeGrant は 1 人のユーザーとの連携を解除する。grant.Service.Revoke が Grant と配下の
// 全 Token Family・全トークンを失効させる（Interaction API の DELETE /grants と同じ操作）。
// 一覧は詳細画面（handleClient）が grant.Service.ListByClient で描く。
//
// Client が Store にあるかは見ない。Grant は client_id × subject で引くので、Client が先に
// 削除されていれば Grant も失効済みで、ここは何もせず成功する（冪等）。
func (a *App) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	id, subject := r.PathValue("id"), r.PostForm.Get("subject")
	if subject == "" {
		a.renderError(w, http.StatusBadRequest, "subject が指定されていない")
		return
	}
	if err := a.cfg.Grants.Revoke(r.Context(), id, subject); err != nil {
		if errors.Is(err, grant.ErrNotFound) {
			a.renderError(w, http.StatusNotFound, "client_id "+id+" に対する subject "+subject+" の Grant はない")
			return
		}
		a.logger.Error("console: revoke grant", "client_id", id, "subject", subject, "error", err)
		a.renderError(w, http.StatusInternalServerError, "連携の解除に失敗した: "+err.Error())
		return
	}
	a.logger.Info("console: revoked grant", "client_id", id, "subject", subject)
	q := url.Values{"notice": {"grant-revoked"}, "subject": {subject}}
	// 解除前に見ていたページに戻る
	if after := r.PostForm.Get("grants_after"); after != "" {
		q.Set("grants_after", after)
	}
	http.Redirect(w, r, clientPath(id)+"?"+q.Encode()+"#grants", http.StatusSeeOther)
}
