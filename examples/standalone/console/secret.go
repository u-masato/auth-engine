package console

import (
	"errors"
	"net/http"
	"strings"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

// handleRotateSecret は Client Secret を再発行する。Client.RotateSecret が新しいシークレットを生成し、
// Store.RotateClientSecret がハッシュだけを書き換える。保存した時点で旧シークレットは使えなくなる
// （新旧を併用する期間はない）。発行済みのトークンと Grant には触れない。
//
// 動いている Client を止めうる操作なので、削除と同じく確認欄に client_id を入力させる。
func (a *App) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.renderError(w, http.StatusBadRequest, "bad form")
		return
	}
	c, ok := a.findClient(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(r.PostForm.Get("confirm")) != c.ID {
		a.renderError(w, http.StatusBadRequest, "確認欄の client_id が一致しない。再発行していない")
		return
	}
	next, secret, err := c.RotateSecret()
	if err != nil {
		if errors.Is(err, client.ErrInvalid) {
			a.renderError(w, http.StatusBadRequest, "public クライアントはシークレットを持たない")
			return
		}
		a.logger.Error("console: rotate secret", "client_id", c.ID, "error", err)
		a.renderError(w, http.StatusInternalServerError, "再発行に失敗した: "+err.Error())
		return
	}
	if err := a.cfg.Store.RotateClientSecret(r.Context(), next.ID, next.SecretHash); err != nil {
		// ErrNotFound / ErrStateConflict は、画面を開いた後に削除・作り直しされた場合
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrStateConflict) {
			a.renderError(w, http.StatusConflict, "client_id "+c.ID+" は操作中に削除されたか、シークレットを持たない Profile で作り直された")
			return
		}
		a.logger.Error("console: rotate secret", "client_id", c.ID, "error", err)
		a.renderError(w, http.StatusInternalServerError, "再発行に失敗した: "+err.Error())
		return
	}
	// 平文は Store に残らない。詳細画面に 1 度表示するため、メモリの値を新しいものに置き換える
	a.rememberSecret(next.ID, string(secret))
	a.logger.Info("console: rotated client secret", "client_id", next.ID)
	http.Redirect(w, r, clientPath(next.ID)+"?notice=rotated", http.StatusSeeOther)
}
