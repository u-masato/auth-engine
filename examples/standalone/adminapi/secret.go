package adminapi

import (
	"errors"
	"net/http"

	"github.com/u-masato/auth-engine/client"
)

// handleRotateSecret は POST /clients/{id}/secret。新しいシークレットを生成して保存し、応答の
// client_secret で平文を 1 回だけ返す。本文は要らない（値は指定できず、常に生成する）。
//
// 保存した時点で旧シークレットは使えなくなる。新旧を併用する期間はないので、Client 側の設定を
// 差し替えるまでの間、トークンエンドポイントへの要求は invalid_client になる。発行済みの
// Access Token はそのまま使える。
//
// 発行済みのトークンと Grant には触れない。漏えいへの対応で、攻撃者が Refresh Token も得ている
// おそれがあるなら、DELETE /clients/{id}/grants で Grant も失効させる。
func (a *API) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	cur, ok := a.findClient(w, r)
	if !ok {
		return
	}
	next, secret, err := cur.RotateSecret()
	if err != nil {
		if errors.Is(err, client.ErrInvalid) { // public クライアント
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		a.internalError(w, r, err)
		return
	}
	// シークレットだけを書き換える専用の操作。読んでから書くまでの間の他の変更（名前の変更など）を
	// 巻き戻さない。その間に削除されて public クライアントとして作り直されていれば ErrStateConflict。
	if err := a.cfg.Store.RotateClientSecret(r.Context(), next.ID, next.SecretHash); err != nil {
		a.storeError(w, r, err, cur.ID)
		return
	}
	a.logger.InfoContext(r.Context(), "admin: client secret rotated", "event", "admin.secret_rotated", "client_id", next.ID)
	out := SpecOf(next)
	out.ClientSecret = string(secret)
	writeJSON(w, http.StatusOK, out)
}
