// Package adminapi は、運用者が Client と Grant を管理するための JSON API の例である。
//
// エンジンは管理用の HTTP API を持たない（docs/adr/0004-client-profiles.md「影響」）。
// 組み込む側が Go API（client のコンストラクタと遷移メソッド、client.Store、grant.Service）で
// 用意するもので、このパッケージはその一例である。Dynamic Client Registration（RFC 7591）の
// 代わりではなく、呼び出せるのは運用者だけである。
//
//	GET    /clients?after=&limit=         一覧（client_id の昇順。続きは next_after を after に渡す）
//	POST   /clients                       登録。生成したシークレットは応答の client_secret で 1 回だけ返す
//	GET    /clients/{id}                  取得
//	PUT    /clients/{id}                  開放項目の置き換え（ADR-0004 §2）
//	DELETE /clients/{id}                  削除。Grant とトークンも失効する
//	POST   /clients/{id}/secret           シークレットの再発行。旧シークレットは直ちに使えなくなる
//	GET    /clients/{id}/grants?after=&limit=   この Client を利用しているユーザーの一覧（subject の昇順）
//	DELETE /clients/{id}/grants?subject=  1 人のユーザーとの連携を解除する
//
// Client の表現（ClientSpec）は登録・取得・更新で同じ形で、項目名は RFC 7591 §2 のクライアント
// メタデータに寄せている。プロトコルの判断はここに書かない（Profile の規則は client が、
// 失効の連鎖は Store が決める）。HTTP 層の仕事は、JSON の読み書きとステータスへの写像だけである。
//
// 全ルートで Config.Auth を通す。認証を設定しないと New が失敗する（fail-closed）。
// 公開エンドポイントとは別のリスナーに載せ、外部に公開しないこと。
//
// 例として簡略化している点:
//   - 認証は事前共有の Bearer トークン 1 つで、運用者を区別しない。監査ログ（event=admin.*）に
//     「誰が」は残らない。本番では Authenticator を運用者ごとの認証に差し替え、主体をログに足す。
//   - 更新は後から保存した方が勝つ（版番号による同時編集の検出はしない）。シークレットだけは
//     専用の操作（Store.RotateClientSecret）なので、古い値の保存で戻ることはない。
package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
)

// ページの件数の既定値と上限。
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// maxBody は要求本文の上限。redirect URI を多数持つ Client でも十分な大きさ。
const maxBody = 64 << 10

// Authenticator は管理 API の呼び出し元を認証する。httpapi.BearerAuthenticator がこれを満たす。
type Authenticator interface {
	// Authenticate は認証に失敗したら非 nil の error を返す。
	Authenticate(r *http.Request) error
}

// Config は管理 API の設定。
type Config struct {
	// Store は Client の一覧・登録・変更・削除・シークレットの再発行に使う。必須。
	Store client.Store
	// Grants は Client ごとの Grant の一覧と失効に使う（Engine.Grants）。必須。
	Grants *grant.Service
	// Auth は全ルートに適用する認証。必須。
	Auth Authenticator
	// Logger は nil なら slog.Default()。
	Logger *slog.Logger
}

// API は管理 API。
type API struct {
	cfg    Config
	logger *slog.Logger
}

// New は Config を検証して API を返す。
func New(cfg Config) (*API, error) {
	if cfg.Store == nil || cfg.Grants == nil {
		return nil, errors.New("adminapi: Store and Grants are required")
	}
	if cfg.Auth == nil {
		return nil, errors.New("adminapi: Auth is required")
	}
	a := &API{cfg: cfg, logger: cfg.Logger}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	return a, nil
}

// Handler は管理 API の http.Handler を返す。全ルートで認証を通す。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /clients", a.handleListClients)
	mux.HandleFunc("POST /clients", a.handleCreateClient)
	mux.HandleFunc("GET /clients/{id}", a.handleGetClient)
	mux.HandleFunc("PUT /clients/{id}", a.handleUpdateClient)
	mux.HandleFunc("DELETE /clients/{id}", a.handleDeleteClient)
	mux.HandleFunc("POST /clients/{id}/secret", a.handleRotateSecret)
	mux.HandleFunc("GET /clients/{id}/grants", a.handleListGrants)
	mux.HandleFunc("DELETE /clients/{id}/grants", a.handleRevokeGrant)
	return a.requireAuth(mux)
}

func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.cfg.Auth.Authenticate(r); err != nil {
			a.logger.WarnContext(r.Context(), "admin api authentication failed", "event", "admin.unauthorized",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "admin api authentication failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientPath は Client の URL パスを返す。client_id は URL（事前登録した MCP Client）のことが
// あるので、パスの 1 セグメントに収まるようエスケープする。
func ClientPath(id string) string { return "/clients/" + url.PathEscape(id) }

// --- JSON ---

// errorBody はエラー応答の形。Interaction API と同じく error と error_description を持つ。
//
//	invalid_request          400  本文やクエリが読めない、この操作では指定できない項目がある
//	invalid_client_metadata  400  Profile の規則に違反している（RFC 7591 §3.2.2 と同じ名前）
//	unauthorized             401  認証に失敗した
//	not_found                404  Client または Grant がない
//	conflict                 409  client_id が登録済み、または操作の途中で削除・作り直しされた
//	server_error             500  内部障害（詳細はログに出す）
type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// 応答にシークレットや利用者の識別子を含むので、どの応答もキャッシュさせない
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, errorBody{Error: code, Description: description})
}

func (a *API) internalError(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.ErrorContext(r.Context(), "admin api internal error", "event", "http.internal_error", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "server_error", "internal error")
}

// decodeJSON は本文を v に読む。未知の項目は拒否する（項目名の打ち間違いが、既定値での登録に
// ならないようにする）。失敗したら 400 を書いて false を返す。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: unexpected data after the object")
		return false
	}
	return true
}

// pageParams は一覧のクエリ（after、limit）を読む。limit は省略なら DefaultPageSize、上限は MaxPageSize。
func pageParams(r *http.Request) (after string, limit int, err error) {
	q := r.URL.Query()
	limit = DefaultPageSize
	if v := q.Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 1 || limit > MaxPageSize {
			return "", 0, fmt.Errorf("limit must be an integer within [1, %d]", MaxPageSize)
		}
	}
	return q.Get("after"), limit, nil
}
