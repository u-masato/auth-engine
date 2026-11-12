package tour

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/examples/standalone/loginapp"
)

// interactionApp は Interaction App（ログインと同意の画面）。auth-engine とは別のアプリケーションで、
// Interaction API をバックチャネルで呼ぶ（docs/adr/0003-interaction-contract.md）。
//
// 画面の流れは loginapp と同じだが、ログインセッションを持たず、毎回この画面を出す（ツアーで必ず
// 通るようにするため）。Interaction API の呼び出しには loginapp.App の GetTransaction / Complete /
// Reject をそのまま使う。
type interactionApp struct {
	api       *loginapp.App
	ports     map[string]string
	clientURL string
	logger    *slog.Logger
}

func (a *interactionApp) handler(rec *Recorder) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /login", rec.Observe(Interaction, http.HandlerFunc(a.show)))
	mux.Handle("POST /login", rec.Observe(Interaction, http.HandlerFunc(a.submit)))
	return mux
}

// scopeText は同意画面に出す scope の説明。scope の意味を知っているのは Interaction App と
// Resource Server で、auth-engine は文字列として扱う。
var scopeText = map[string][2]string{
	ScopeRead:  {"ノートを読む", "あなたのノートの一覧を取得します"},
	ScopeWrite: {"ノートを書く", "あなたのノートを追加します"},
}

type scopeView struct{ Name, Label, Detail string }

type loginView struct {
	chrome
	Txn          *loginapp.Transaction
	TxnJSON      string
	Scopes       []scopeView
	RedirectHost string
}

// show は txn の内容を Interaction API から取得し、ログインと同意の画面を出す。
func (a *interactionApp) show(w http.ResponseWriter, r *http.Request) {
	txnID := r.URL.Query().Get("txn")
	if txnID == "" {
		a.message(w, http.StatusBadRequest, "txn がない。この画面は auth-engine の /authorize から送られてきたときだけ使える")
		return
	}
	txn, err := a.api.GetTransaction(r.Context(), txnID)
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	if txn.Status != "pending" {
		a.message(w, http.StatusConflict, "この認可要求は処理済み。Client からやり直す")
		return
	}
	v := loginView{chrome: chrome{Ports: a.ports, Here: string(Interaction)}, Txn: txn, TxnJSON: prettyJSON(txn)}
	for _, s := range txn.Request.Scopes {
		t, ok := scopeText[s]
		if !ok {
			t = [2]string{s, ""}
		}
		v.Scopes = append(v.Scopes, scopeView{Name: s, Label: t[0], Detail: t[1]})
	}
	if u, err := url.Parse(txn.Request.RedirectURI); err == nil {
		v.RedirectHost = u.Host
	}
	render(w, a.logger, http.StatusOK, "login", v)
}

// submit は入力を受け、結果を Interaction API に伝えて、返ってきた resume_url へブラウザを戻す。
func (a *interactionApp) submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.message(w, http.StatusBadRequest, "フォームを読めない")
		return
	}
	txnID := r.PostForm.Get("txn")
	username := strings.TrimSpace(r.PostForm.Get("username"))
	granted := r.PostForm["scope"]

	var resume string
	var err error
	switch {
	case r.PostForm.Get("action") != "approve":
		// 拒否も resume_url を経由して Client に伝える（RFC 6749 §4.1.2.1 の access_denied）
		resume, err = a.api.Reject(r.Context(), txnID, "access_denied", "the user denied the request")
	case username == "":
		a.message(w, http.StatusBadRequest, "ユーザー名が要る")
		return
	case len(granted) == 0:
		// scope をすべて外した承認は拒否として扱う（エンジンは空の granted_scopes を受け付けない）
		resume, err = a.api.Reject(r.Context(), txnID, "access_denied", "no scope was granted")
	default:
		// ここで本人確認をしたことにする。本番ではパスワードやパスキーを検証した後にだけ Complete する
		resume, err = a.api.Complete(r.Context(), txnID, loginapp.Outcome{
			Subject:         username,
			AuthenticatedAt: time.Now(),
			GrantedScopes:   granted,
			AMR:             []string{"demo"},
		})
	}
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	http.Redirect(w, r, resume, http.StatusFound)
}

func (a *interactionApp) apiFailure(w http.ResponseWriter, err error) {
	var apiErr *loginapp.APIError
	if errors.As(err, &apiErr) && apiErr.Status/100 == 4 {
		a.message(w, apiErr.Status, "Interaction API が要求を受け付けなかった（"+apiErr.Code+": "+apiErr.Description+"）。Client からやり直す")
		return
	}
	a.logger.Error("tour: interaction api call failed", "error", err)
	a.message(w, http.StatusBadGateway, "Interaction API を呼べなかった")
}

func (a *interactionApp) message(w http.ResponseWriter, status int, text string) {
	render(w, a.logger, status, "message", messageView{
		chrome: chrome{Ports: a.ports, Here: string(Interaction)}, Title: "Interaction App", Text: text, BackURL: a.clientURL,
	})
}
