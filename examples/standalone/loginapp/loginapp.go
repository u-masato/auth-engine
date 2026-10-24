// Package loginapp は、Interaction API を使ってログインと同意を行う Interaction App の
// 最小実装である。エンジンの外側で動く別アプリケーションの例として、またテストの
// 自動承認用（AutoApprove）として使う。
//
// 本番の Interaction App に必要だがここで省いているもの:
//   - 実際の認証（パスワード、パスキー、MFA）。ここではユーザー名を入力するだけで認証済みとみなす。
//   - ログインフォームの CSRF 対策と、自アプリのセッションへの Txn ID の紐づけ
//     （docs/adr/0003-interaction-contract.md §6 の推奨事項）。
//   - prompt=none / login_hint / max_age の解釈。
package loginapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Config は loginapp の設定。
type Config struct {
	// InteractionAPI はエンジンの Interaction Handler の URL（例: http://127.0.0.1:8081）。
	InteractionAPI string
	// APIToken は Interaction API の Bearer トークン。
	APIToken string
	// AutoApprove が true なら、画面を出さず AutoSubject として要求 scope をすべて承認する。
	// E2E テストと Conformance Suite 用。
	AutoApprove bool
	AutoSubject string
	HTTPClient  *http.Client
	Logger      *slog.Logger
}

// App は Interaction App。
type App struct {
	cfg    Config
	api    string
	client *http.Client
	logger *slog.Logger
}

// New は App を作る。
func New(cfg Config) (*App, error) {
	if cfg.InteractionAPI == "" || cfg.APIToken == "" {
		return nil, errors.New("loginapp: InteractionAPI and APIToken are required")
	}
	a := &App{cfg: cfg, api: strings.TrimRight(cfg.InteractionAPI, "/"), client: cfg.HTTPClient, logger: cfg.Logger}
	if a.client == nil {
		a.client = &http.Client{Timeout: 10 * time.Second}
	}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	if a.cfg.AutoSubject == "" {
		a.cfg.AutoSubject = "demo-user"
	}
	return a, nil
}

// Handler は GET /login と POST /login を持つ http.Handler を返す。
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", a.handleGet)
	mux.HandleFunc("POST /login", a.handlePost)
	return mux
}

// --- Interaction API クライアント ---

// Transaction は GET /transactions/{id} の応答のうち、この App が使う部分。
type Transaction struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Client struct {
		ClientID string `json:"client_id"`
		Name     string `json:"name"`
		Profile  string `json:"profile"`
	} `json:"client"`
	Request struct {
		Scopes    []string `json:"scopes"`
		LoginHint string   `json:"login_hint"`
		Prompt    []string `json:"prompt"`
	} `json:"request"`
}

// APIError は Interaction API のエラー応答。
type APIError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("interaction api: %d %s: %s", e.Status, e.Code, e.Description)
}

func (a *App) call(ctx context.Context, method, path string, body any, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, a.api+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		apiErr := &APIError{Status: res.StatusCode}
		_ = json.Unmarshal(data, apiErr)
		return apiErr
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// GetTransaction は Txn の内容を取得する。
func (a *App) GetTransaction(ctx context.Context, id string) (*Transaction, error) {
	var t Transaction
	if err := a.call(ctx, http.MethodGet, "/transactions/"+id, nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Outcome は Complete の本文（ADR-0003 §3 (5)）。
type Outcome struct {
	Subject         string         `json:"subject"`
	AuthenticatedAt time.Time      `json:"authenticated_at"`
	GrantedScopes   []string       `json:"granted_scopes"`
	AMR             []string       `json:"amr,omitempty"`
	ACR             string         `json:"acr,omitempty"`
	Claims          map[string]any `json:"claims,omitempty"`
}

type resumeResponse struct {
	ResumeURL string `json:"resume_url"`
}

// Complete は成功結果を伝え、ブラウザを戻す Resume URL を返す。
func (a *App) Complete(ctx context.Context, id string, out Outcome) (string, error) {
	var res resumeResponse
	if err := a.call(ctx, http.MethodPost, "/transactions/"+id+"/complete", out, &res); err != nil {
		return "", err
	}
	return res.ResumeURL, nil
}

// Reject は失敗結果を伝え、Resume URL を返す。
func (a *App) Reject(ctx context.Context, id, code, description string) (string, error) {
	var res resumeResponse
	body := map[string]string{"error": code, "error_description": description}
	if err := a.call(ctx, http.MethodPost, "/transactions/"+id+"/reject", body, &res); err != nil {
		return "", err
	}
	return res.ResumeURL, nil
}

// --- HTTP ハンドラ ---

var page = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
<style>body{font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem}label{display:block;margin:.5rem 0}</style></head>
<body>
<h1>Sign in to {{.Txn.Client.Name}}</h1>
<p><small>client_id: <code>{{.Txn.Client.ClientID}}</code> ({{.Txn.Client.Profile}})</small></p>
<form method="post" action="/login">
  <input type="hidden" name="txn" value="{{.Txn.ID}}">
  <label>Username <input name="username" value="{{.Txn.Request.LoginHint}}" required autofocus></label>
  <p>{{.Txn.Client.Name}} is requesting:</p>
  {{range .Txn.Request.Scopes}}<label><input type="checkbox" name="scope" value="{{.}}" checked> {{.}}</label>{{end}}
  <p><button name="action" value="approve">Approve</button> <button name="action" value="deny">Deny</button></p>
</form>
<p><small>Demo Interaction App. No password is checked.</small></p>
</body></html>
`))

func (a *App) handleGet(w http.ResponseWriter, r *http.Request) {
	txnID := r.URL.Query().Get("txn")
	if txnID == "" {
		http.Error(w, "missing txn", http.StatusBadRequest)
		return
	}
	txn, err := a.GetTransaction(r.Context(), txnID)
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	if txn.Status != "pending" {
		http.Error(w, "this authorization request has already been handled; start again from the application", http.StatusConflict)
		return
	}
	if a.cfg.AutoApprove {
		a.approve(w, r, txn, a.cfg.AutoSubject, txn.Request.Scopes)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = page.Execute(w, struct{ Txn *Transaction }{txn})
}

func (a *App) handlePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	txnID := r.PostForm.Get("txn")
	txn, err := a.GetTransaction(r.Context(), txnID)
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	switch r.PostForm.Get("action") {
	case "approve":
		username := strings.TrimSpace(r.PostForm.Get("username"))
		if username == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		a.approve(w, r, txn, username, r.PostForm["scope"])
	default:
		resume, err := a.Reject(r.Context(), txn.ID, "access_denied", "the user denied the request")
		if err != nil {
			a.apiFailure(w, err)
			return
		}
		http.Redirect(w, r, resume, http.StatusFound)
	}
}

// approve は subject として認証済みとみなし、granted を承認して Resume URL へ戻す。
func (a *App) approve(w http.ResponseWriter, r *http.Request, txn *Transaction, subject string, granted []string) {
	if len(granted) == 0 {
		// scope をすべて外した承認は拒否として扱う（エンジンは空の granted_scopes を受け付けない）。
		resume, err := a.Reject(r.Context(), txn.ID, "access_denied", "no scope was granted")
		if err != nil {
			a.apiFailure(w, err)
			return
		}
		http.Redirect(w, r, resume, http.StatusFound)
		return
	}
	resume, err := a.Complete(r.Context(), txn.ID, Outcome{
		Subject:         subject,
		AuthenticatedAt: time.Now(),
		GrantedScopes:   granted,
		AMR:             []string{"demo"},
		Claims: map[string]any{
			"name":  subject,
			"email": subject + "@example.com",
		},
	})
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	http.Redirect(w, r, resume, http.StatusFound)
}

func (a *App) apiFailure(w http.ResponseWriter, err error) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusNotFound, http.StatusGone, http.StatusConflict:
			http.Error(w, apiErr.Description+"; start again from the application", apiErr.Status)
			return
		}
	}
	a.logger.Error("interaction api call failed", "error", err)
	http.Error(w, "login service is unavailable", http.StatusBadGateway)
}
