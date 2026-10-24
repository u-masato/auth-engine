// Package loginapp は、Interaction API を使ってログインと同意を行う Interaction App の
// 最小実装である。エンジンの外側で動く別アプリケーションの例として、またテストの
// 自動承認用（AutoApprove）として使う。
//
// ログイン状態は署名なしの Cookie セッション（session.go）で持ち、prompt=none / prompt=login /
// max_age の解釈（OIDC Core §3.1.2.1）はこのセッションに基づいて行う。Conformance Suite の
// Basic OP プロファイルが要求する範囲を満たすための最小実装である。
//
// 本番の Interaction App に必要だがここで省いているもの:
//   - 実際の認証（パスワード、パスキー、MFA）。ここではユーザー名を入力するだけで認証済みとみなす。
//   - 署名付きセッション、ログインフォームの CSRF 対策、自アプリのセッションへの Txn ID の紐づけ
//     （docs/adr/0003-interaction-contract.md §6 の推奨事項）。
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
	"slices"
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
	// Now は現在時刻（認証時刻と max_age の判定に使う）。nil なら time.Now。テスト用。
	Now func() time.Time
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
	if a.cfg.Now == nil {
		a.cfg.Now = time.Now
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
		MaxAge    *int64   `json:"max_age"`
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
	d := decide(r, txn, a.cfg.Now())
	if d.Reject != "" {
		// prompt=none でログインが必要: UI を出さずに Reject する
		a.reject(w, r, txn.ID, d.Reject, "authentication is required but prompt=none was requested")
		return
	}
	if a.cfg.AutoApprove {
		a.approve(w, r, txn, a.cfg.AutoSubject, txn.Request.Scopes, d)
		return
	}
	if d.Session != nil && !slices.Contains(txn.Request.Prompt, "consent") {
		// ログイン済みで再認証も同意の再表示も求められていなければ、そのまま承認する
		a.approve(w, r, txn, d.Session.Subject, txn.Request.Scopes, d)
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
		d := decide(r, txn, a.cfg.Now())
		if d.Session != nil && d.Session.Subject != username {
			d = decision{Fresh: true} // 別のユーザーとしてログインし直した
		}
		a.approve(w, r, txn, username, r.PostForm["scope"], d)
	default:
		a.reject(w, r, txn.ID, "access_denied", "the user denied the request")
	}
}

// approve は subject として認証済みとみなし、granted を承認して Resume URL へ戻す。
// d.Session があれば認証時刻はセッションのもの（既存ログインの再利用）、なければ今。
func (a *App) approve(w http.ResponseWriter, r *http.Request, txn *Transaction, subject string, granted []string, d decision) {
	if len(granted) == 0 {
		// scope をすべて外した承認は拒否として扱う（エンジンは空の granted_scopes を受け付けない）。
		a.reject(w, r, txn.ID, "access_denied", "no scope was granted")
		return
	}
	authenticatedAt := a.cfg.Now()
	if d.Session != nil {
		authenticatedAt = d.Session.AuthenticatedAt
	}
	resume, err := a.Complete(r.Context(), txn.ID, Outcome{
		Subject:         subject,
		AuthenticatedAt: authenticatedAt,
		GrantedScopes:   granted,
		AMR:             []string{"demo"},
		Claims:          demoClaims(subject, authenticatedAt),
	})
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	writeSession(w, session{Subject: subject, AuthenticatedAt: authenticatedAt})
	http.Redirect(w, r, resume, http.StatusFound)
}

func (a *App) reject(w http.ResponseWriter, r *http.Request, txnID, code, description string) {
	resume, err := a.Reject(r.Context(), txnID, code, description)
	if err != nil {
		a.apiFailure(w, err)
		return
	}
	http.Redirect(w, r, resume, http.StatusFound)
}

// demoClaims は OIDC Core §5.1 の標準 Claims をひととおり埋めたデモ用の値。
// エンジンは付与された scope で絞って UserInfo から返す（docs/adr/0006 §3）。
func demoClaims(subject string, authenticatedAt time.Time) map[string]any {
	return map[string]any{
		"name": subject + " Example", "given_name": subject, "family_name": "Example", "middle_name": "Demo",
		"nickname": subject, "preferred_username": subject, "profile": "https://example.com/" + subject,
		"picture": "https://example.com/" + subject + ".png", "website": "https://example.com", "gender": "unspecified",
		"birthdate": "1990-01-01", "zoneinfo": "Asia/Tokyo", "locale": "ja-JP", "updated_at": authenticatedAt.Unix(),
		"email": subject + "@example.com", "email_verified": true,
		"address": map[string]any{"formatted": "1-1 Example-cho, Chiyoda-ku, Tokyo 100-0001, JP", "street_address": "1-1 Example-cho",
			"locality": "Chiyoda-ku", "region": "Tokyo", "postal_code": "100-0001", "country": "JP"},
		"phone_number": "+81 3-0000-0000", "phone_number_verified": false,
	}
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
