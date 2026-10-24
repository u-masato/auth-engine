// Package console は、デモ環境で Client の登録と各フローの手動確認をブラウザだけで行うための
// 開発者コンソールである。役割は 2 つある。
//
//   - 運用者: Client を Store に直接登録する（register.go）。エンジンの公開 API ではない。
//     Dynamic Client Registration（RFC 7591）は実装しない方針なので（docs/roadmap.md M3 合意事項 8）、
//     デモでは運用者が Store に書き込む形を画面にしただけである。
//   - Relying Party: 登録した Client として oauthclient で HTTP 越しにフローを実行し、
//     各段階の要求・応答・検証結果を仕様の節番号付きで表示する（flow.go）。
//
// 対応する仕様: RFC 6749 §4.1 / §4.4 / §6 / §10.12、RFC 7009、RFC 7636、RFC 7662、RFC 8252 §7.3、
// RFC 9207、OIDC Core §3.1.2.1 / §3.1.3.7 / §5.3 / §12.2。
//
// 認証がなく Store に書き込めるので、127.0.0.1 にだけ bind すること。
//
// デモとして簡略化している点:
//   - フローの状態はプロセス内のメモリに置き、コールバックは state で引き当てる。本物の RP は
//     state をブラウザのセッションに結びつける（RFC 6749 §10.12）。ここでは確認しやすさを優先した。
//   - コンソールが登録した Client の Secret はメモリにだけ持つ。再起動後は開始フォームに入れ直す。
package console

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
	"github.com/u-masato/auth-engine/storage"
)

// Config はコンソールの設定。
type Config struct {
	// Issuer はエンジンの Issuer。メタデータは最初に使うときに取得する（起動順に依存しないため）。
	Issuer string
	// BaseURL はコンソール自身の URL（例: http://127.0.0.1:8083）。redirect URI は BaseURL + "/callback"。
	// Native の loopback 照合はポートだけを無視するので（RFC 8252 §7.3）、パスは /callback に固定する。
	BaseURL string
	// Store は Client の登録と参照に使う。
	Store client.Store
	// Known は起動時に分かっている Client（demo-cli や -clients で登録したもの）。一覧に出す。
	Known      []KnownClient
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// KnownClient は一覧に出す Client。Secret が分かっていれば開始フォームに入れておく。
type KnownClient struct {
	ID     string
	Secret string
}

// App は開発者コンソール。
type App struct {
	cfg    Config
	hc     *http.Client
	logger *slog.Logger

	mu       sync.Mutex
	md       *oauthclient.Metadata
	clients  []KnownClient    // 登録順
	flows    map[string]*flow // flow ID → flow
	byState  map[string]*flow // state → flow（コールバックの引き当て）
	flowList []*flow          // 新しい順
}

// New は App を作る。
func New(cfg Config) (*App, error) {
	if cfg.Issuer == "" || cfg.BaseURL == "" || cfg.Store == nil {
		return nil, errors.New("console: Issuer, BaseURL and Store are required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	a := &App{cfg: cfg, hc: cfg.HTTPClient, logger: cfg.Logger,
		flows: map[string]*flow{}, byState: map[string]*flow{}}
	if a.hc == nil {
		a.hc = &http.Client{Timeout: 10 * time.Second}
	}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	for _, k := range cfg.Known {
		a.remember(k)
	}
	return a, nil
}

// RedirectURI はコンソールのコールバック URL。
func (a *App) RedirectURI() string { return a.cfg.BaseURL + "/callback" }

// Handler はコンソールの http.Handler を返す。
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleIndex)
	mux.HandleFunc("POST /clients", a.handleRegister)
	mux.HandleFunc("GET /clients/{id}", a.handleClient)
	mux.HandleFunc("POST /flows", a.handleStart)
	mux.HandleFunc("GET /flows/{id}", a.handleFlow)
	mux.HandleFunc("POST /flows/{id}/{action}", a.handleAction)
	mux.HandleFunc("GET /callback", a.handleCallback)
	return mux
}

// metadata はエンジンのメタデータ（RFC 8414）を取得し、以後はそれを使う。失敗はキャッシュしない。
func (a *App) metadata(ctx context.Context) (*oauthclient.Metadata, error) {
	a.mu.Lock()
	md := a.md
	a.mu.Unlock()
	if md != nil {
		return md, nil
	}
	md, err := oauthclient.Discover(ctx, a.hc, a.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	a.mu.Lock()
	a.md = md
	a.mu.Unlock()
	return md, nil
}

// remember は Client を一覧に加える。既にあれば Secret だけ更新する（空では上書きしない）。
func (a *App) remember(k KnownClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.clients {
		if a.clients[i].ID == k.ID {
			if k.Secret != "" {
				a.clients[i].Secret = k.Secret
			}
			return
		}
	}
	a.clients = append(a.clients, k)
}

func (a *App) knownSecret(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range a.clients {
		if k.ID == id {
			return k.Secret
		}
	}
	return ""
}

// --- 画面 ---

//go:embed console.html
var templateFS embed.FS

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"join":   strings.Join,
	"native": func(p client.Profile) bool { return p == client.ProfileNative },
	"inc":    func(i int) int { return i + 1 },
}).ParseFS(templateFS, "console.html"))

// clientView は一覧と詳細に出す Client の情報。Store から取れなかったものは Err に理由を入れる。
type clientView struct {
	Client    *client.Client
	ID        string
	Secret    string
	Err       string
	Usable    bool // コンソールの redirect URI で Code フローを実行できる
	Generated bool // この画面でシークレットを初めて表示する
}

func (a *App) clientView(ctx context.Context, k KnownClient) clientView {
	v := clientView{ID: k.ID, Secret: k.Secret}
	c, err := a.cfg.Store.GetClient(ctx, k.ID)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		v.Err = "Store に見つからない（reset した後なら再登録が必要）"
	case err != nil:
		v.Err = err.Error()
	default:
		v.Client = c
		v.Usable = c.Profile == client.ProfileMachine || a.redirectUsable(c)
	}
	return v
}

// redirectUsable は、コンソールの redirect URI でこの Client の認可要求が通るかを返す。
// 照合そのものはエンジンが行う（client/redirect.go）。ここでは画面の案内に使うだけ。
func (a *App) redirectUsable(c *client.Client) bool {
	cb := a.RedirectURI()
	if slices.Contains(c.RedirectURIs, cb) {
		return true
	}
	if c.Profile == client.ProfileNative && strings.HasPrefix(cb, "http://127.0.0.1:") {
		// RFC 8252 §7.3: loopback はポートを無視して照合される
		return slices.Contains(c.RedirectURIs, "http://127.0.0.1/callback")
	}
	return false
}

type indexPage struct {
	Issuer      string
	RedirectURI string
	Clients     []clientView
	Flows       []flowSummary
	Form        registerForm
	Error       string
}

// flowSummary は履歴に出すフローの要約。flow はトークン操作中に変わるので、ロックを取って写す。
type flowSummary struct {
	ID, ClientID string
	Profile      client.Profile
	Created      time.Time
	Last         string
	Failed       bool
}

func summarize(f *flow) flowSummary {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := flowSummary{ID: f.ID, ClientID: f.ClientID, Profile: f.Profile, Created: f.Created}
	if n := len(f.Steps); n > 0 {
		s.Last, s.Failed = f.Steps[n-1].Title, f.Steps[n-1].Err != ""
	}
	return s
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.renderIndex(w, r, newRegisterForm(a.RedirectURI()), "", http.StatusOK)
}

func (a *App) renderIndex(w http.ResponseWriter, r *http.Request, form registerForm, errMsg string, status int) {
	a.mu.Lock()
	known := slices.Clone(a.clients)
	flows := slices.Clone(a.flowList)
	a.mu.Unlock()
	p := indexPage{Issuer: a.cfg.Issuer, RedirectURI: a.RedirectURI(), Form: form, Error: errMsg}
	for _, f := range flows {
		p.Flows = append(p.Flows, summarize(f))
	}
	for _, k := range known {
		p.Clients = append(p.Clients, a.clientView(r.Context(), k))
	}
	a.render(w, "index", p, status)
}

type clientPage struct {
	Issuer      string
	RedirectURI string
	View        clientView
	Scope       string
}

func (a *App) handleClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v := a.clientView(r.Context(), KnownClient{ID: id, Secret: a.knownSecret(id)})
	if v.Client == nil {
		a.renderError(w, http.StatusNotFound, "client_id "+id+": "+v.Err)
		return
	}
	v.Generated = r.URL.Query().Get("registered") == "1" && v.Secret != ""
	a.render(w, "client", clientPage{Issuer: a.cfg.Issuer, RedirectURI: a.RedirectURI(), View: v,
		Scope: strings.Join(v.Client.Scopes, " ")}, http.StatusOK)
}

func (a *App) render(w http.ResponseWriter, name string, data any, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		a.logger.Error("console: render", "template", name, "error", err)
	}
}

func (a *App) renderError(w http.ResponseWriter, status int, msg string) {
	a.render(w, "error", struct{ Message string }{msg}, status)
}
