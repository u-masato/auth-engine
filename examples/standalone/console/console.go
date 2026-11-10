// Package console は、デモ環境で Client の管理と各フローの手動確認をブラウザだけで行うための
// 開発者コンソール（Client 管理ダッシュボード）である。役割は 2 つある。
//
//   - 運用者: Store の Client を一覧し、登録・変更・削除する（clients.go、register.go、edit.go）。
//     エンジンは管理用の HTTP API を持たないので（docs/adr/0004-client-profiles.md「影響」）、
//     組み込む側が Go API（client のコンストラクタ、Client.Update、client.Store）で用意する。
//     このパッケージはその一例で、Dynamic Client Registration（RFC 7591）の代わりではない。
//   - Relying Party: 登録した Client として oauthclient で HTTP 越しにフローを実行し、
//     各段階の要求・応答・検証結果を仕様の節番号付きで表示する（flow.go）。
//
// 対応する仕様: RFC 6749 §2 / §4.1 / §4.4 / §6 / §10.12、RFC 7009、RFC 7636、RFC 7662、RFC 8252 §7.3、
// RFC 8707 §2、RFC 9207、OIDC Core §3.1.2.1 / §3.1.3.7 / §5.3 / §12.2。
//
// 認証がなく Store に書き込めるので、127.0.0.1 にだけ bind すること。他のサイトからブラウザ経由で
// 書き込まれないよう、状態を変える要求は同一オリジンに限る（http.CrossOriginProtection）。
// 本番の管理画面は、これに加えて運用者の認証と操作の監査ログを持つこと。
//
// デモとして簡略化している点:
//   - フローの状態はプロセス内のメモリに置き、コールバックは state で引き当てる。本物の RP は
//     state をブラウザのセッションに結びつける（RFC 6749 §10.12）。ここでは確認しやすさを優先した。
//   - Client Secret の平文はメモリにだけ持つ（Store はハッシュだけを保存する）。再起動後は
//     開始フォームに入れ直す。
package console

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
)

// DefaultPageSize は一覧の 1 ページの件数の既定値。
const DefaultPageSize = 50

// Config はコンソールの設定。
type Config struct {
	// Issuer はエンジンの Issuer。メタデータは最初に使うときに取得する（起動順に依存しないため）。
	Issuer string
	// BaseURL はコンソール自身の URL（例: http://127.0.0.1:8083）。redirect URI は BaseURL + "/callback"。
	// Native の loopback 照合はポートだけを無視するので（RFC 8252 §7.3）、パスは /callback に固定する。
	BaseURL string
	// Store は Client の一覧・登録・変更・削除に使う。
	Store client.Store
	// Secrets は起動時に分かっている Client Secret の平文（client_id → Secret）。開始フォームに入れておく。
	Secrets map[string]string
	// PageSize は一覧の 1 ページの件数。0 なら DefaultPageSize。
	PageSize   int
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// App は開発者コンソール。
type App struct {
	cfg    Config
	hc     *http.Client
	logger *slog.Logger

	mu       sync.Mutex
	md       *oauthclient.Metadata
	secrets  map[string]string // client_id → Client Secret の平文
	flows    map[string]*flow  // flow ID → flow
	byState  map[string]*flow  // state → flow（コールバックの引き当て）
	flowList []*flow           // 新しい順
}

// New は App を作る。
func New(cfg Config) (*App, error) {
	if cfg.Issuer == "" || cfg.BaseURL == "" || cfg.Store == nil {
		return nil, errors.New("console: Issuer, BaseURL and Store are required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.PageSize < 1 {
		cfg.PageSize = DefaultPageSize
	}
	a := &App{cfg: cfg, hc: cfg.HTTPClient, logger: cfg.Logger,
		secrets: map[string]string{}, flows: map[string]*flow{}, byState: map[string]*flow{}}
	if a.hc == nil {
		a.hc = &http.Client{Timeout: 10 * time.Second}
	}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	for id, secret := range cfg.Secrets {
		a.rememberSecret(id, secret)
	}
	return a, nil
}

// RedirectURI はコンソールのコールバック URL。
func (a *App) RedirectURI() string { return a.cfg.BaseURL + "/callback" }

// Handler はコンソールの http.Handler を返す。
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	// Client の管理（運用者）
	mux.HandleFunc("GET /{$}", a.handleClients)
	mux.HandleFunc("GET /clients/new", a.handleNewClient)
	mux.HandleFunc("POST /clients", a.handleRegister)
	mux.HandleFunc("GET /clients/{id}", a.handleClient)
	mux.HandleFunc("GET /clients/{id}/edit", a.handleEditClient)
	mux.HandleFunc("POST /clients/{id}", a.handleUpdateClient)
	mux.HandleFunc("POST /clients/{id}/delete", a.handleDeleteClient)
	// フローの実行（Relying Party）
	mux.HandleFunc("GET /flows", a.handleFlows)
	mux.HandleFunc("POST /flows", a.handleStart)
	mux.HandleFunc("GET /flows/{id}", a.handleFlow)
	mux.HandleFunc("POST /flows/{id}/{action}", a.handleAction)
	mux.HandleFunc("GET /callback", a.handleCallback)
	// 認証のない管理画面なので、他のサイトが利用者のブラウザに POST させる経路（CSRF）を閉じる。
	// ブラウザ以外（curl、テスト）からの要求は Sec-Fetch-Site も Origin も持たないので通る。
	return http.NewCrossOriginProtection().Handler(mux)
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

// rememberSecret は Client Secret の平文を覚える。空では上書きしない。
func (a *App) rememberSecret(id, secret string) {
	if secret == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secrets[id] = secret
}

func (a *App) forgetSecret(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.secrets, id)
}

func (a *App) knownSecret(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.secrets[id]
}

// --- 画面 ---

//go:embed console.html
var templateFS embed.FS

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"join":       strings.Join,
	"inc":        func(i int) int { return i + 1 },
	"clientPath": clientPath,
	"date":       func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
	"duration":   shortDuration,
}).ParseFS(templateFS, "console.html"))

// clientPath は Client の詳細画面のパスを返す。client_id は URL（事前登録した MCP Client）のことが
// あるので、パスの 1 セグメントに収まるようエスケープする。
func clientPath(id string) string { return "/clients/" + url.PathEscape(id) }

// shortDuration は time.Duration を "1h"、"15m"、"1h30m" のように、0 の単位を省いて表す。
// 編集フォームの初期値にも使うので、time.ParseDuration で読み戻せる形にする。
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// layout は全画面に共通の情報。
type layout struct {
	Title       string
	Nav         string // "clients" | "flows"
	Issuer      string
	RedirectURI string
}

func (a *App) layout(title, nav string) layout {
	return layout{Title: title, Nav: nav, Issuer: a.cfg.Issuer, RedirectURI: a.RedirectURI()}
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
	a.render(w, "error", struct {
		Layout  layout
		Message string
	}{a.layout("エラー", ""), msg}, status)
}
