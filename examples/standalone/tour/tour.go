package tour

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/examples/standalone/loginapp"
	"github.com/u-masato/auth-engine/httpapi"
	"github.com/u-masato/auth-engine/keys"
	"github.com/u-masato/auth-engine/resource"
	"github.com/u-masato/auth-engine/resourceserver"
	"github.com/u-masato/auth-engine/storage/memory"
)

// Notes API がトークンを検証する方式。
const (
	// VerifyJWT は JWT Access Token（RFC 9068）を JWKS でローカル検証する。失効は exp まで伝わらない。
	VerifyJWT = "jwt"
	// VerifyIntrospection は呼ばれるたびに Introspection（RFC 7662）する。失効がすぐ反映される。
	VerifyIntrospection = "introspection"
)

// Config は各コンポーネントの URL。コンポーネントは互いをこの URL で呼ぶので、待ち受けるアドレスと
// 一致していること。
type Config struct {
	// ClientURL は Client（Notes Web）の URL。ツアーの画面もここに出る。
	ClientURL string
	// IssuerURL は auth-engine の公開エンドポイントの URL（Issuer）。
	IssuerURL string
	// InteractionAPIURL は Interaction API の URL。Interaction App だけが呼ぶ。
	InteractionAPIURL string
	// LoginURL は Interaction App の URL（ログイン画面は LoginURL + "/login"）。
	LoginURL string
	// ResourceURL は Notes API（Resource Server）の URL。RFC 8707 の resource indicator としても使う。
	ResourceURL string

	// Verify は Notes API がトークンを検証する方式。VerifyJWT（既定）か VerifyIntrospection。
	Verify string

	// Logger は nil なら slog.Default()。
	Logger *slog.Logger
}

// Tour は配線済みのコンポーネント。それぞれを Config の URL に対応するアドレスで待ち受けさせる。
type Tour struct {
	Client         http.Handler // ClientURL
	Public         http.Handler // IssuerURL
	InteractionAPI http.Handler // InteractionAPIURL
	Login          http.Handler // LoginURL
	Resource       http.Handler // ResourceURL

	rec *Recorder
}

// Steps は記録したやり取りを古い順に返す。
func (t *Tour) Steps() []Step { return t.rec.Steps() }

// New は Store に Client を登録し、全コンポーネントを組み立てる。
func New(ctx context.Context, cfg Config) (*Tour, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Verify == "" {
		cfg.Verify = VerifyJWT
	}
	if cfg.Verify != VerifyJWT && cfg.Verify != VerifyIntrospection {
		return nil, fmt.Errorf("tour: unknown Verify %q (want %q or %q)", cfg.Verify, VerifyJWT, VerifyIntrospection)
	}
	ports := map[string]string{}
	for name, raw := range map[Component]*string{ClientApp: &cfg.ClientURL, Engine: &cfg.IssuerURL, Interaction: &cfg.LoginURL, Resource: &cfg.ResourceURL} {
		*raw = strings.TrimRight(*raw, "/")
		u, err := url.Parse(*raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("tour: the URL of %s must be absolute: %q", name, *raw)
		}
		ports[string(name)] = ":" + u.Port()
	}
	now := time.Now()
	rec := &Recorder{}

	// --- auth-engine ---
	keySet := keys.NewSet()
	key, err := keys.Generate(keys.AlgRS256, now)
	if err != nil {
		return nil, err
	}
	if err := keySet.AddSigning(key); err != nil {
		return nil, err
	}
	// Access Token の形式は Resource Server の検証方式で決まる（ADR-0008 §3）
	notes := resource.Resource{URI: cfg.ResourceURL, Name: "Notes API", Scopes: []string{ScopeRead, ScopeWrite}, AccessTokenFormat: resource.FormatOpaque}
	if cfg.Verify == VerifyJWT {
		notes.AccessTokenFormat = resource.FormatJWT
	}
	store := tracedStore{Store: memory.New(), rec: rec}
	engine, err := authengine.New(authengine.Config{Issuer: cfg.IssuerURL, Store: store, Keys: keySet, Logger: cfg.Logger,
		Resources: []resource.Resource{notes}})
	if err != nil {
		return nil, err
	}

	// Client（Notes Web）を登録する。Web Profile なので PKCE と Client 認証が固定で要る
	web, webSecret, err := client.NewWeb(client.WebParams{
		ID:           "notes-web",
		Name:         "Notes Web",
		RedirectURIs: []string{cfg.ClientURL + "/callback"},
		Scopes:       []string{ScopeRead, ScopeWrite},
		Resources:    []string{cfg.ResourceURL},
		// http://localhost で動かすデモなので http の redirect URI を許す
		AllowInsecureLocalhost: true,
	}, now)
	if err != nil {
		return nil, err
	}
	if err := store.CreateClient(ctx, web); err != nil {
		return nil, err
	}

	// Interaction API のトークンはプロセス内で作り、Interaction App にだけ渡す
	apiToken, err := randomToken()
	if err != nil {
		return nil, err
	}
	srv, err := httpapi.New(httpapi.Config{
		Engine:          engine,
		InteractionURL:  cfg.LoginURL + "/login",
		InteractionAuth: httpapi.BearerAuthenticator{Token: apiToken},
		InsecureCookies: true, // http://localhost のデモ用。本番では false のまま使う
	})
	if err != nil {
		return nil, err
	}

	// --- Interaction App ---
	api, err := loginapp.New(loginapp.Config{InteractionAPI: cfg.InteractionAPIURL, APIToken: apiToken,
		HTTPClient: taggedClient(Interaction), Logger: cfg.Logger})
	if err != nil {
		return nil, err
	}
	login := &interactionApp{api: api, ports: ports, clientURL: cfg.ClientURL, logger: cfg.Logger}

	// --- Resource Server（Notes API）---
	var verifier resourceserver.TokenVerifier = &resourceserver.JWTVerifier{Issuer: cfg.IssuerURL, HTTPClient: taggedClient(Resource)}
	if cfg.Verify == VerifyIntrospection {
		// Introspection を呼ぶには、Resource Server 自身が Machine Profile の Client である必要がある（ADR-0006 §1）
		rs, rsSecret, err := client.NewMachine(client.MachineParams{ID: "notes-api", Name: "Notes API", Scopes: []string{"introspect"}}, now)
		if err != nil {
			return nil, err
		}
		if err := store.CreateClient(ctx, rs); err != nil {
			return nil, err
		}
		verifier = &resourceserver.IntrospectionVerifier{Issuer: cfg.IssuerURL, ClientID: rs.ID, ClientSecret: string(rsSecret),
			HTTPClient: taggedClient(Resource)}
	}
	notesAPI, err := newResourceServer(cfg.ResourceURL, cfg.IssuerURL, verifier, cfg.Logger)
	if err != nil {
		return nil, err
	}

	// --- Client（Notes Web）---
	app := &clientApp{issuer: cfg.IssuerURL, baseURL: cfg.ClientURL, resourceURL: cfg.ResourceURL,
		clientID: web.ID, clientSecret: string(webSecret), verify: cfg.Verify, ports: ports,
		rec: rec, hc: taggedClient(ClientApp), logger: cfg.Logger, sessions: map[string]*session{}}

	return &Tour{
		Client:         app.handler(),
		Public:         rec.Observe(Engine, srv.PublicHandler()),
		InteractionAPI: rec.Observe(Engine, srv.InteractionHandler()),
		Login:          login.handler(rec),
		Resource:       rec.Observe(Resource, notesAPI),
		rec:            rec,
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// --- 画面 ---

//go:embed pages.html
var pagesFS embed.FS

var componentNames = map[Component]string{
	Browser: "ブラウザ", ClientApp: "Client", Engine: "auth-engine", Interaction: "Interaction App", Resource: "Resource Server", Store: "Store",
}

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"name": func(c Component) string { return componentNames[c] },
	// statusClass は HTTP ステータスの百の位を CSS のクラスにする
	"statusClass": func(code int) string { return fmt.Sprintf("s%d", code/100) },
	"multiline":   func(s string) bool { return strings.Contains(s, "\n") },
}).ParseFS(pagesFS, "pages.html"))

// chrome は全画面に共通の値。
type chrome struct {
	// Ports は図に出す各コンポーネントのポート（":8100" の形）。
	Ports map[string]string
	// Here はこの画面を出しているコンポーネント。図に「いまここ」と出す。
	Here string
}

type messageView struct {
	chrome
	Title, Text, BackURL string
}

// render はテンプレートをいったんバッファに描いてから返す（途中で失敗した画面を出さない）。
func render(w http.ResponseWriter, logger *slog.Logger, status int, name string, data any) {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		logger.Error("tour: render", "page", name, "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
