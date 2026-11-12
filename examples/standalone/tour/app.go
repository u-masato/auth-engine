package tour

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/examples/standalone/oauthclient"
)

// clientApp は Client「Notes Web」。Web Profile の confidential クライアントで、Authorization Code + PKCE で
// Notes API 向けの Access Token を得て、利用者の代わりに Notes API を呼ぶ。
//
// トークンはサーバー側のセッションに置き、ブラウザにはセッション Cookie だけを渡す（BFF の形）。
// ツアーの画面（図とタイムライン）もここが出す。
type clientApp struct {
	issuer, baseURL, resourceURL string
	clientID, clientSecret       string
	verify                       string
	secure                       bool // セッション Cookie に Secure を付けるか（Client の URL が https のとき）
	ports                        map[string]string
	rec                          *Recorder
	hc                           *http.Client
	logger                       *slog.Logger

	mu       sync.Mutex
	md       *oauthclient.Metadata
	sessions map[string]*session
}

// session は 1 つのブラウザの状態。
type session struct {
	mu sync.Mutex

	flow    *oauthclient.CodeFlow // 進行中の認可要求。コールバックを受けたら消す
	access  string
	refresh string
	scope   string
	expires time.Time
	last    *result
}

// result は直近の操作の結果。画面に出す。
type result struct {
	Title  string
	Status string // "200 OK" など。HTTP の応答がない失敗では空
	OK     bool
	Header string // WWW-Authenticate
	Body   string
	Hint   string
}

const sessionCookie = "tour_session"

func (a *clientApp) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.hub)
	mux.HandleFunc("GET /trace.json", a.trace)
	mux.Handle("POST /start", a.step("ログインして Notes API へのアクセスを許可する", a.start))
	mux.Handle("GET /callback", a.rec.Observe(ClientApp, http.HandlerFunc(a.callback)))
	mux.Handle("POST /actions/read", a.step("ノートを読む", a.read))
	mux.Handle("POST /actions/write", a.step("ノートを書く", a.write))
	mux.Handle("POST /actions/anonymous", a.step("トークンなしで Notes API を呼ぶ", a.anonymous))
	mux.Handle("POST /actions/refresh", a.step("トークンを更新する", a.refresh))
	mux.Handle("POST /actions/revoke", a.step("Access Token を失効させる", a.revoke))
	mux.HandleFunc("POST /reset", a.reset)
	// 他のサイトのページからボタンを押させないよう、状態を変える要求は同一オリジンに限る
	return http.NewCrossOriginProtection().Handler(mux)
}

// step はボタン 1 回分の操作を始め、ブラウザからの要求として記録する。
func (a *clientApp) step(title string, h func(http.ResponseWriter, *http.Request, *session)) http.Handler {
	observed := a.rec.Observe(ClientApp, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := a.session(w, r)
		s.mu.Lock()
		defer s.mu.Unlock()
		h(w, r, s)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.rec.StartStep(title)
		observed.ServeHTTP(w, r)
	})
}

// session は Cookie からセッションを引く。なければ作る。
func (a *clientApp) session(w http.ResponseWriter, r *http.Request) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, err := r.Cookie(sessionCookie); err == nil {
		if s, ok := a.sessions[c.Value]; ok {
			return s
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read は失敗しない（Go 1.24 以降）
	id := base64.RawURLEncoding.EncodeToString(b)
	s := &session{}
	a.sessions[id] = s
	http.SetCookie(w, a.cookie(id, 0))
	return s
}

// cookie はセッション Cookie を組み立てる。maxAge が負なら削除になる。
//
// SameSite=Lax にするのは、認可サーバーからのリダイレクト（トップレベルの GET）でコールバックに
// 届く必要があるため。Secure は Client の URL が https のときに付ける。既定の http://localhost では
// 付けない（付けると、http では Cookie を送らないブラウザでセッションが続かない）。本番の Client は
// https で動かし、必ず Secure を付けること。
func (a *clientApp) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: sessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode}
}

// metadata は認可サーバーのメタデータ（RFC 8414）を取得し、以後はそれを使う。失敗は覚えない。
func (a *clientApp) metadata(ctx context.Context) (*oauthclient.Metadata, error) {
	a.mu.Lock()
	md := a.md
	a.mu.Unlock()
	if md != nil {
		return md, nil
	}
	md, err := oauthclient.Discover(ctx, a.hc, a.issuer)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.md = md
	a.mu.Unlock()
	return md, nil
}

// oauth は Client の資格情報を持つ oauthclient.CodeFlow を返す。
func (a *clientApp) oauth(ctx context.Context) (*oauthclient.CodeFlow, error) {
	md, err := a.metadata(ctx)
	if err != nil {
		return nil, err
	}
	f, err := oauthclient.NewCodeFlow(md, a.clientID, a.baseURL+"/callback", []string{ScopeRead, ScopeWrite})
	if err != nil {
		return nil, err
	}
	f.ClientSecret = a.clientSecret
	f.HTTPClient = a.hc
	// RFC 8707 §2: Access Token の宛先（aud）を Notes API に絞る
	f.Resources = []string{a.resourceURL}
	return f, nil
}

// start は認可要求を組み立て、ブラウザを認可エンドポイントへ送る（RFC 6749 §4.1.1）。
func (a *clientApp) start(w http.ResponseWriter, r *http.Request, s *session) {
	f, err := a.oauth(r.Context())
	if err != nil {
		s.last = &result{Title: "認可サーバーに届かなかった", Body: err.Error()}
		a.back(w, r)
		return
	}
	s.flow = f
	http.Redirect(w, r, f.AuthorizationURL(), http.StatusSeeOther)
}

// callback は redirect URI に戻ってきた認可応答を受け、Code をトークンに交換する。
func (a *clientApp) callback(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flow
	if f == nil {
		s.last = &result{Title: "進行中の認可要求がない", Hint: "このブラウザで「ログイン」を押してから戻ってくる必要がある（RFC 6749 §10.12）"}
		a.back(w, r)
		return
	}
	s.flow = nil // Code は 1 回しか使えない（RFC 6749 §4.1.2）
	// state と iss（RFC 9207 §2.4）は HandleCallback が確かめる
	code, err := f.HandleCallback(r.URL.Query())
	if err != nil {
		res := &result{Title: "認可されなかった", Body: err.Error()}
		var aerr *oauthclient.AuthorizationError
		if errors.As(err, &aerr) {
			res.Hint = "Interaction App が伝えた拒否を、auth-engine が OAuth のエラーとして Client に戻した（RFC 6749 §4.1.2.1）。トークンは発行されていない"
		}
		s.last = res
		a.back(w, r)
		return
	}
	tok, err := f.Exchange(r.Context(), code)
	if err != nil {
		s.last = &result{Title: "トークンに交換できなかった", Body: err.Error()}
		a.back(w, r)
		return
	}
	s.keep(tok)
	s.last = &result{Title: "トークンを受け取った", Status: "200 OK", OK: true, Body: tokenView(tok),
		Hint: "トークンは Client のサーバー側セッションに保存した。ブラウザが持つのはセッション Cookie だけ。付与された scope は同意画面で選んだもの"}
	a.back(w, r)
}

// keep はトークン応答をセッションに保存する。Refresh Token は Rotation されるので必ず差し替える。
func (s *session) keep(tok *oauthclient.TokenResponse) {
	s.access, s.refresh, s.scope = tok.AccessToken, tok.RefreshToken, tok.Scope
	s.expires = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
}

func (a *clientApp) read(w http.ResponseWriter, r *http.Request, s *session) {
	if s.access == "" {
		s.last = &result{Title: "ノートを読む", Hint: "まだ Access Token がない。先にログインする"}
	} else {
		s.last = a.call(r.Context(), "ノートを読む", http.MethodGet, s.access, nil)
	}
	a.back(w, r)
}

func (a *clientApp) write(w http.ResponseWriter, r *http.Request, s *session) {
	text := strings.TrimSpace(r.FormValue("text"))
	if text == "" {
		text = "ツアーで書いたノート"
	}
	if s.access == "" {
		s.last = &result{Title: "ノートを書く", Hint: "まだ Access Token がない。先にログインする"}
	} else {
		body, _ := json.Marshal(map[string]string{"text": text})
		s.last = a.call(r.Context(), "ノートを書く", http.MethodPost, s.access, body)
	}
	a.back(w, r)
}

func (a *clientApp) anonymous(w http.ResponseWriter, r *http.Request, s *session) {
	s.last = a.call(r.Context(), "トークンなしで Notes API を呼ぶ", http.MethodGet, "", nil)
	a.back(w, r)
}

// call は Notes API を呼び、結果を画面用にまとめる。accessToken が空なら Authorization を付けない。
func (a *clientApp) call(ctx context.Context, title, method, accessToken string, body []byte) *result {
	req, err := http.NewRequestWithContext(ctx, method, a.resourceURL+"/notes", bytes.NewReader(body))
	if err != nil {
		return &result{Title: title, Body: err.Error()}
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken) // RFC 6750 §2.1
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.hc.Do(req)
	if err != nil {
		return &result{Title: title, Body: err.Error()}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	out := &result{Title: title, Status: res.Status, OK: res.StatusCode/100 == 2, Header: res.Header.Get("WWW-Authenticate"), Body: indent(raw)}
	switch res.StatusCode {
	case http.StatusOK, http.StatusCreated:
		out.Hint = "Notes API が Access Token を検証し、トークンの sub（応答の owner）のノートだけを扱った。Client はユーザーが誰かを、この応答で初めて知る"
	case http.StatusUnauthorized:
		if accessToken == "" {
			out.Hint = "WWW-Authenticate の resource_metadata が、この API を守る認可サーバーの場所を教える（RFC 9728 §5.1）。Client はそこからトークンを取りに行く"
		} else {
			out.Hint = "Access Token が無効（期限切れか失効）。「トークンを更新」で新しいものを取れる"
		}
	case http.StatusForbidden:
		out.Hint = "トークンは有効だが scope が足りない。同意画面で外した権限が必要な操作なので、もう一度ログインして許可すると通る"
	}
	return out
}

// refresh は Refresh Token で新しいトークンを得る（RFC 6749 §6）。
func (a *clientApp) refresh(w http.ResponseWriter, r *http.Request, s *session) {
	const title = "トークンを更新する"
	defer a.back(w, r)
	if s.refresh == "" {
		s.last = &result{Title: title, Hint: "Refresh Token がない。先にログインする"}
		return
	}
	f, err := a.oauth(r.Context())
	if err != nil {
		s.last = &result{Title: title, Body: err.Error()}
		return
	}
	tok, err := f.Refresh(r.Context(), s.refresh, "")
	if err != nil {
		s.last = &result{Title: title, Body: err.Error(), Hint: "Refresh Token が使えなかった。もう一度ログインする"}
		return
	}
	s.keep(tok)
	s.last = &result{Title: title, Status: "200 OK", OK: true, Body: tokenView(tok),
		Hint: "Refresh Token は Rotation された。古い値をもう一度使うと再利用として検知され、Token Family ごと失効する（RFC 9700 §4.14.2）"}
}

// revoke は Access Token を失効させる（RFC 7009）。セッションには残すので、失効後に Notes API を呼んで違いを見られる。
func (a *clientApp) revoke(w http.ResponseWriter, r *http.Request, s *session) {
	const title = "Access Token を失効させる"
	defer a.back(w, r)
	if s.access == "" {
		s.last = &result{Title: title, Hint: "Access Token がない。先にログインする"}
		return
	}
	f, err := a.oauth(r.Context())
	if err == nil {
		err = f.Revoke(r.Context(), s.access, "access_token")
	}
	if err != nil {
		s.last = &result{Title: title, Body: err.Error()}
		return
	}
	hint := "auth-engine の Store では失効した。Notes API は呼ばれるたびに Introspection するので、次の「ノートを読む」は 401 になる"
	if a.verify == VerifyJWT {
		hint = "auth-engine の Store では失効した。ただし Notes API は JWT を自分で検証するので、失効を知らない。「ノートを読む」は exp まで通る（docs/adr/0006 §1）。" +
			"すぐ止めたいときは -verify introspection で起動する"
	}
	s.last = &result{Title: title, Status: "200 OK", OK: true, Body: "（本文なし）", Hint: hint}
}

// reset は記録とこのブラウザのセッションを捨てる。発行済みのトークンは期限まで Store に残る。
func (a *clientApp) reset(w http.ResponseWriter, r *http.Request) {
	a.rec.Reset()
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, a.cookie("", -1))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// back は結果を見せるためにトップへ戻す（POST-redirect-GET）。
func (a *clientApp) back(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type hubView struct {
	chrome
	Linked      bool
	Scopes      []string
	CanWrite    bool
	Expires     string
	Expired     bool
	TokenClaims string // JWT Access Token の payload。Opaque なら空
	Last        *result
	Steps       []Step // 新しい順
	Verify      string
	ResourceURL string
}

func (a *clientApp) hub(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	s.mu.Lock()
	v := hubView{chrome: chrome{Ports: a.ports, Here: string(ClientApp)}, Linked: s.access != "", Scopes: strings.Fields(s.scope),
		Last: s.last, Verify: a.verify, ResourceURL: a.resourceURL}
	if v.Linked {
		v.CanWrite = slices.Contains(v.Scopes, ScopeWrite)
		v.Expires, v.Expired = s.expires.Format(time.TimeOnly), time.Now().After(s.expires)
		v.TokenClaims = jwtPayload(s.access)
	}
	s.mu.Unlock()
	v.Steps = a.rec.Steps()
	slices.Reverse(v.Steps)
	render(w, a.logger, http.StatusOK, "hub", v)
}

// trace は記録を JSON で返す（画面を使わずに確かめたいとき用）。
func (a *clientApp) trace(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.rec.Steps())
}

// tokenView はトークン応答を、値を先頭だけにして整形する。
func tokenView(tok *oauthclient.TokenResponse) string {
	m := map[string]any{"token_type": tok.TokenType, "expires_in": tok.ExpiresIn, "scope": tok.Scope,
		"access_token": abbreviate(tok.AccessToken)}
	if tok.RefreshToken != "" {
		m["refresh_token"] = abbreviate(tok.RefreshToken)
	}
	return prettyJSON(m)
}

// jwtPayload は JWT の payload を整形して返す。JWT でなければ空。
//
// 画面で中身を見せるためだけのもので、検証はしていない。Client は本来 Access Token を不透明な文字列として
// 扱い、中身を解釈しない（RFC 9068 §6）。検証するのは Resource Server である。
func jwtPayload(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	return indent(raw)
}

// indent は JSON を整形する。JSON でなければそのまま返す。
func indent(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, bytes.TrimSpace(raw), "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
