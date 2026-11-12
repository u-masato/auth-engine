package tour

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Component は境界図のノード。
type Component string

const (
	Browser     Component = "browser"
	ClientApp   Component = "client"
	Engine      Component = "engine"
	Interaction Component = "interaction"
	Resource    Component = "resource"
	Store       Component = "store"
)

// fromHeader はサーバー間の要求が送信元を名乗るヘッダ。図に出すための目印で、プロトコルの一部ではない。
// 誰でも偽れるが、変わるのは表示だけである。ヘッダのない要求はブラウザからとみなす。
const fromHeader = "Tour-From"

// KV は画面に出す名前と値の組。
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// Event は境界を越えた 1 回のやり取り。HTTP の要求と応答、または Store の 1 メソッド。
type Event struct {
	Seq    int       `json:"seq"`   // 通し番号
	Index  int       `json:"index"` // Step の中での順番（1 始まり）
	At     time.Time `json:"at"`
	From   Component `json:"from"`
	To     Component `json:"to"`
	Method string    `json:"method"` // HTTP メソッド。Store では空
	Target string    `json:"target"` // パス、または Store のメソッド名
	Status int       `json:"status"` // HTTP ステータス。応答前と Store では 0
	Failed bool      `json:"failed"` // 4xx / 5xx、または Store のエラー
	Note   string    `json:"note"`   // 何が起きたかの説明
	Ref    string    `json:"ref"`    // 対応する仕様の節

	Request  []KV `json:"request"`
	Response []KV `json:"response"`
}

// Step は利用者の 1 回の操作（ボタン 1 回）と、それが引き起こしたやり取り。
type Step struct {
	N       int       `json:"n"`
	Title   string    `json:"title"`
	Started time.Time `json:"started"`
	Events  []Event   `json:"events"`
}

// maxSteps は覚えておく操作の数。超えたら古いものから捨てる。
const maxSteps = 40

// Recorder はやり取りを時系列で覚える。全コンポーネントが 1 プロセスにいるので共有できる。
type Recorder struct {
	mu    sync.Mutex
	seq   int
	stepN int
	steps []*stepRecord
}

type stepRecord struct {
	n       int
	title   string
	started time.Time
	events  []*Event
}

// StartStep は新しい操作を始める。以後のやり取りはこの操作に属する。
// 操作は 1 つずつ行う前提で、並行する操作のやり取りは区別しない。
func (r *Recorder) StartStep(title string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startLocked(title)
}

func (r *Recorder) startLocked(title string) *stepRecord {
	r.stepN++
	s := &stepRecord{n: r.stepN, title: title, started: time.Now()}
	r.steps = append(r.steps, s)
	if len(r.steps) > maxSteps {
		r.steps = r.steps[len(r.steps)-maxSteps:]
	}
	return s
}

// begin はやり取りを記録に足す。順番は開始時に決める（要求の中で起きた別の要求が、外側より後に並ぶ）。
func (r *Recorder) begin(e Event) *Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var s *stepRecord
	if len(r.steps) > 0 {
		s = r.steps[len(r.steps)-1]
	} else {
		s = r.startLocked("ツアーの外からの要求")
	}
	r.seq++
	e.Seq, e.At = r.seq, time.Now()
	e.Note, e.Ref = explain(&e)
	p := &e
	s.events = append(s.events, p)
	return p
}

// finish は応答を受けてやり取りを確定する。
func (r *Recorder) finish(e *Event, status int, response []KV) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Status, e.Response, e.Failed = status, response, status >= 400
	e.Note, e.Ref = explain(e)
}

// storeCall は auth-engine から Store への 1 回の呼び出しを記録する。
func (r *Recorder) storeCall(method, note string, err error) {
	e := r.begin(Event{From: Engine, To: Store, Target: method})
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Note, e.Ref = note, "docs/adr/0005-storage-port.md"
	if err != nil {
		e.Failed, e.Response = true, []KV{{"error", err.Error()}}
	}
}

// Steps は記録の写しを古い順に返す。
func (r *Recorder) Steps() []Step {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Step, 0, len(r.steps))
	for _, s := range r.steps {
		st := Step{N: s.n, Title: s.title, Started: s.started, Events: make([]Event, 0, len(s.events))}
		for i, e := range s.events {
			c := *e
			c.Index = i + 1
			c.Request, c.Response = slices.Clone(e.Request), slices.Clone(e.Response)
			st.Events = append(st.Events, c)
		}
		out = append(out, st)
	}
	return out
}

// Reset は記録を空にする。
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps, r.seq, r.stepN = nil, 0, 0
}

// Observe は to が受けた HTTP 要求を記録するミドルウェアを返す。
func (r *Recorder) Observe(to Component, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		from := Browser
		switch c := Component(req.Header.Get(fromHeader)); c {
		case ClientApp, Interaction, Resource:
			from = c
		}
		e := r.begin(Event{From: from, To: to, Method: req.Method, Target: shortPath(req.URL.Path), Request: requestView(req)})
		cw := &capture{ResponseWriter: w}
		next.ServeHTTP(cw, req)
		r.finish(e, cw.status(), cw.view())
	})
}

// taggedClient は from として名乗る http.Client を返す。
func taggedClient(from Component) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: tagTransport{from: from, base: http.DefaultTransport}}
}

type tagTransport struct {
	from Component
	base http.RoundTripper
}

func (t tagTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context()) // RoundTripper は受け取った要求を書き換えてはならない
	req.Header.Set(fromHeader, string(t.from))
	return t.base.RoundTrip(req)
}

// --- 表示用の整形 ---

// maxBody は記録する本文の上限。
const maxBody = 8 << 10

// secretKeys は値を先頭だけにして出すパラメータ。隠すためというより、長い値で画面が埋まらないようにするため。
var secretKeys = map[string]bool{
	"code": true, "code_verifier": true, "access_token": true, "refresh_token": true, "id_token": true,
	"token": true, "client_secret": true,
}

// abbreviate は長い値を先頭 10 文字にする。
func abbreviate(v string) string {
	if len(v) <= 14 {
		return v
	}
	return v[:10] + "…（全 " + strconv.Itoa(len(v)) + " 文字）"
}

func maskParam(k, v string) string {
	switch {
	case secretKeys[k]:
		return abbreviate(v)
	case k == "resume_url":
		return maskURL(v)
	}
	return v
}

// maskURL は URL のクエリのうち secretKeys の値を先頭だけにする。
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	parts := make([]string, 0, len(q))
	for _, k := range sortedKeys(q) {
		for _, v := range q[k] {
			parts = append(parts, k+"="+maskParam(k, v))
		}
	}
	u.RawQuery = ""
	return u.String() + "?" + strings.Join(parts, "&")
}

func sortedKeys(q url.Values) []string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// shortPath は /transactions/{id} の ID を短くする（ID は長い乱数で、図の説明には要らない）。
func shortPath(p string) string {
	rest, ok := strings.CutPrefix(p, "/transactions/")
	if !ok {
		return p
	}
	id, tail, _ := strings.Cut(rest, "/")
	if len(id) > 6 {
		id = id[:6] + "…"
	}
	if tail != "" {
		tail = "/" + tail
	}
	return "/transactions/" + id + tail
}

// requestView は要求のうち画面に出すものを集める。本文は読んだあと next が読めるように戻す。
func requestView(req *http.Request) []KV {
	var out []KV
	add := func(q url.Values) {
		for _, k := range sortedKeys(q) {
			out = append(out, KV{k, maskParam(k, strings.Join(q[k], " "))})
		}
	}
	add(req.URL.Query())
	if req.Body != nil && req.Method != http.MethodGet {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		req.Body = io.NopCloser(bytes.NewReader(body))
		switch mediaType(req.Header.Get("Content-Type")) {
		case "application/x-www-form-urlencoded":
			if q, err := url.ParseQuery(string(body)); err == nil {
				add(q)
			}
		case "application/json":
			var m map[string]any
			if json.Unmarshal(body, &m) == nil {
				for _, k := range sortedMapKeys(m) {
					out = append(out, KV{k, compactJSON(maskJSON(k, m[k]))})
				}
			}
		}
	}
	if h := req.Header.Get("Authorization"); h != "" {
		out = append(out, KV{"Authorization", authView(h)})
	}
	if cs := req.Cookies(); len(cs) > 0 {
		names := make([]string, 0, len(cs))
		for _, c := range cs {
			names = append(names, c.Name)
		}
		out = append(out, KV{"Cookie", strings.Join(names, ", ") + "（値は省略）"})
	}
	return out
}

// authView は Authorization ヘッダを、方式と値の先頭だけにする。
func authView(h string) string {
	scheme, rest, _ := strings.Cut(h, " ")
	if strings.EqualFold(scheme, "Basic") {
		return "Basic（client_id と client_secret）"
	}
	return scheme + " " + abbreviate(strings.TrimSpace(rest))
}

func mediaType(contentType string) string {
	mt, _, _ := mime.ParseMediaType(contentType)
	return mt
}

func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// maskJSON は JSON の値のうち、キーが secretKeys にある文字列を先頭だけにする。
func maskJSON(key string, v any) any {
	switch t := v.(type) {
	case string:
		return maskParam(key, t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = maskJSON(k, val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = maskJSON(key, val)
		}
		return out
	}
	return v
}

func compactJSON(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return encodeJSON(v, "")
}

func prettyJSON(v any) string { return encodeJSON(v, "  ") }

// encodeJSON は画面に出すための JSON を作る。URL の & が \u0026 にならないよう HTML エスケープを切る
// （HTML への埋め込みは html/template がエスケープする）。
func encodeJSON(v any, indent string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// capture は応答のステータスと、JSON の本文を覚える http.ResponseWriter。
type capture struct {
	http.ResponseWriter
	code int
	body bytes.Buffer
}

func (c *capture) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *capture) Write(p []byte) (int, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	if room := maxBody - c.body.Len(); room > 0 && mediaType(c.Header().Get("Content-Type")) == "application/json" {
		c.body.Write(p[:min(len(p), room)])
	}
	return c.ResponseWriter.Write(p)
}

// Unwrap は http.ResponseController が元の ResponseWriter に届くようにする。
func (c *capture) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *capture) status() int {
	if c.code == 0 {
		return http.StatusOK
	}
	return c.code
}

// view は応答のうち画面に出すものを集める。
func (c *capture) view() []KV {
	var out []KV
	h := c.Header()
	if loc := h.Get("Location"); loc != "" {
		out = append(out, KV{"Location", maskURL(loc)})
	}
	if v := h.Get("WWW-Authenticate"); v != "" {
		out = append(out, KV{"WWW-Authenticate", v})
	}
	if cs := h.Values("Set-Cookie"); len(cs) > 0 {
		names := make([]string, 0, len(cs))
		for _, sc := range cs {
			name, _, _ := strings.Cut(sc, "=")
			names = append(names, name)
		}
		out = append(out, KV{"Set-Cookie", strings.Join(names, ", ") + "（値は省略）"})
	}
	if c.body.Len() > 0 {
		var v any
		if json.Unmarshal(c.body.Bytes(), &v) == nil {
			out = append(out, KV{"body", prettyJSON(maskJSON("", v))})
		} else {
			out = append(out, KV{"body", c.body.String()})
		}
	}
	return out
}
