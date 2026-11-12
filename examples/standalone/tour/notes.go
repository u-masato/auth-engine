package tour

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/u-masato/auth-engine/resourceserver"
)

// Notes API が要求する scope。
const (
	ScopeRead  = "notes:read"
	ScopeWrite = "notes:write"
)

// note は 1 件のノート。
type note struct {
	ID        int       `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// notesAPI は業務 API「Notes API」（Resource Server）。ノートはユーザー（トークンの sub）ごとに持つ。
//
// トークンの検証（署名または Introspection、iss、exp、aud、scope）は resourceserver.Protector が行い、
// ここは検証済みの主体（Principal）だけを見る。誰のノートを返すかを決めるのは Resource Server で、
// auth-engine は業務データに関与しない。
type notesAPI struct {
	mu    sync.Mutex
	next  int
	notes map[string][]note // subject → ノート
}

// newResourceServer は Notes API の http.Handler を返す。
func newResourceServer(resourceURL, issuer string, verifier resourceserver.TokenVerifier, logger *slog.Logger) (http.Handler, error) {
	p, err := resourceserver.New(resourceserver.Config{
		Resource:             resourceURL,
		AuthorizationServers: []string{issuer},
		Scopes:               []string{ScopeRead, ScopeWrite},
		Name:                 "Notes API",
		Verifier:             verifier,
		Logger:               logger,
	})
	if err != nil {
		return nil, err
	}
	api := &notesAPI{notes: map[string][]note{}}
	mux := http.NewServeMux()
	mux.Handle(p.MetadataPath(), p.MetadataHandler()) // RFC 9728 §3
	// ルートごとに必要な scope を決める。足りなければ Protector が 403 insufficient_scope を返す（RFC 6750 §3.1）
	mux.Handle("GET /notes", p.Protect(http.HandlerFunc(api.list), ScopeRead))
	mux.Handle("POST /notes", p.Protect(http.HandlerFunc(api.create), ScopeWrite))
	return mux, nil
}

// list はトークンの sub が持つノートを返す。
func (a *notesAPI) list(w http.ResponseWriter, r *http.Request) {
	pr, _ := resourceserver.FromContext(r.Context())
	a.mu.Lock()
	notes := append([]note{}, a.ownedLocked(pr.Subject)...)
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"owner": pr.Subject, "notes": notes})
}

// create はトークンの sub のノートを 1 件足す。
func (a *notesAPI) create(w http.ResponseWriter, r *http.Request) {
	pr, _ := resourceserver.FromContext(r.Context())
	var in struct {
		Text string `json:"text"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil || json.Unmarshal(body, &in) != nil || strings.TrimSpace(in.Text) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "text is required"})
		return
	}
	a.mu.Lock()
	a.ownedLocked(pr.Subject)
	a.next++
	n := note{ID: a.next, Text: strings.TrimSpace(in.Text), CreatedAt: time.Now().UTC().Truncate(time.Second)}
	a.notes[pr.Subject] = append(a.notes[pr.Subject], n)
	a.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"owner": pr.Subject, "note": n})
}

// ownedLocked は subject のノートを返す。初めてのユーザーには見本を 1 件入れる。
func (a *notesAPI) ownedLocked(subject string) []note {
	if _, ok := a.notes[subject]; !ok {
		a.next++
		a.notes[subject] = []note{{ID: a.next, Text: subject + " さんの最初のノート", CreatedAt: time.Now().UTC().Truncate(time.Second)}}
	}
	return a.notes[subject]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
