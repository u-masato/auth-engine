package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/storage"
)

// InteractionAuthenticator は Interaction API の呼び出し元を認証する（ADR-0003 §4）。
type InteractionAuthenticator interface {
	// Authenticate は認証に失敗したら非 nil の error を返す。
	Authenticate(r *http.Request) error
}

// BearerAuthenticator は事前共有の Bearer トークンで認証する既定実装。
type BearerAuthenticator struct {
	Token string
}

var errUnauthenticated = errors.New("httpapi: interaction api authentication failed")

// Authenticate は Authorization: Bearer <token> を定数時間で比較する。
func (a BearerAuthenticator) Authenticate(r *http.Request) error {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if a.Token == "" || len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return errUnauthenticated
	}
	if subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(a.Token)) != 1 {
		return errUnauthenticated
	}
	return nil
}

func (s *Server) requireInteractionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.cfg.InteractionAuth.Authenticate(r); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="interaction"`)
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "interaction api authentication failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxInteractionBody は Complete / Reject の本文の上限。Claims を含んでも十分な大きさ。
const maxInteractionBody = 64 << 10

// transactionView は GET /transactions/{id} の応答。Interaction App が UI を描くのに必要な
// 情報だけを返し、state・nonce・code_challenge は含めない。
type transactionView struct {
	ID        string         `json:"id"`
	Status    string         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Client    clientView     `json:"client"`
	Request   requestView    `json:"request"`
	Outcome   *outcomeView   `json:"outcome,omitempty"`
	Rejection *rejectionView `json:"rejection,omitempty"`
}

type clientView struct {
	ClientID string `json:"client_id"`
	Name     string `json:"name"`
	// Profile は web / native / machine / mcp。
	Profile string `json:"profile"`
	// ClientURI は CIMD 文書の client_uri（MCP Client のみ。ADR-0008 §6）。
	ClientURI string `json:"client_uri,omitempty"`
	LogoURI   string `json:"logo_uri,omitempty"`
	PolicyURI string `json:"policy_uri,omitempty"`
}

type requestView struct {
	// RedirectURI は今回の認可要求で実際に使う redirect URI（登録情報と照合済み）。MCP 仕様（CIMD Security）が
	// 同意画面でのホスト名表示を求めるため、全 Profile で返す（ADR-0008 §6）。
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
	Prompt      []string `json:"prompt,omitempty"`
	MaxAge      *int64   `json:"max_age,omitempty"`
	LoginHint   string   `json:"login_hint,omitempty"`
	UILocales   string   `json:"ui_locales,omitempty"`
	ACRValues   string   `json:"acr_values,omitempty"`
	Resource    []string `json:"resource,omitempty"`
}

// outcomeView / completeBody は Complete の本文。authenticated_at は RFC 3339。
type outcomeView struct {
	Subject         string         `json:"subject"`
	AuthenticatedAt time.Time      `json:"authenticated_at"`
	GrantedScopes   []string       `json:"granted_scopes"`
	AMR             []string       `json:"amr,omitempty"`
	ACR             string         `json:"acr,omitempty"`
	Claims          map[string]any `json:"claims,omitempty"`
}

type rejectionView struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

type resumeBody struct {
	ResumeURL string `json:"resume_url"`
}

func (s *Server) handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	txn, err := s.engine.Store.GetTransaction(ctx, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "transaction not found")
			return
		}
		s.interactionInternalError(w, r, err)
		return
	}
	if txn.Expired(s.engine.Clock.Now()) {
		writeJSONError(w, http.StatusGone, "expired", "transaction has expired")
		return
	}
	// Store ではなく Resolver で引く。CIMD Client は Store になく、cimd.Resolver のキャッシュから返る。
	c, err := s.engine.Clients.GetClient(ctx, txn.Request.ClientID)
	if err != nil {
		s.interactionInternalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newTransactionView(txn, c))
}

func newTransactionView(txn *authorization.Transaction, c *client.Client) transactionView {
	v := transactionView{
		ID: txn.ID, Status: string(txn.Status), CreatedAt: txn.CreatedAt, ExpiresAt: txn.ExpiresAt,
		Client: clientView{ClientID: c.ID, Name: c.Name, Profile: string(c.Profile), ClientURI: c.ClientURI, LogoURI: c.LogoURI, PolicyURI: c.PolicyURI},
		Request: requestView{
			RedirectURI: txn.Request.RedirectURI, Scopes: txn.Request.Scopes, Prompt: txn.Request.Prompt, LoginHint: txn.Request.LoginHint,
			UILocales: txn.Request.UILocales, ACRValues: txn.Request.ACRValues, Resource: txn.Request.Resource,
		},
	}
	if txn.Request.HasMaxAge {
		sec := int64(txn.Request.MaxAge / time.Second)
		v.Request.MaxAge = &sec
	}
	if o := txn.Outcome; o != nil {
		v.Outcome = &outcomeView{Subject: o.Subject, AuthenticatedAt: o.AuthenticatedAt, GrantedScopes: o.GrantedScopes, AMR: o.AMR, ACR: o.ACR, Claims: o.Claims}
	}
	if rj := txn.Rejection; rj != nil {
		v.Rejection = &rejectionView{Error: rj.Error, Description: rj.Description}
	}
	return v
}

func (s *Server) handleComplete(w http.ResponseWriter, r *http.Request) {
	var body outcomeView
	if !s.decodeInteractionBody(w, r, &body) {
		return
	}
	resumeToken, err := s.engine.Authorization.Complete(r.Context(), r.PathValue("id"), authorization.Outcome{
		Subject: body.Subject, AuthenticatedAt: body.AuthenticatedAt, GrantedScopes: body.GrantedScopes,
		AMR: body.AMR, ACR: body.ACR, Claims: body.Claims,
	})
	s.writeResumeResult(w, r, r.PathValue("id"), resumeToken, err)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	var body rejectionView
	if !s.decodeInteractionBody(w, r, &body) {
		return
	}
	resumeToken, err := s.engine.Authorization.Reject(r.Context(), r.PathValue("id"), authorization.Rejection{
		Error: body.Error, Description: body.Description,
	})
	s.writeResumeResult(w, r, r.PathValue("id"), resumeToken, err)
}

func (s *Server) decodeInteractionBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxInteractionBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "malformed JSON body: "+err.Error())
		return false
	}
	return true
}

// writeResumeResult は Complete / Reject の結果を HTTP に写す（ADR-0003 §3 (5)）。
func (s *Server) writeResumeResult(w http.ResponseWriter, r *http.Request, txnID, resumeToken string, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, resumeBody{ResumeURL: s.resumeURL(txnID, resumeToken)})
	case errors.Is(err, authorization.ErrTransactionNotFound):
		writeJSONError(w, http.StatusNotFound, "not_found", "transaction not found")
	case errors.Is(err, authorization.ErrTransactionExpired):
		writeJSONError(w, http.StatusGone, "expired", "transaction has expired")
	case errors.Is(err, authorization.ErrTransactionNotPending):
		writeJSONError(w, http.StatusConflict, "not_pending", "transaction has already been completed or rejected")
	case errors.Is(err, authorization.ErrInvalidOutcome):
		writeJSONError(w, http.StatusBadRequest, "invalid_outcome", err.Error())
	default:
		s.interactionInternalError(w, r, err)
	}
}

func (s *Server) interactionInternalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "interaction api internal error", "event", "http.internal_error", "path", r.URL.Path, "error", err)
	writeJSONError(w, http.StatusInternalServerError, "server_error", "internal error")
}
