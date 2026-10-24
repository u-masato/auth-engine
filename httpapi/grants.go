package httpapi

import (
	"net/http"
	"time"

	"github.com/muno/auth-engine/grant"
)

// grantView は GET /grants の 1 要素。Claims は含めない（Interaction App が渡したものであり、
// 同意画面の判断には scope だけで足りる）。
type grantView struct {
	ClientID  string    `json:"client_id"`
	Subject   string    `json:"subject"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type grantsBody struct {
	Grants []grantView `json:"grants"`
}

// handleListGrants は Interaction API の GET /grants?subject=...&client_id=...（ADR-0003 §3 (4)）。
//
// subject は必須。client_id を付けると、その Client に対する active な Grant だけ（0 または 1 件）を
// 返すので、同意スキップの判断に使える。付けなければ subject の全 active Grant（連携済みアプリ一覧）。
func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "subject is required")
		return
	}
	var (
		grants []*grant.Grant
		err    error
	)
	if clientID := r.URL.Query().Get("client_id"); clientID != "" {
		g, ferr := s.engine.Grants.Find(r.Context(), clientID, subject)
		switch {
		case ferr == nil:
			grants = []*grant.Grant{g}
		case ferr == grant.ErrNotFound:
			grants = nil
		default:
			err = ferr
		}
	} else {
		grants, err = s.engine.Grants.List(r.Context(), subject)
	}
	if err != nil {
		s.interactionInternalError(w, r, err)
		return
	}
	body := grantsBody{Grants: make([]grantView, 0, len(grants))}
	for _, g := range grants {
		body.Grants = append(body.Grants, grantView{ClientID: g.ClientID, Subject: g.Subject, Scopes: g.Scopes, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, body)
}
