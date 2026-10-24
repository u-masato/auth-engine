package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/u-masato/auth-engine/authorization"
)

// handleAuthorize は /authorize（RFC 6749 §3.1）。GET と POST（form）を受ける。
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var params url.Values
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			s.render.RenderError(w, r, http.StatusBadRequest, authorization.CodeInvalidRequest, "malformed form body")
			return
		}
		params = r.PostForm
	} else {
		params = r.URL.Query()
	}

	binding, err := s.browserBinding(w, r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	txn, err := s.engine.Authorization.Begin(r.Context(), params, binding)
	if err != nil {
		var perr *authorization.Error
		if !errors.As(err, &perr) {
			s.internalError(w, r, err)
			return
		}
		s.logger.InfoContext(r.Context(), "authorization request rejected",
			"event", "authorize.rejected", "error", perr.Code, "description", perr.Description, "redirectable", perr.Redirectable())
		if perr.Redirectable() {
			redirect(w, r, perr.RedirectURL(s.engine.Issuer))
			return
		}
		s.render.RenderError(w, r, http.StatusBadRequest, perr.Code, perr.Description)
		return
	}

	// Interaction App へ。URL に載せるのは Txn ID だけ（ADR-0003 §3 (1)(2)）。
	target := *s.interactionURL
	q := target.Query()
	q.Set("txn", txn.ID)
	target.RawQuery = q.Encode()
	redirect(w, r, target.String())
}

// handleResume は /authorize/resume（ADR-0003 §3 (7)(8)）。
func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	txnID, token := q.Get("txn"), q.Get("token")
	if txnID == "" || token == "" {
		s.render.RenderError(w, r, http.StatusBadRequest, authorization.CodeInvalidRequest, "txn and token are required")
		return
	}
	var binding string
	if c, err := r.Cookie(s.bindingCookieName()); err == nil {
		binding = c.Value
	}

	location, err := s.engine.Authorization.Resume(r.Context(), txnID, token, binding)
	if err != nil {
		switch {
		case errors.Is(err, authorization.ErrTransactionNotFound):
			s.render.RenderError(w, r, http.StatusNotFound, "unknown_transaction", "the authorization transaction does not exist")
		case errors.Is(err, authorization.ErrTransactionExpired):
			s.render.RenderError(w, r, http.StatusGone, "expired_transaction", "the authorization transaction has expired; start again")
		case errors.Is(err, authorization.ErrResumeDenied):
			s.logger.WarnContext(r.Context(), "resume denied", "event", "resume.denied", "txn", txnID)
			s.render.RenderError(w, r, http.StatusBadRequest, "resume_denied", "the authorization could not be resumed; start again")
		default:
			s.internalError(w, r, err)
		}
		return
	}
	redirect(w, r, location)
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "internal error", "event", "http.internal_error", "path", r.URL.Path, "error", err)
	s.render.RenderError(w, r, http.StatusInternalServerError, authorization.CodeServerError, "internal error")
}
