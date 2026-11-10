package authorization

import (
	"context"
	"errors"
	"net/url"

	"github.com/u-masato/auth-engine/internal/rand"
)

// Begin は /authorize の要求を検証して Transaction を作る（ADR-0003 §3 (1)(2)）。
//
// browserBinding はブラウザ結合 Cookie の値（平文）。HTTP 層が既存 Cookie を読むか新規発行して渡す。
// 失敗は *Error で返し、Redirectable なら Client へリダイレクトして返す。
func (s *Service) Begin(ctx context.Context, params url.Values, browserBinding string) (*Transaction, error) {
	if browserBinding == "" {
		return nil, errors.New("authorization: browser binding is required")
	}
	req, perr := parseRequest(ctx, s.Clients, s.Resources, params)
	if perr != nil {
		return nil, perr
	}
	id, err := rand.Token("")
	if err != nil {
		return nil, s.serverError(req, err)
	}
	now := s.Clock.Now()
	txn := &Transaction{
		ID:                 id,
		Status:             StatusPending,
		Request:            *req,
		BrowserBindingHash: rand.Hash(browserBinding),
		CreatedAt:          now,
		ExpiresAt:          now.Add(s.txnTTL()),
	}
	if err := s.Store.CreateTransaction(ctx, txn); err != nil {
		return nil, s.serverError(req, err)
	}
	return txn, nil
}

func (s *Service) serverError(req *Request, cause error) *Error {
	return &Error{Code: CodeServerError, Description: "internal error", RedirectURI: req.RedirectURI, State: req.State, Cause: cause}
}
