package authorization

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/internal/rand"
	"github.com/u-masato/auth-engine/storage"
)

// Resume はブラウザが Resume URL で戻ってきたときに Code を発行し、Client へのリダイレクト URL を返す
// （ADR-0003 §3 (7)(8)）。
//
// 失敗のうち ErrTransactionNotFound / ErrTransactionExpired / ErrResumeDenied は
// Client へリダイレクトせずエラーページを描く。Txn が rejected なら、Client 向けの
// エラー応答 URL を返す（これは正常な戻り値であり err は nil）。
//
// 書き込みの順序は fail-closed にする: まず Txn を consumed に遷移させ（CAS）、その後に
// Grant と Code を作る。途中で失敗しても Txn は消費済みで、Code は存在しない。
func (s *Service) Resume(ctx context.Context, txnID, resumeToken, browserBinding string) (string, error) {
	txn, err := s.Transaction(ctx, txnID)
	if err != nil {
		return "", err
	}
	if txn.Status != StatusCompleted && txn.Status != StatusRejected {
		return "", ErrResumeDenied
	}
	// 定数時間比較。両方を評価してから判定する（早期 return で情報を漏らさない）。
	tokenOK := rand.HashEqual(txn.ResumeTokenHash, resumeToken)
	bindOK := rand.HashEqual(txn.BrowserBindingHash, browserBinding)
	if !tokenOK || !bindOK {
		return "", ErrResumeDenied
	}

	if err := s.Store.TransitionTransaction(ctx, txn.ID, txn.Status, StatusConsumed, Patch{}); err != nil {
		if errors.Is(err, storage.ErrStateConflict) || errors.Is(err, storage.ErrNotFound) {
			return "", ErrResumeDenied
		}
		return "", fmt.Errorf("authorization: transition transaction: %w", err)
	}

	if txn.Status == StatusRejected {
		perr := &Error{Code: txn.Rejection.Error, Description: txn.Rejection.Description, RedirectURI: txn.Request.RedirectURI, State: txn.Request.State}
		return perr.RedirectURL(s.Issuer), nil
	}
	return s.issueCode(ctx, txn, s.Clock.Now())
}

// issueCode は completed な Txn から Grant を更新し、Code を発行して成功応答 URL を返す。
func (s *Service) issueCode(ctx context.Context, txn *Transaction, now time.Time) (string, error) {
	out := txn.Outcome
	grantID, err := rand.Token("")
	if err != nil {
		return "", err
	}
	g, err := s.Grants.UpsertGrant(ctx, &grant.Grant{
		ID:        grantID,
		ClientID:  txn.Request.ClientID,
		Subject:   out.Subject,
		Scopes:    out.GrantedScopes,
		Claims:    out.Claims,
		Status:    grant.StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return "", fmt.Errorf("authorization: upsert grant: %w", err)
	}

	code, err := rand.Token("")
	if err != nil {
		return "", err
	}
	familyID, err := rand.Token("")
	if err != nil {
		return "", err
	}
	ac := &AuthorizationCode{
		Hash:                rand.Hash(code),
		TxnID:               txn.ID,
		ClientID:            txn.Request.ClientID,
		GrantID:             g.ID,
		FamilyID:            familyID,
		Subject:             out.Subject,
		RedirectURI:         txn.Request.RedirectURI,
		RedirectURIExplicit: txn.Request.RedirectURIExplicit,
		Scopes:              out.GrantedScopes,
		CodeChallenge:       txn.Request.CodeChallenge,
		CodeChallengeMethod: txn.Request.CodeChallengeMethod,
		Nonce:               txn.Request.Nonce,
		Resource:            txn.Request.Resource,
		AuthenticatedAt:     out.AuthenticatedAt,
		AMR:                 out.AMR,
		ACR:                 out.ACR,
		Claims:              out.Claims,
		CreatedAt:           now,
		ExpiresAt:           now.Add(s.codeTTL()),
	}
	if err := s.Store.CreateAuthorizationCode(ctx, ac); err != nil {
		return "", fmt.Errorf("authorization: create code: %w", err)
	}

	// RFC 6749 §4.1.2 の成功応答に RFC 9207 の iss を付ける。
	q := url.Values{}
	q.Set("code", code)
	if txn.Request.State != "" {
		q.Set("state", txn.Request.State)
	}
	q.Set("iss", s.Issuer)
	return appendQuery(txn.Request.RedirectURI, q), nil
}
