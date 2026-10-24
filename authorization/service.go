package authorization

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/grant"
	"github.com/muno/auth-engine/internal/clock"
	"github.com/muno/auth-engine/internal/rand"
	"github.com/muno/auth-engine/resource"
	"github.com/muno/auth-engine/storage"
)

// 期限の既定値と上限（ADR-0003 §5）。
const (
	DefaultTransactionTTL = 10 * time.Minute
	MaxTransactionTTL     = time.Hour
	DefaultCodeTTL        = time.Minute
	MaxCodeTTL            = 10 * time.Minute // RFC 6749 §4.1.2
)

// ResumeTokenPrefix は Resume Token の接頭辞。
const ResumeTokenPrefix = "rs_"

// Service は認可エンドポイントのユースケース群。フィールドは Engine が配線する。
type Service struct {
	Clients client.Resolver
	Store   Store
	Grants  grant.Store
	Clock   clock.Clock

	// Resources は認可要求の resource パラメータで指定できる Resource Server の集合（RFC 8707 §2.1）。
	// nil なら空集合で、resource 付きの要求はすべて invalid_target になる。
	Resources *resource.Set

	// Issuer は認可サーバーの識別子（RFC 8414 の issuer）。認可応答の iss に使う（RFC 9207）。
	Issuer string

	// TransactionTTL / CodeTTL は 0 なら既定値。上限の検査は Engine の設定検証で行う。
	TransactionTTL time.Duration
	CodeTTL        time.Duration
}

func (s *Service) txnTTL() time.Duration {
	if s.TransactionTTL == 0 {
		return DefaultTransactionTTL
	}
	return s.TransactionTTL
}

func (s *Service) codeTTL() time.Duration {
	if s.CodeTTL == 0 {
		return DefaultCodeTTL
	}
	return s.CodeTTL
}

// Begin は /authorize の要求を検証して Transaction を作る（ADR-0003 §3 (1)(2)）。
//
// browserBinding はブラウザ結合 Cookie の値（平文）。HTTP 層が既存 Cookie を読むか新規発行して渡す。
// 失敗は *Error で返し、Redirectable なら Client へリダイレクトして返す。
func (s *Service) Begin(ctx context.Context, params url.Values, browserBinding string) (*Transaction, error) {
	if browserBinding == "" {
		return nil, errors.New("authorization: browser binding is required")
	}
	req, _, perr := parseRequest(ctx, s.Clients, s.Resources, params)
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

// Complete は Interaction App からの成功結果を記録し、Resume Token の平文を返す（ADR-0003 §3 (5)）。
//
// Outcome の検証: subject 非空、authenticated_at 非ゼロ、granted_scopes が要求 scope の
// 空でない部分集合、max_age 要求時は認証が新しいこと。
func (s *Service) Complete(ctx context.Context, txnID string, out Outcome) (string, error) {
	txn, err := s.pendingTransaction(ctx, txnID)
	if err != nil {
		return "", err
	}
	now := s.Clock.Now()
	if out.Subject == "" {
		return "", invalidOutcome("subject is required")
	}
	if out.AuthenticatedAt.IsZero() {
		return "", invalidOutcome("authenticated_at is required")
	}
	if len(out.GrantedScopes) == 0 {
		return "", invalidOutcome("granted_scopes must not be empty; use Reject to deny")
	}
	granted := slices.Compact(slices.Clone(out.GrantedScopes))
	for _, sc := range granted {
		if !slices.Contains(txn.Request.Scopes, sc) {
			return "", invalidOutcome("granted scope %q was not requested", sc)
		}
	}
	if txn.Request.HasMaxAge && now.Sub(out.AuthenticatedAt) > txn.Request.MaxAge {
		return "", invalidOutcome("authentication is older than max_age; re-authenticate the user")
	}
	out.GrantedScopes = granted
	out.AMR = slices.Clone(out.AMR)

	token, hash, err := s.newResumeToken()
	if err != nil {
		return "", err
	}
	err = s.Store.TransitionTransaction(ctx, txn.ID, StatusPending, StatusCompleted, Patch{Outcome: &out, ResumeTokenHash: hash})
	if err != nil {
		return "", mapTransitionError(err)
	}
	return token, nil
}

// Reject は Interaction App からの失敗結果を記録し、Resume Token の平文を返す。
func (s *Service) Reject(ctx context.Context, txnID string, rej Rejection) (string, error) {
	txn, err := s.pendingTransaction(ctx, txnID)
	if err != nil {
		return "", err
	}
	if !rejectionCodes[rej.Error] {
		return "", invalidOutcome("unsupported rejection error code %q", rej.Error)
	}
	token, hash, err := s.newResumeToken()
	if err != nil {
		return "", err
	}
	err = s.Store.TransitionTransaction(ctx, txn.ID, StatusPending, StatusRejected, Patch{Rejection: &rej, ResumeTokenHash: hash})
	if err != nil {
		return "", mapTransitionError(err)
	}
	return token, nil
}

// pendingTransaction は Complete / Reject の前提（存在・未期限・pending）を確認する。
func (s *Service) pendingTransaction(ctx context.Context, id string) (*Transaction, error) {
	txn, err := s.Store.GetTransaction(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTransactionNotFound
		}
		return nil, err
	}
	if txn.Expired(s.Clock.Now()) {
		return nil, ErrTransactionExpired
	}
	if txn.Status != StatusPending {
		return nil, ErrTransactionNotPending
	}
	return txn, nil
}

func (s *Service) newResumeToken() (token, hash string, err error) {
	token, err = rand.Token(ResumeTokenPrefix)
	if err != nil {
		return "", "", err
	}
	return token, rand.Hash(token), nil
}

func mapTransitionError(err error) error {
	if errors.Is(err, storage.ErrStateConflict) {
		return ErrTransactionNotPending
	}
	if errors.Is(err, storage.ErrNotFound) {
		return ErrTransactionNotFound
	}
	return err
}

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
	txn, err := s.Store.GetTransaction(ctx, txnID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrTransactionNotFound
		}
		return "", err
	}
	now := s.Clock.Now()
	if txn.Expired(now) {
		return "", ErrTransactionExpired
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
		return "", err
	}

	if txn.Status == StatusRejected {
		perr := &Error{Code: txn.Rejection.Error, Description: txn.Rejection.Description, RedirectURI: txn.Request.RedirectURI, State: txn.Request.State}
		return perr.RedirectURL(s.Issuer), nil
	}
	return s.issueCode(ctx, txn, now)
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
