package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/muno/auth-engine/authorization"
	"github.com/muno/auth-engine/storage"
)

func (s *Store) CreateTransaction(ctx context.Context, txn *authorization.Transaction) error {
	request, err := mustJSON(txn.Request)
	if err != nil {
		return err
	}
	outcome, err := toJSON(txn.Outcome)
	if err != nil {
		return err
	}
	rejection, err := toJSON(txn.Rejection)
	if err != nil {
		return err
	}
	return insertOnce(ctx, s.db, `INSERT INTO transactions
		(id, status, request, browser_binding_hash, outcome, rejection, resume_token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO NOTHING`,
		txn.ID, string(txn.Status), request, txn.BrowserBindingHash, outcome, rejection, txn.ResumeTokenHash,
		mustNanos(txn.CreatedAt), mustNanos(txn.ExpiresAt))
}

func (s *Store) GetTransaction(ctx context.Context, id string) (*authorization.Transaction, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, status, request, browser_binding_hash, outcome, rejection,
		resume_token_hash, created_at, expires_at FROM transactions WHERE id = $1`, id)
	var (
		t                  authorization.Transaction
		request            sql.NullString
		outcome, rejection sql.NullString
		createdAt, expires sql.NullInt64
	)
	err := row.Scan(&t.ID, &t.Status, &request, &t.BrowserBindingHash, &outcome, &rejection, &t.ResumeTokenHash, &createdAt, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(request, &t.Request); err != nil {
		return nil, err
	}
	if outcome.Valid {
		t.Outcome = &authorization.Outcome{}
		if err := fromJSON(outcome, t.Outcome); err != nil {
			return nil, err
		}
	}
	if rejection.Valid {
		t.Rejection = &authorization.Rejection{}
		if err := fromJSON(rejection, t.Rejection); err != nil {
			return nil, err
		}
	}
	t.CreatedAt = fromNanos(createdAt)
	t.ExpiresAt = fromNanos(expires)
	return &t, nil
}

// TransitionTransaction は CAS。UPDATE の WHERE に from を含め、更新行数で成否を判定する。
func (s *Store) TransitionTransaction(ctx context.Context, id string, from, to authorization.Status, patch authorization.Patch) error {
	outcome, err := toJSON(patch.Outcome)
	if err != nil {
		return err
	}
	rejection, err := toJSON(patch.Rejection)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE transactions SET
			status = $1,
			outcome = COALESCE($2::jsonb, outcome),
			rejection = COALESCE($3::jsonb, rejection),
			resume_token_hash = CASE WHEN $4 = '' THEN resume_token_hash ELSE $4 END
		WHERE id = $5 AND status = $6`,
		string(to), outcome, rejection, patch.ResumeTokenHash, id, string(from))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM transactions WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return storage.ErrNotFound
	}
	return storage.ErrStateConflict
}

const codeColumns = `hash, txn_id, client_id, grant_id, family_id, subject, redirect_uri, redirect_uri_explicit, scopes,
	code_challenge, code_challenge_method, nonce, authenticated_at, amr, acr, claims, created_at, expires_at, consumed_at`

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *authorization.AuthorizationCode) error {
	scopes, err := mustJSON(code.Scopes)
	if err != nil {
		return err
	}
	amr, err := toJSON(code.AMR)
	if err != nil {
		return err
	}
	claims, err := toJSON(code.Claims)
	if err != nil {
		return err
	}
	return insertOnce(ctx, s.db, `INSERT INTO authorization_codes (`+codeColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) ON CONFLICT (hash) DO NOTHING`,
		code.Hash, code.TxnID, code.ClientID, code.GrantID, code.FamilyID, code.Subject, code.RedirectURI,
		code.RedirectURIExplicit, scopes, code.CodeChallenge, code.CodeChallengeMethod, code.Nonce,
		nanos(code.AuthenticatedAt), amr, code.ACR, claims, mustNanos(code.CreatedAt), mustNanos(code.ExpiresAt), nanos(code.ConsumedAt))
}

func scanCode(row rowScanner) (*authorization.AuthorizationCode, error) {
	var (
		c                                         authorization.AuthorizationCode
		scopes, amr, claims                       sql.NullString
		authenticated, created, expires, consumed sql.NullInt64
	)
	err := row.Scan(&c.Hash, &c.TxnID, &c.ClientID, &c.GrantID, &c.FamilyID, &c.Subject, &c.RedirectURI, &c.RedirectURIExplicit,
		&scopes, &c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &authenticated, &amr, &c.ACR, &claims, &created, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		src sql.NullString
		dst any
	}{{scopes, &c.Scopes}, {amr, &c.AMR}, {claims, &c.Claims}} {
		if err := fromJSON(pair.src, pair.dst); err != nil {
			return nil, err
		}
	}
	c.AuthenticatedAt, c.CreatedAt, c.ExpiresAt, c.ConsumedAt = fromNanos(authenticated), fromNanos(created), fromNanos(expires), fromNanos(consumed)
	return &c, nil
}
