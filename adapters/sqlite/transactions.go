package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/storage"
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
	return s.write(ctx, func(tx *sql.Tx) error {
		return insertOnce(ctx, tx, `INSERT INTO transactions
			(id, status, request, browser_binding_hash, outcome, rejection, resume_token_hash, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO NOTHING`,
			txn.ID, string(txn.Status), request, txn.BrowserBindingHash, outcome, rejection, txn.ResumeTokenHash,
			mustNanos(txn.CreatedAt), mustNanos(txn.ExpiresAt))
	})
}

func (s *Store) GetTransaction(ctx context.Context, id string) (*authorization.Transaction, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, status, request, browser_binding_hash, outcome, rejection,
		resume_token_hash, created_at, expires_at FROM transactions WHERE id = ?`, id)
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
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE transactions SET
				status = ?,
				outcome = COALESCE(?, outcome),
				rejection = COALESCE(?, rejection),
				resume_token_hash = CASE WHEN ? = '' THEN resume_token_hash ELSE ? END
			WHERE id = ? AND status = ?`,
			string(to), outcome, rejection, patch.ResumeTokenHash, patch.ResumeTokenHash, id, string(from))
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
		ok, err := exists(ctx, tx, `SELECT COUNT(*) FROM transactions WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if !ok {
			return storage.ErrNotFound
		}
		return storage.ErrStateConflict
	})
}

const codeColumns = `hash, txn_id, client_id, grant_id, family_id, subject, redirect_uri, redirect_uri_explicit, scopes, resource,
	code_challenge, code_challenge_method, nonce, authenticated_at, amr, acr, claims, created_at, expires_at, consumed_at`

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *authorization.AuthorizationCode) error {
	scopes, err := mustJSON(code.Scopes)
	if err != nil {
		return err
	}
	res, err := toJSON(code.Resource) // 空なら NULL
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
	return s.write(ctx, func(tx *sql.Tx) error {
		return insertOnce(ctx, tx, `INSERT INTO authorization_codes (`+codeColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (hash) DO NOTHING`,
			code.Hash, code.TxnID, code.ClientID, code.GrantID, code.FamilyID, code.Subject, code.RedirectURI,
			boolInt(code.RedirectURIExplicit), scopes, res, code.CodeChallenge, code.CodeChallengeMethod, code.Nonce,
			nanos(code.AuthenticatedAt), amr, code.ACR, claims, mustNanos(code.CreatedAt), mustNanos(code.ExpiresAt), nanos(code.ConsumedAt))
	})
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCode(row rowScanner) (*authorization.AuthorizationCode, error) {
	var (
		c                        authorization.AuthorizationCode
		explicit                 int
		scopes, res, amr, claims sql.NullString
		authAt, created, expires sql.NullInt64
		consumed                 sql.NullInt64
	)
	err := row.Scan(&c.Hash, &c.TxnID, &c.ClientID, &c.GrantID, &c.FamilyID, &c.Subject, &c.RedirectURI, &explicit, &scopes, &res,
		&c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &authAt, &amr, &c.ACR, &claims, &created, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.RedirectURIExplicit = explicit == 1
	if err := fromJSON(scopes, &c.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(res, &c.Resource); err != nil {
		return nil, err
	}
	if err := fromJSON(amr, &c.AMR); err != nil {
		return nil, err
	}
	if err := fromJSON(claims, &c.Claims); err != nil {
		return nil, err
	}
	c.AuthenticatedAt = fromNanos(authAt)
	c.CreatedAt = fromNanos(created)
	c.ExpiresAt = fromNanos(expires)
	c.ConsumedAt = fromNanos(consumed)
	return &c, nil
}
