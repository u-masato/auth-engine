package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/u-masato/auth-engine/authorization"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
	"github.com/u-masato/auth-engine/token"
)

// ConsumeAuthorizationCode は 1 文の UPDATE ... RETURNING で原子的に消費する。
// 0 行なら SELECT で「消費済み」と「不明・期限切れ」を区別する。
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash string, now time.Time) (*authorization.AuthorizationCode, error) {
	var (
		code *authorization.AuthorizationCode
		cerr error
	)
	err := s.write(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `UPDATE authorization_codes SET consumed_at = ?
			WHERE hash = ? AND consumed_at IS NULL AND expires_at > ?
			RETURNING `+codeColumns, now.UnixNano(), codeHash, now.UnixNano())
		c, err := scanCode(row)
		if err == nil {
			code = c
			return nil
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		existing, err := scanCode(tx.QueryRowContext(ctx, `SELECT `+codeColumns+` FROM authorization_codes WHERE hash = ?`, codeHash))
		if err != nil {
			return err // ErrNotFound を含む
		}
		if existing.Consumed() {
			code, cerr = existing, storage.ErrCodeAlreadyUsed
			return nil
		}
		return storage.ErrNotFound // 期限切れ
	})
	if err != nil {
		return nil, err
	}
	return code, cerr
}

const familyColumns = `id, grant_id, client_id, subject, scopes, audience, authenticated_at, amr, acr, status, created_at, expires_at, revoked_at`

func scanFamily(row rowScanner) (*token.Family, error) {
	var (
		f                                        token.Family
		scopes, audience, amr                    sql.NullString
		authenticated, created, expires, revoked sql.NullInt64
	)
	err := row.Scan(&f.ID, &f.GrantID, &f.ClientID, &f.Subject, &scopes, &audience, &authenticated, &amr, &f.ACR, &f.Status, &created, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &f.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(audience, &f.Audience); err != nil {
		return nil, err
	}
	if err := fromJSON(amr, &f.AMR); err != nil {
		return nil, err
	}
	f.AuthenticatedAt, f.CreatedAt, f.ExpiresAt, f.RevokedAt = fromNanos(authenticated), fromNanos(created), fromNanos(expires), fromNanos(revoked)
	return &f, nil
}

const accessColumns = `hash, family_id, grant_id, client_id, subject, scopes, audience, status, issued_at, expires_at, revoked_at`
const refreshColumns = `hash, family_id, status, replaced_by_hash, issued_at, expires_at, rotated_at, revoked_at`

func scanAccess(row rowScanner) (*token.AccessToken, error) {
	var (
		t                        token.AccessToken
		scopes, audience         sql.NullString
		issued, expires, revoked sql.NullInt64
	)
	err := row.Scan(&t.Hash, &t.FamilyID, &t.GrantID, &t.ClientID, &t.Subject, &scopes, &audience, &t.Status, &issued, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &t.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(audience, &t.Audience); err != nil {
		return nil, err
	}
	t.IssuedAt, t.ExpiresAt, t.RevokedAt = fromNanos(issued), fromNanos(expires), fromNanos(revoked)
	return &t, nil
}

func scanRefresh(row rowScanner) (*token.RefreshToken, error) {
	var (
		t                                 token.RefreshToken
		issued, expires, rotated, revoked sql.NullInt64
	)
	err := row.Scan(&t.Hash, &t.FamilyID, &t.Status, &t.ReplacedByHash, &issued, &expires, &rotated, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.IssuedAt, t.ExpiresAt, t.RotatedAt, t.RevokedAt = fromNanos(issued), fromNanos(expires), fromNanos(rotated), fromNanos(revoked)
	return &t, nil
}

func insertAccess(ctx context.Context, tx *sql.Tx, t *token.AccessToken) error {
	scopes, err := mustJSON(t.Scopes)
	if err != nil {
		return err
	}
	audience, err := toJSON(t.Audience) // 空なら NULL
	if err != nil {
		return err
	}
	return insertOnce(ctx, tx, `INSERT INTO access_tokens (`+accessColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (hash) DO NOTHING`,
		t.Hash, t.FamilyID, t.GrantID, t.ClientID, t.Subject, scopes, audience, string(t.Status),
		mustNanos(t.IssuedAt), mustNanos(t.ExpiresAt), nanos(t.RevokedAt))
}

func insertRefresh(ctx context.Context, tx *sql.Tx, t *token.RefreshToken) error {
	return insertOnce(ctx, tx, `INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (hash) DO NOTHING`,
		t.Hash, t.FamilyID, string(t.Status), t.ReplacedByHash,
		mustNanos(t.IssuedAt), mustNanos(t.ExpiresAt), nanos(t.RotatedAt), nanos(t.RevokedAt))
}

// IssueTokens は Grant が active であることを同じトランザクション内で確認してから挿入する。
func (s *Store) IssueTokens(ctx context.Context, family *token.Family, access *token.AccessToken, refresh *token.RefreshToken) error {
	scopes, err := mustJSON(family.Scopes)
	if err != nil {
		return err
	}
	audience, err := toJSON(family.Audience) // 空なら NULL
	if err != nil {
		return err
	}
	amr, err := toJSON(family.AMR)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM grants WHERE id = ?`, family.GrantID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && status != string(grant.StatusActive)) {
			return storage.ErrGrantRevoked
		}
		if err != nil {
			return err
		}
		err = insertOnce(ctx, tx, `INSERT INTO token_families (`+familyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO NOTHING`,
			family.ID, family.GrantID, family.ClientID, family.Subject, scopes, audience, nanos(family.AuthenticatedAt), amr, family.ACR,
			string(family.Status), mustNanos(family.CreatedAt), nanos(family.ExpiresAt), nanos(family.RevokedAt))
		if err != nil {
			return err
		}
		if err := insertAccess(ctx, tx, access); err != nil {
			return err
		}
		if refresh != nil {
			return insertRefresh(ctx, tx, refresh)
		}
		return nil
	})
}

// RotateRefreshToken は旧トークンが active のときだけ rotated にし、後継と Access Token を挿入する。
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next *token.RefreshToken, access *token.AccessToken, now time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		old, err := scanRefresh(tx.QueryRowContext(ctx, `SELECT `+refreshColumns+` FROM refresh_tokens WHERE hash = ?`, oldHash))
		if err != nil {
			return err // ErrNotFound を含む
		}
		switch old.Status {
		case token.RefreshRotated:
			return storage.ErrTokenReused
		case token.RefreshRevoked:
			return storage.ErrFamilyRevoked
		}
		if old.Expired(now) {
			return storage.ErrNotFound
		}
		var familyStatus, grantStatus string
		err = tx.QueryRowContext(ctx, `SELECT f.status, g.status FROM token_families f JOIN grants g ON g.id = f.grant_id WHERE f.id = ?`,
			old.FamilyID).Scan(&familyStatus, &grantStatus)
		if err != nil {
			return err
		}
		if familyStatus != string(token.FamilyActive) {
			return storage.ErrFamilyRevoked
		}
		if grantStatus != string(grant.StatusActive) {
			return storage.ErrGrantRevoked
		}
		res, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status = ?, rotated_at = ?, replaced_by_hash = ? WHERE hash = ? AND status = ?`,
			string(token.RefreshRotated), now.UnixNano(), next.Hash, oldHash, string(token.RefreshActive))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return storage.ErrTokenReused
		}
		if err := insertRefresh(ctx, tx, next); err != nil {
			return err
		}
		return insertAccess(ctx, tx, access)
	})
}

func (s *Store) LookupAccessToken(ctx context.Context, hash string) (*token.AccessToken, *grant.Grant, error) {
	t, err := scanAccess(s.db.QueryRowContext(ctx, `SELECT `+accessColumns+` FROM access_tokens WHERE hash = ?`, hash))
	if err != nil {
		return nil, nil, err
	}
	g, err := s.GetGrant(ctx, t.GrantID)
	if err != nil {
		return nil, nil, err
	}
	return t, g, nil
}

func (s *Store) LookupRefreshToken(ctx context.Context, hash string) (*token.RefreshToken, error) {
	return scanRefresh(s.db.QueryRowContext(ctx, `SELECT `+refreshColumns+` FROM refresh_tokens WHERE hash = ?`, hash))
}

func (s *Store) GetTokenFamily(ctx context.Context, id string) (*token.Family, error) {
	return scanFamily(s.db.QueryRowContext(ctx, `SELECT `+familyColumns+` FROM token_families WHERE id = ?`, id))
}

func (s *Store) RevokeTokenFamily(ctx context.Context, familyID string, now time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		ok, err := exists(ctx, tx, `SELECT COUNT(*) FROM token_families WHERE id = ?`, familyID)
		if err != nil {
			return err
		}
		if !ok {
			return storage.ErrNotFound
		}
		return revokeFamiliesWhere(ctx, tx, `id = ?`, familyID, now)
	})
}

// revokeFamiliesWhere は token_families の where 条件に合う Family と、その配下の全トークンを失効させる。
// where は token_families の列だけを参照すること（例: "grant_id = ?"、"id = ?"）。
func revokeFamiliesWhere(ctx context.Context, tx *sql.Tx, where string, arg any, now time.Time) error {
	n := now.UnixNano()
	sub := `SELECT id FROM token_families WHERE ` + where
	if _, err := tx.ExecContext(ctx, `UPDATE access_tokens SET status = ?, revoked_at = ? WHERE status = ? AND family_id IN (`+sub+`)`,
		string(token.AccessRevoked), n, string(token.AccessActive), arg); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET status = ?, revoked_at = ? WHERE status != ? AND family_id IN (`+sub+`)`,
		string(token.RefreshRevoked), n, string(token.RefreshRevoked), arg); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE token_families SET status = ?, revoked_at = ? WHERE status = ? AND `+where,
		string(token.FamilyRevoked), n, string(token.FamilyActive), arg)
	return err
}

func (s *Store) RevokeAccessToken(ctx context.Context, hash string, now time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE access_tokens SET status = ?, revoked_at = ? WHERE hash = ? AND status = ?`,
			string(token.AccessRevoked), now.UnixNano(), hash, string(token.AccessActive))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		ok, err := exists(ctx, tx, `SELECT COUNT(*) FROM access_tokens WHERE hash = ?`, hash)
		if err != nil {
			return err
		}
		if !ok {
			return storage.ErrNotFound
		}
		return nil
	})
}

// Purge は期限切れの行を削除する。消費済み Code も期限が過ぎれば削除する。
func (s *Store) Purge(ctx context.Context, now time.Time) error {
	n := now.UnixNano()
	return s.write(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM transactions WHERE expires_at <= ?`,
			`DELETE FROM authorization_codes WHERE expires_at <= ?`,
			`DELETE FROM access_tokens WHERE expires_at <= ?`,
			`DELETE FROM refresh_tokens WHERE expires_at <= ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, n); err != nil {
				return err
			}
		}
		return nil
	})
}
