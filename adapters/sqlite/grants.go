package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
)

const grantColumns = `id, client_id, subject, scopes, claims, status, created_at, updated_at, revoked_at`

func scanGrant(row rowScanner) (*grant.Grant, error) {
	var (
		g                         grant.Grant
		scopes, claims            sql.NullString
		created, updated, revoked sql.NullInt64
	)
	err := row.Scan(&g.ID, &g.ClientID, &g.Subject, &scopes, &claims, &g.Status, &created, &updated, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &g.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(claims, &g.Claims); err != nil {
		return nil, err
	}
	g.CreatedAt = fromNanos(created)
	g.UpdatedAt = fromNanos(updated)
	g.RevokedAt = fromNanos(revoked)
	return &g, nil
}

func (s *Store) GetGrant(ctx context.Context, id string) (*grant.Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE id = ?`, id))
}

func (s *Store) FindGrant(ctx context.Context, clientID, subject string) (*grant.Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE client_id = ? AND subject = ?`, clientID, subject))
}

func (s *Store) ListGrantsBySubject(ctx context.Context, subject string) ([]*grant.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE subject = ? ORDER BY created_at, id`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*grant.Grant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertGrant は (client_id, subject) の一意制約を前提に、既存があれば grant.Merge の結果で更新する。
func (s *Store) UpsertGrant(ctx context.Context, candidate *grant.Grant) (*grant.Grant, error) {
	var result *grant.Grant
	err := s.write(ctx, func(tx *sql.Tx) error {
		existing, err := scanGrant(tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE client_id = ? AND subject = ?`,
			candidate.ClientID, candidate.Subject))
		switch {
		case err == nil:
			merged := grant.Merge(existing, candidate)
			scopes, err := mustJSON(merged.Scopes)
			if err != nil {
				return err
			}
			claims, err := toJSON(merged.Claims)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE grants SET scopes = ?, claims = ?, status = ?, updated_at = ?, revoked_at = NULL WHERE id = ?`,
				scopes, claims, string(merged.Status), mustNanos(merged.UpdatedAt), merged.ID)
			if err != nil {
				return err
			}
			result = merged
			return nil
		case errors.Is(err, storage.ErrNotFound):
			scopes, err := mustJSON(candidate.Scopes)
			if err != nil {
				return err
			}
			claims, err := toJSON(candidate.Claims)
			if err != nil {
				return err
			}
			// (client_id, subject) の重複は直前の SELECT で見ているので、ここで衝突しうるのは id だけ。
			err = insertOnce(ctx, tx, `INSERT INTO grants (`+grantColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (id) DO NOTHING`,
				candidate.ID, candidate.ClientID, candidate.Subject, scopes, claims, string(candidate.Status),
				mustNanos(candidate.CreatedAt), mustNanos(candidate.UpdatedAt), nanos(candidate.RevokedAt))
			if err != nil {
				return err
			}
			cp := *candidate
			result = &cp
			return nil
		default:
			return err
		}
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RevokeGrant は Grant と配下の Family・全トークンを 1 トランザクションで失効させる。
func (s *Store) RevokeGrant(ctx context.Context, id string, now time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE grants SET status = ?, revoked_at = ? WHERE id = ? AND status = ?`,
			string(grant.StatusRevoked), now.UnixNano(), id, string(grant.StatusActive))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			ok, err := exists(ctx, tx, `SELECT COUNT(*) FROM grants WHERE id = ?`, id)
			if err != nil {
				return err
			}
			if !ok {
				return storage.ErrNotFound
			}
			return nil // 既に失効済み（冪等）
		}
		return revokeFamiliesWhere(ctx, tx, `grant_id = ?`, id, now)
	})
}
