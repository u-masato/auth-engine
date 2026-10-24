package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/muno/auth-engine/grant"
	"github.com/muno/auth-engine/storage"
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
	g.CreatedAt, g.UpdatedAt, g.RevokedAt = fromNanos(created), fromNanos(updated), fromNanos(revoked)
	return &g, nil
}

func (s *Store) GetGrant(ctx context.Context, id string) (*grant.Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE id = $1`, id))
}

func (s *Store) FindGrant(ctx context.Context, clientID, subject string) (*grant.Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE client_id = $1 AND subject = $2`, clientID, subject))
}

func (s *Store) ListGrantsBySubject(ctx context.Context, subject string) ([]*grant.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE subject = $1 ORDER BY created_at, id`, subject)
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

// UpsertGrant は (client_id, subject) の既存行を FOR UPDATE でロックしてから grant.Merge の結果で
// 更新する。なければ INSERT する。2 つの要求が同時に同じ (client_id, subject) を初めて作ろうとすると
// 片方が unique_violation になるので、その場合はやり直して既存行への更新にする。
func (s *Store) UpsertGrant(ctx context.Context, candidate *grant.Grant) (*grant.Grant, error) {
	for attempt := 0; ; attempt++ {
		result, err := s.upsertGrantOnce(ctx, candidate)
		if err != nil && isUniqueViolation(err) && attempt < 3 {
			continue
		}
		return result, err
	}
}

func (s *Store) upsertGrantOnce(ctx context.Context, candidate *grant.Grant) (*grant.Grant, error) {
	var result *grant.Grant
	err := s.write(ctx, func(tx *sql.Tx) error {
		existing, err := scanGrant(tx.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM grants WHERE client_id = $1 AND subject = $2 FOR UPDATE`,
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
			_, err = tx.ExecContext(ctx, `UPDATE grants SET scopes = $1, claims = $2, status = $3, updated_at = $4, revoked_at = NULL WHERE id = $5`,
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
			// id の重複は ON CONFLICT で検知し ErrAlreadyExists、(client_id, subject) の重複は
			// unique_violation として呼び出し元でやり直す。
			if err := insertOnce(ctx, tx, `INSERT INTO grants (`+grantColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO NOTHING`,
				candidate.ID, candidate.ClientID, candidate.Subject, scopes, claims, string(candidate.Status),
				mustNanos(candidate.CreatedAt), mustNanos(candidate.UpdatedAt), nanos(candidate.RevokedAt)); err != nil {
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

// RevokeGrant は Grant 行を CAS で失効させ、同じトランザクションで配下の Family・全トークンを失効させる。
// Grant 行の更新が行ロックになるので、同時に走る IssueTokens（FOR UPDATE）はこの後に順番が来て
// ErrGrantRevoked になるか、先に挿入を終えていてここで巻き込まれるかのどちらかになる。
func (s *Store) RevokeGrant(ctx context.Context, id string, now time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE grants SET status = $1, revoked_at = $2 WHERE id = $3 AND status = $4`,
			string(grant.StatusRevoked), now.UnixNano(), id, string(grant.StatusActive))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			var exists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM grants WHERE id = $1)`, id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return storage.ErrNotFound
			}
			return nil // 既に失効済み（冪等）
		}
		return revokeFamiliesWhere(ctx, tx, `grant_id = $3`, id, now)
	})
}
