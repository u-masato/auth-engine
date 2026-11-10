package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/u-masato/auth-engine/client"
	"github.com/u-masato/auth-engine/grant"
	"github.com/u-masato/auth-engine/storage"
)

const clientColumns = `id, profile, name, logo_uri, policy_uri, client_uri, redirect_uris, scopes, resources, secret_hash,
	access_token_ttl, id_token_alg, allow_insecure_localhost, created_at`

func (s *Store) GetClient(ctx context.Context, id string) (*client.Client, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = ?`, id)
	return scanClient(row)
}

func scanClient(row *sql.Row) (*client.Client, error) {
	var (
		c            client.Client
		redirectURIs sql.NullString
		scopes       sql.NullString
		resources    sql.NullString
		ttl          int64
		insecure     int
		createdAt    sql.NullInt64
	)
	err := row.Scan(&c.ID, &c.Profile, &c.Name, &c.LogoURI, &c.PolicyURI, &c.ClientURI, &redirectURIs, &scopes, &resources, &c.SecretHash,
		&ttl, &c.IDTokenAlg, &insecure, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(redirectURIs, &c.RedirectURIs); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &c.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(resources, &c.Resources); err != nil {
		return nil, err
	}
	c.AccessTokenTTL = time.Duration(ttl)
	c.AllowInsecureLocalhost = insecure == 1
	c.CreatedAt = fromNanos(createdAt)
	return &c, nil
}

func (s *Store) CreateClient(ctx context.Context, c *client.Client) error {
	redirectURIs, err := mustJSON(c.RedirectURIs)
	if err != nil {
		return err
	}
	scopes, err := mustJSON(c.Scopes)
	if err != nil {
		return err
	}
	resources, err := toJSON(c.Resources) // 空なら NULL（制限なし）
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		return insertOnce(ctx, tx, `INSERT INTO clients (`+clientColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO NOTHING`,
			c.ID, string(c.Profile), c.Name, c.LogoURI, c.PolicyURI, c.ClientURI, redirectURIs, scopes, resources, c.SecretHash,
			int64(c.AccessTokenTTL), c.IDTokenAlg, boolInt(c.AllowInsecureLocalhost), mustNanos(c.CreatedAt))
	})
}

func (s *Store) UpdateClient(ctx context.Context, c *client.Client) error {
	redirectURIs, err := mustJSON(c.RedirectURIs)
	if err != nil {
		return err
	}
	scopes, err := mustJSON(c.Scopes)
	if err != nil {
		return err
	}
	resources, err := toJSON(c.Resources)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		// Profile の照合を WHERE に含め、照合と更新を 1 文で行う（ADR-0004 §4）。
		res, err := tx.ExecContext(ctx, `UPDATE clients SET name = ?, logo_uri = ?, policy_uri = ?, client_uri = ?, redirect_uris = ?,
			scopes = ?, resources = ?, secret_hash = ?, access_token_ttl = ?, id_token_alg = ?, allow_insecure_localhost = ?
			WHERE id = ? AND profile = ?`,
			c.Name, c.LogoURI, c.PolicyURI, c.ClientURI, redirectURIs, scopes, resources, c.SecretHash,
			int64(c.AccessTokenTTL), c.IDTokenAlg, boolInt(c.AllowInsecureLocalhost), c.ID, string(c.Profile))
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
		ok, err := exists(ctx, tx, `SELECT COUNT(*) FROM clients WHERE id = ?`, c.ID)
		if err != nil {
			return err
		}
		if !ok {
			return storage.ErrNotFound
		}
		return storage.ErrStateConflict // Profile が違う
	})
}

func (s *Store) DeleteClient(ctx context.Context, id string, now time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return storage.ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `UPDATE grants SET status = ?, revoked_at = ? WHERE client_id = ? AND status = ?`,
			string(grant.StatusRevoked), now.UnixNano(), id, string(grant.StatusActive)); err != nil {
			return err
		}
		if err := revokeFamiliesWhere(ctx, tx, `grant_id IN (SELECT id FROM grants WHERE client_id = ?)`, id, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM authorization_codes WHERE client_id = ?`, id)
		return err
	})
}
