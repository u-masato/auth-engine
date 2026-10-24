package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/muno/auth-engine/client"
	"github.com/muno/auth-engine/storage"
)

const clientColumns = `id, profile, name, logo_uri, policy_uri, redirect_uris, scopes, resources, secret_hash,
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
	err := row.Scan(&c.ID, &c.Profile, &c.Name, &c.LogoURI, &c.PolicyURI, &redirectURIs, &scopes, &resources, &c.SecretHash,
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
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE id = ?`, c.ID).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return storage.ErrAlreadyExists
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO clients (`+clientColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, string(c.Profile), c.Name, c.LogoURI, c.PolicyURI, redirectURIs, scopes, resources, c.SecretHash,
			int64(c.AccessTokenTTL), c.IDTokenAlg, boolInt(c.AllowInsecureLocalhost), mustNanos(c.CreatedAt))
		return err
	})
}
