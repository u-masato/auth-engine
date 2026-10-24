package postgres

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
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = $1`, id))
}

func scanClient(row rowScanner) (*client.Client, error) {
	var (
		c            client.Client
		redirectURIs sql.NullString
		scopes       sql.NullString
		resources    sql.NullString
		ttl          int64
		createdAt    sql.NullInt64
	)
	err := row.Scan(&c.ID, &c.Profile, &c.Name, &c.LogoURI, &c.PolicyURI, &redirectURIs, &scopes, &resources, &c.SecretHash,
		&ttl, &c.IDTokenAlg, &c.AllowInsecureLocalhost, &createdAt)
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
	return insertOnce(ctx, s.db, `INSERT INTO clients (`+clientColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (id) DO NOTHING`,
		c.ID, string(c.Profile), c.Name, c.LogoURI, c.PolicyURI, redirectURIs, scopes, resources, c.SecretHash,
		int64(c.AccessTokenTTL), c.IDTokenAlg, c.AllowInsecureLocalhost, mustNanos(c.CreatedAt))
}
