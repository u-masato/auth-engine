-- +goose Up
-- M2: Refresh 時の ID Token に元の認証情報（auth_time / amr / acr）を載せるため、
-- Token Family に認証情報の写しを持つ（OIDC Core §12.2）。
ALTER TABLE token_families ADD COLUMN authenticated_at INTEGER;
ALTER TABLE token_families ADD COLUMN amr TEXT;                  -- JSON array
ALTER TABLE token_families ADD COLUMN acr TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE token_families DROP COLUMN acr;
ALTER TABLE token_families DROP COLUMN amr;
ALTER TABLE token_families DROP COLUMN authenticated_at;
