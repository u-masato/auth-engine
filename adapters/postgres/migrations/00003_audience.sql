-- +goose Up
-- M3: Audience 付き Access Token（RFC 8707 §2.2、ADR-0008 §3）。列の意味は adapters/sqlite/migrations/00004 と同じ。
ALTER TABLE token_families ADD COLUMN audience JSONB;
ALTER TABLE access_tokens ADD COLUMN audience JSONB;

-- +goose Down
ALTER TABLE access_tokens DROP COLUMN audience;
ALTER TABLE token_families DROP COLUMN audience;
