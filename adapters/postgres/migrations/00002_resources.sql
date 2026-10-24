-- +goose Up
-- M3: Resource Indicators（RFC 8707、ADR-0008 §2〜§3）。列の意味は adapters/sqlite/migrations/00003 と同じ。
-- clients.resources は Client が要求できる resource の上限。NULL / 空配列は制限なし。
-- authorization_codes.resource は認可要求の resource をそのまま引き継いだもの。NULL は resource なし。
ALTER TABLE clients ADD COLUMN resources JSONB;
ALTER TABLE authorization_codes ADD COLUMN resource JSONB;

-- +goose Down
ALTER TABLE authorization_codes DROP COLUMN resource;
ALTER TABLE clients DROP COLUMN resources;
