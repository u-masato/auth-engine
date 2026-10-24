-- +goose Up
-- M3: Audience 付き Access Token（RFC 8707 §2.2、ADR-0008 §3）。
-- token_families.audience は認可要求の resource をそのまま引き継いだ上限（JSON array）。
-- access_tokens.audience はそのトークンの Audience で、Family の部分集合（JSON array）。NULL は resource なし。
ALTER TABLE token_families ADD COLUMN audience TEXT;
ALTER TABLE access_tokens ADD COLUMN audience TEXT;

-- +goose Down
ALTER TABLE access_tokens DROP COLUMN audience;
ALTER TABLE token_families DROP COLUMN audience;
