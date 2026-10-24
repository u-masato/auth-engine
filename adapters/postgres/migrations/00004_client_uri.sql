-- +goose Up
-- M3: MCP Client Profile（ADR-0008 §4、§6）。列の意味は adapters/sqlite/migrations/00005 と同じ。
ALTER TABLE clients ADD COLUMN client_uri TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE clients DROP COLUMN client_uri;
