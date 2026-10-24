-- +goose Up
-- M3: MCP Client Profile（ADR-0008 §4、§6）。
-- clients.client_uri は CIMD 文書の client_uri（RFC 7591 §2）。Interaction App が同意画面に表示する。登録済み Client では空。
ALTER TABLE clients ADD COLUMN client_uri TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE clients DROP COLUMN client_uri;
