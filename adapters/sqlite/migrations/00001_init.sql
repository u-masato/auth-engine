-- +goose Up
-- 時刻はすべて UTC の Unix ナノ秒（INTEGER）。ゼロ値は NULL。
-- 配列・マップは JSON 文字列（TEXT）。
-- 秘密値（Code、トークン、Resume Token、Client Secret）は SHA-256 の 16 進文字列のみを保存する。

CREATE TABLE clients (
    id                       TEXT PRIMARY KEY,
    profile                  TEXT NOT NULL,
    name                     TEXT NOT NULL,
    logo_uri                 TEXT NOT NULL DEFAULT '',
    policy_uri               TEXT NOT NULL DEFAULT '',
    redirect_uris            TEXT NOT NULL,            -- JSON array
    scopes                   TEXT NOT NULL,            -- JSON array
    secret_hash              TEXT NOT NULL DEFAULT '',
    access_token_ttl         INTEGER NOT NULL DEFAULT 0, -- ナノ秒。0 は既定値
    id_token_alg             TEXT NOT NULL DEFAULT '',
    allow_insecure_localhost INTEGER NOT NULL DEFAULT 0,
    created_at               INTEGER NOT NULL
);

CREATE TABLE transactions (
    id                   TEXT PRIMARY KEY,
    status               TEXT NOT NULL,                -- pending | completed | rejected | consumed
    request              TEXT NOT NULL,                -- JSON (authorization.Request)
    browser_binding_hash TEXT NOT NULL,
    outcome              TEXT,                         -- JSON (authorization.Outcome)
    rejection            TEXT,                         -- JSON (authorization.Rejection)
    resume_token_hash    TEXT NOT NULL DEFAULT '',
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL
);
CREATE INDEX transactions_expires_at ON transactions (expires_at);

CREATE TABLE authorization_codes (
    hash                  TEXT PRIMARY KEY,
    txn_id                TEXT NOT NULL,
    client_id             TEXT NOT NULL,
    grant_id              TEXT NOT NULL,
    family_id             TEXT NOT NULL,
    subject               TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    redirect_uri_explicit INTEGER NOT NULL,
    scopes                TEXT NOT NULL,               -- JSON array
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce                 TEXT NOT NULL DEFAULT '',
    authenticated_at      INTEGER,
    amr                   TEXT,                        -- JSON array
    acr                   TEXT NOT NULL DEFAULT '',
    claims                TEXT,                        -- JSON object
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    consumed_at           INTEGER                      -- NULL なら未消費。再利用検知のため期限まで残す
);
CREATE INDEX authorization_codes_expires_at ON authorization_codes (expires_at);

CREATE TABLE grants (
    id         TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,                          -- JSON array
    claims     TEXT,                                   -- JSON object
    status     TEXT NOT NULL,                          -- active | revoked
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    revoked_at INTEGER,
    UNIQUE (client_id, subject)
);

CREATE TABLE token_families (
    id         TEXT PRIMARY KEY,
    grant_id   TEXT NOT NULL REFERENCES grants (id),
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,                          -- JSON array
    status     TEXT NOT NULL,                          -- active | revoked
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX token_families_grant_id ON token_families (grant_id);

CREATE TABLE access_tokens (
    hash       TEXT PRIMARY KEY,
    family_id  TEXT NOT NULL REFERENCES token_families (id),
    grant_id   TEXT NOT NULL REFERENCES grants (id),
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,                          -- JSON array
    status     TEXT NOT NULL,                          -- active | revoked
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX access_tokens_family_id ON access_tokens (family_id);
CREATE INDEX access_tokens_grant_id ON access_tokens (grant_id);
CREATE INDEX access_tokens_expires_at ON access_tokens (expires_at);

CREATE TABLE refresh_tokens (
    hash             TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL REFERENCES token_families (id),
    status           TEXT NOT NULL,                    -- active | rotated | revoked
    replaced_by_hash TEXT NOT NULL DEFAULT '',
    issued_at        INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    rotated_at       INTEGER,
    revoked_at       INTEGER
);
CREATE INDEX refresh_tokens_family_id ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- +goose Down
DROP TABLE refresh_tokens;
DROP TABLE access_tokens;
DROP TABLE token_families;
DROP TABLE grants;
DROP TABLE authorization_codes;
DROP TABLE transactions;
DROP TABLE clients;
