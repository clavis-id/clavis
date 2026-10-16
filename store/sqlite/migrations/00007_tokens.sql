-- +goose Up
-- When the code was exchanged for tokens; NULL until then.
ALTER TABLE authorization_codes ADD COLUMN redeemed_at INTEGER;

-- An API resource whose scopes clients request (ADR 0014). scopes is a JSON
-- array.
CREATE TABLE api_resources (
    id         TEXT    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    identifier TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    scopes     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id, identifier)
) STRICT;

-- An issued access token, kept so it can be revoked before it expires. id is
-- the jti claim; user_id is NULL for tokens a client obtained for itself, and
-- code_hash is the hash of the authorization code it was issued for. scopes is
-- a JSON array.
CREATE TABLE access_tokens (
    id         TEXT    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    user_id    TEXT,
    code_hash  BLOB,
    scopes     TEXT    NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX access_tokens_client ON access_tokens (tenant_id, client_id);
CREATE INDEX access_tokens_user ON access_tokens (tenant_id, user_id);
CREATE INDEX access_tokens_code ON access_tokens (tenant_id, code_hash);
CREATE INDEX access_tokens_expires_at ON access_tokens (expires_at);

-- +goose Down
DROP TABLE access_tokens;
DROP TABLE api_resources;
ALTER TABLE authorization_codes DROP COLUMN redeemed_at;
