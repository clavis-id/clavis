-- +goose Up
-- When the code was exchanged for tokens; NULL until then.
ALTER TABLE authorization_codes ADD COLUMN redeemed_at timestamptz;

-- An API resource whose scopes clients request (ADR 0014).
CREATE TABLE api_resources (
    id         uuid        NOT NULL PRIMARY KEY,
    tenant_id  uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    identifier text        NOT NULL,
    name       text        NOT NULL,
    scopes     text[]      NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, identifier)
);

-- An issued access token, kept so it can be revoked before it expires. id is
-- the jti claim; user_id is NULL for tokens a client obtained for itself, and
-- code_hash is the hash of the authorization code it was issued for.
CREATE TABLE access_tokens (
    id         text        NOT NULL PRIMARY KEY,
    tenant_id  uuid        NOT NULL,
    client_id  uuid        NOT NULL,
    user_id    uuid,
    code_hash  bytea,
    scopes     text[]      NOT NULL,
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX access_tokens_client ON access_tokens (tenant_id, client_id);
CREATE INDEX access_tokens_user ON access_tokens (tenant_id, user_id);
CREATE INDEX access_tokens_code ON access_tokens (tenant_id, code_hash);
CREATE INDEX access_tokens_expires_at ON access_tokens (expires_at);

-- +goose Down
DROP TABLE access_tokens;
DROP TABLE api_resources;
ALTER TABLE authorization_codes DROP COLUMN redeemed_at;
