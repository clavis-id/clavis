-- +goose Up
-- Lets authorization requests and codes reference a client within its tenant.
CREATE UNIQUE INDEX clients_tenant_id_id ON clients (tenant_id, id);

-- An authorization request waiting for the user to sign in (ADR 0013).
-- scopes is a JSON array.
CREATE TABLE authorization_requests (
    id                    TEXT    NOT NULL PRIMARY KEY,
    tenant_id             TEXT    NOT NULL,
    client_id             TEXT    NOT NULL,
    binding_hash          BLOB    NOT NULL,
    redirect_uri          TEXT    NOT NULL,
    redirect_uri_provided INTEGER NOT NULL,
    scopes                TEXT    NOT NULL,
    state                 TEXT    NOT NULL,
    nonce                 TEXT    NOT NULL,
    code_challenge        TEXT    NOT NULL,
    code_challenge_method TEXT    NOT NULL,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX authorization_requests_client ON authorization_requests (tenant_id, client_id);

-- A browser session. token_hash is the SHA-256 hash of the cookie value;
-- amr is a JSON array.
CREATE TABLE sessions (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    token_hash      BLOB    NOT NULL UNIQUE,
    user_id         TEXT    NOT NULL,
    auth_time       INTEGER NOT NULL,
    amr             TEXT    NOT NULL,
    acr             TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX sessions_user ON sessions (tenant_id, user_id);

-- An authorization code, identified by the SHA-256 hash of its value. scopes
-- and amr are JSON arrays.
CREATE TABLE authorization_codes (
    hash                  BLOB    NOT NULL PRIMARY KEY,
    tenant_id             TEXT    NOT NULL,
    client_id             TEXT    NOT NULL,
    user_id               TEXT    NOT NULL,
    session_id            TEXT    NOT NULL,
    redirect_uri          TEXT    NOT NULL,
    redirect_uri_provided INTEGER NOT NULL,
    scopes                TEXT    NOT NULL,
    nonce                 TEXT    NOT NULL,
    code_challenge        TEXT    NOT NULL,
    code_challenge_method TEXT    NOT NULL,
    auth_time             INTEGER NOT NULL,
    amr                   TEXT    NOT NULL,
    acr                   TEXT    NOT NULL,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX authorization_codes_client ON authorization_codes (tenant_id, client_id);
CREATE INDEX authorization_codes_user ON authorization_codes (tenant_id, user_id);

-- +goose Down
DROP TABLE authorization_codes;
DROP TABLE sessions;
DROP TABLE authorization_requests;
DROP INDEX clients_tenant_id_id;
