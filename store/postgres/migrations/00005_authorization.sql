-- +goose Up
-- Lets authorization requests and codes reference a client within its tenant.
CREATE UNIQUE INDEX clients_tenant_id_id ON clients (tenant_id, id);

-- An authorization request waiting for the user to sign in (ADR 0013).
CREATE TABLE authorization_requests (
    id                    text        NOT NULL PRIMARY KEY,
    tenant_id             uuid        NOT NULL,
    client_id             uuid        NOT NULL,
    binding_hash          bytea       NOT NULL,
    redirect_uri          text        NOT NULL,
    redirect_uri_provided boolean     NOT NULL,
    scopes                text[]      NOT NULL,
    state                 text        NOT NULL,
    nonce                 text        NOT NULL,
    code_challenge        text        NOT NULL,
    code_challenge_method text        NOT NULL,
    created_at            timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX authorization_requests_client ON authorization_requests (tenant_id, client_id);

-- A browser session. token_hash is the SHA-256 hash of the cookie value.
CREATE TABLE sessions (
    id              uuid        NOT NULL PRIMARY KEY,
    tenant_id       uuid        NOT NULL,
    token_hash      bytea       NOT NULL UNIQUE,
    user_id         uuid        NOT NULL,
    auth_time       timestamptz NOT NULL,
    amr             text[]      NOT NULL,
    acr             text        NOT NULL,
    created_at      timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX sessions_user ON sessions (tenant_id, user_id);

-- An authorization code, identified by the SHA-256 hash of its value.
CREATE TABLE authorization_codes (
    hash                  bytea       NOT NULL PRIMARY KEY,
    tenant_id             uuid        NOT NULL,
    client_id             uuid        NOT NULL,
    user_id               uuid        NOT NULL,
    session_id            uuid        NOT NULL,
    redirect_uri          text        NOT NULL,
    redirect_uri_provided boolean     NOT NULL,
    scopes                text[]      NOT NULL,
    nonce                 text        NOT NULL,
    code_challenge        text        NOT NULL,
    code_challenge_method text        NOT NULL,
    auth_time             timestamptz NOT NULL,
    amr                   text[]      NOT NULL,
    acr                   text        NOT NULL,
    created_at            timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX authorization_codes_client ON authorization_codes (tenant_id, client_id);
CREATE INDEX authorization_codes_user ON authorization_codes (tenant_id, user_id);

-- +goose Down
DROP TABLE authorization_codes;
DROP TABLE sessions;
DROP TABLE authorization_requests;
DROP INDEX clients_tenant_id_id;
