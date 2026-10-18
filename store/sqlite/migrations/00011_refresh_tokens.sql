-- +goose Up
-- The chain of refresh tokens that one authorization grant yields (ADR 0014,
-- ADR 0021). session_id is not a reference, because the family can outlive the
-- session; code_hash is the hash of the authorization code the family was
-- issued for. scopes, amr, userinfo_claims and id_token_claims are JSON
-- arrays.
CREATE TABLE refresh_token_families (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    client_id       TEXT    NOT NULL,
    user_id         TEXT    NOT NULL,
    session_id      TEXT,
    code_hash       BLOB,
    scopes          TEXT    NOT NULL,
    auth_time       INTEGER NOT NULL,
    amr             TEXT    NOT NULL,
    acr             TEXT    NOT NULL,
    userinfo_claims TEXT    NOT NULL,
    id_token_claims TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    revoked_at      INTEGER,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX refresh_token_families_client ON refresh_token_families (tenant_id, client_id);
CREATE INDEX refresh_token_families_user ON refresh_token_families (tenant_id, user_id, client_id);
CREATE INDEX refresh_token_families_code ON refresh_token_families (tenant_id, code_hash);
CREATE INDEX refresh_token_families_expires_at ON refresh_token_families (expires_at);
CREATE INDEX refresh_token_families_idle_expires_at ON refresh_token_families (idle_expires_at);

-- A refresh token of a family, stored as the SHA-256 hash of its value.
-- rotated_at is when it was replaced by its successor; NULL until then.
CREATE TABLE refresh_tokens (
    hash       BLOB    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL,
    family_id  TEXT    NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    rotated_at INTEGER,
    FOREIGN KEY (tenant_id, family_id) REFERENCES refresh_token_families (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX refresh_tokens_family ON refresh_tokens (tenant_id, family_id);
CREATE INDEX refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- +goose Down
DROP TABLE refresh_tokens;
DROP TABLE refresh_token_families;
