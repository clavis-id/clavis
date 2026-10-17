-- +goose Up
-- force_consent records prompt=consent; session_id is the session of the user
-- who authenticated for the request, NULL until then.
ALTER TABLE authorization_requests ADD COLUMN force_consent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authorization_requests ADD COLUMN session_id TEXT;

-- The scopes a user allowed a client (ADR 0020). scopes is a JSON array.
CREATE TABLE grants (
    id         TEXT    NOT NULL PRIMARY KEY,
    tenant_id  TEXT    NOT NULL,
    user_id    TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    scopes     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id, user_id, client_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX grants_client ON grants (tenant_id, client_id);

-- +goose Down
DROP TABLE grants;
ALTER TABLE authorization_requests DROP COLUMN session_id;
ALTER TABLE authorization_requests DROP COLUMN force_consent;
