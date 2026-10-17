-- +goose Up
-- force_consent records prompt=consent; session_id is the session of the user
-- who authenticated for the request, NULL until then.
ALTER TABLE authorization_requests ADD COLUMN force_consent boolean NOT NULL DEFAULT false;
ALTER TABLE authorization_requests ADD COLUMN session_id uuid;

-- The scopes a user allowed a client (ADR 0020).
CREATE TABLE grants (
    id         uuid        NOT NULL PRIMARY KEY,
    tenant_id  uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    client_id  uuid        NOT NULL,
    scopes     text[]      NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, user_id, client_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX grants_client ON grants (tenant_id, client_id);

-- +goose Down
DROP TABLE grants;
ALTER TABLE authorization_requests DROP COLUMN session_id;
ALTER TABLE authorization_requests DROP COLUMN force_consent;
