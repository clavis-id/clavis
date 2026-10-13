-- +goose Up
CREATE TABLE signing_keys (
    id                TEXT    NOT NULL PRIMARY KEY,
    tenant_id         TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    algorithm         TEXT    NOT NULL,
    generation        INTEGER NOT NULL,
    key_id            TEXT    NOT NULL,
    public_key        BLOB    NOT NULL,
    private_key       BLOB    NOT NULL,
    encryption_key_id TEXT    NOT NULL,
    activates_at      INTEGER NOT NULL,
    retires_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    UNIQUE (tenant_id, algorithm, generation),
    UNIQUE (tenant_id, key_id)
) STRICT;

CREATE INDEX signing_keys_expires_at ON signing_keys (expires_at);

-- +goose Down
DROP TABLE signing_keys;
