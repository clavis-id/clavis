-- +goose Up
CREATE TABLE signing_keys (
    id                uuid        NOT NULL PRIMARY KEY,
    tenant_id         uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    algorithm         text        NOT NULL,
    generation        bigint      NOT NULL,
    key_id            text        NOT NULL,
    public_key        bytea       NOT NULL,
    private_key       bytea       NOT NULL,
    encryption_key_id text        NOT NULL,
    activates_at      timestamptz NOT NULL,
    retires_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    UNIQUE (tenant_id, algorithm, generation),
    UNIQUE (tenant_id, key_id)
);

CREATE INDEX signing_keys_expires_at ON signing_keys (expires_at);

-- +goose Down
DROP TABLE signing_keys;
