-- +goose Up
-- Lifetimes are whole seconds, and 0 selects the default.
CREATE TABLE clients (
    id                                      uuid        NOT NULL PRIMARY KEY,
    tenant_id                               uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id                               text        NOT NULL,
    name                                    text        NOT NULL,
    type                                    text        NOT NULL,
    secret_hash                             bytea,
    redirect_uris                           text[]      NOT NULL,
    post_logout_redirect_uris               text[]      NOT NULL,
    grant_types                             text[]      NOT NULL,
    scopes                                  text[]      NOT NULL,
    access_token_lifetime_seconds           bigint      NOT NULL,
    id_token_lifetime_seconds               bigint      NOT NULL,
    refresh_token_idle_lifetime_seconds     bigint      NOT NULL,
    refresh_token_absolute_lifetime_seconds bigint      NOT NULL,
    skip_consent                            boolean     NOT NULL,
    pkce_exempt                             boolean     NOT NULL,
    created_at                              timestamptz NOT NULL,
    updated_at                              timestamptz NOT NULL,
    UNIQUE (tenant_id, client_id)
);

-- +goose Down
DROP TABLE clients;
