-- +goose Up
-- List columns hold JSON arrays of strings. Lifetimes are whole seconds, and
-- 0 selects the default. Booleans are 0 or 1.
CREATE TABLE clients (
    id                                      TEXT    NOT NULL PRIMARY KEY,
    tenant_id                               TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id                               TEXT    NOT NULL,
    name                                    TEXT    NOT NULL,
    type                                    TEXT    NOT NULL,
    secret_hash                             BLOB,
    redirect_uris                           TEXT    NOT NULL,
    post_logout_redirect_uris               TEXT    NOT NULL,
    grant_types                             TEXT    NOT NULL,
    scopes                                  TEXT    NOT NULL,
    access_token_lifetime_seconds           INTEGER NOT NULL,
    id_token_lifetime_seconds               INTEGER NOT NULL,
    refresh_token_idle_lifetime_seconds     INTEGER NOT NULL,
    refresh_token_absolute_lifetime_seconds INTEGER NOT NULL,
    skip_consent                            INTEGER NOT NULL,
    pkce_exempt                             INTEGER NOT NULL,
    created_at                              INTEGER NOT NULL,
    updated_at                              INTEGER NOT NULL,
    UNIQUE (tenant_id, client_id)
) STRICT;

-- +goose Down
DROP TABLE clients;
