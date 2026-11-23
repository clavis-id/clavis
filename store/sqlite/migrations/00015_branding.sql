-- +goose Up
-- ui_locales is the request's ui_locales parameter, for the language of the
-- hosted pages (ADR 0025).
ALTER TABLE authorization_requests ADD COLUMN ui_locales TEXT NOT NULL DEFAULT '';

-- How the hosted pages of a tenant look (ADR 0025). theme is a JSON object;
-- logo is NULL when the tenant has no logo.
CREATE TABLE brandings (
    tenant_id  TEXT    NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    theme      TEXT    NOT NULL,
    logo       BLOB,
    logo_type  TEXT    NOT NULL DEFAULT '',
    logo_hash  TEXT    NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE brandings;
ALTER TABLE authorization_requests DROP COLUMN ui_locales;
