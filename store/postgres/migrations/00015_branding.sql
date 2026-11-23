-- +goose Up
-- ui_locales is the request's ui_locales parameter, for the language of the
-- hosted pages (ADR 0025).
ALTER TABLE authorization_requests ADD COLUMN ui_locales text NOT NULL DEFAULT '';

-- How the hosted pages of a tenant look (ADR 0025). logo is NULL when the
-- tenant has no logo.
CREATE TABLE brandings (
    tenant_id  uuid        NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    theme      jsonb       NOT NULL,
    logo       bytea,
    logo_type  text        NOT NULL DEFAULT '',
    logo_hash  text        NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE brandings;
ALTER TABLE authorization_requests DROP COLUMN ui_locales;
