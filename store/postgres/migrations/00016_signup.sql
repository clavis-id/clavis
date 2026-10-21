-- +goose Up
-- signup_enabled lets people create their own accounts on the tenant's
-- hosted pages (ADR 0026).
ALTER TABLE tenants ADD COLUMN signup_enabled boolean NOT NULL DEFAULT false;

-- A code and a link sent to an email address, with which a user proves to
-- receive its mail (ADR 0026). Only their hashes are stored. verified_at is
-- NULL until the user proves the address; authorization_request_id is empty
-- when the verification belongs to no authorization request.
CREATE TABLE email_verifications (
    id                       text        NOT NULL PRIMARY KEY,
    tenant_id                uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    purpose                  text        NOT NULL,
    email                    text        NOT NULL,
    code_hash                bytea       NOT NULL,
    link_hash                bytea       NOT NULL,
    binding_hash             bytea       NOT NULL,
    authorization_request_id text        NOT NULL,
    attempts                 bigint      NOT NULL,
    verified_at              timestamptz,
    created_at               timestamptz NOT NULL,
    expires_at               timestamptz NOT NULL
);

CREATE INDEX email_verifications_tenant_id ON email_verifications (tenant_id);
CREATE INDEX email_verifications_expires_at ON email_verifications (expires_at);

-- +goose Down
DROP TABLE email_verifications;
ALTER TABLE tenants DROP COLUMN signup_enabled;
