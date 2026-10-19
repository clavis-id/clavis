-- +goose Up
-- The identifiers of the API resources whose server the client is: it may
-- introspect the access tokens issued for them (ADR 0022).
ALTER TABLE clients ADD COLUMN resource_server_for text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE clients DROP COLUMN resource_server_for;
