-- +goose Up
-- Let the cleanup of expired records find them without scanning the tables.
CREATE INDEX authorization_requests_expires_at ON authorization_requests (expires_at);
CREATE INDEX sessions_expires_at ON sessions (expires_at);
CREATE INDEX sessions_idle_expires_at ON sessions (idle_expires_at);
CREATE INDEX authorization_codes_expires_at ON authorization_codes (expires_at);

-- +goose Down
DROP INDEX authorization_codes_expires_at;
DROP INDEX sessions_idle_expires_at;
DROP INDEX sessions_expires_at;
DROP INDEX authorization_requests_expires_at;
