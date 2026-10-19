-- +goose Up
-- Ending a session finds the codes issued in it (ADR 0023).
CREATE INDEX authorization_codes_session ON authorization_codes (tenant_id, session_id);

-- +goose Down
DROP INDEX authorization_codes_session;
