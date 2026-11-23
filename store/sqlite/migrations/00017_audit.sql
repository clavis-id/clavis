-- +goose Up
-- What happened to accounts, clients and tenants (ADR 0029). user_id and
-- session_id are not references: events outlive the users and sessions
-- they are about. client_id is the client's public identifier, or empty;
-- details is a JSON object of strings.
CREATE TABLE audit_events (
    id          TEXT    NOT NULL PRIMARY KEY,
    tenant_id   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    occurred_at INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    user_id     TEXT,
    client_id   TEXT    NOT NULL,
    session_id  TEXT,
    ip          TEXT    NOT NULL,
    user_agent  TEXT    NOT NULL,
    details     TEXT    NOT NULL
) STRICT;

CREATE INDEX audit_events_tenant ON audit_events (tenant_id, id);
CREATE INDEX audit_events_user ON audit_events (tenant_id, user_id, id);
CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);

-- +goose Down
DROP TABLE audit_events;
