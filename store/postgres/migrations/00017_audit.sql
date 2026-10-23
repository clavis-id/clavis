-- +goose Up
-- What happened to accounts, clients and tenants (ADR 0029). user_id and
-- session_id are not references: events outlive the users and sessions
-- they are about. client_id is the client's public identifier, or empty;
-- details is a JSON object of strings.
CREATE TABLE audit_events (
    id          uuid        NOT NULL PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    occurred_at timestamptz NOT NULL,
    type        text        NOT NULL,
    actor       text        NOT NULL,
    user_id     uuid,
    client_id   text        NOT NULL,
    session_id  uuid,
    ip          text        NOT NULL,
    user_agent  text        NOT NULL,
    details     jsonb       NOT NULL
);

CREATE INDEX audit_events_tenant ON audit_events (tenant_id, id);
CREATE INDEX audit_events_user ON audit_events (tenant_id, user_id, id);
CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);

-- +goose Down
DROP TABLE audit_events;
