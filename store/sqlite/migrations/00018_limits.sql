-- +goose Up
-- Counters of events per key in a window of time, such as the failed
-- sign-ins for an email address (ADR 0030). key_hash is a hash, never the
-- address itself. A counter whose ends_at has passed counts from zero again.
CREATE TABLE limit_counters (
    tenant_id TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind      TEXT    NOT NULL,
    key_hash  BLOB    NOT NULL,
    hits      INTEGER NOT NULL,
    ends_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, kind, key_hash)
) STRICT;

CREATE INDEX limit_counters_ends_at ON limit_counters (ends_at);

-- +goose Down
DROP TABLE limit_counters;
