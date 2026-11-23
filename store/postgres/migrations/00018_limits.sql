-- +goose Up
-- Counters of events per key in a window of time, such as the failed
-- sign-ins for an email address (ADR 0030). key_hash is a hash, never the
-- address itself. A counter whose ends_at has passed counts from zero again.
CREATE TABLE limit_counters (
    tenant_id uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    kind      text        NOT NULL,
    key_hash  bytea       NOT NULL,
    hits      bigint      NOT NULL,
    ends_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, kind, key_hash)
);

CREATE INDEX limit_counters_ends_at ON limit_counters (ends_at);

-- +goose Down
DROP TABLE limit_counters;
