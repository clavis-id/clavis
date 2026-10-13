-- +goose Up
-- IDs are canonical UUID strings, which sort in the same order as their
-- bytes. Times are Unix microseconds in UTC.
CREATE TABLE tenants (
    id         TEXT    NOT NULL PRIMARY KEY,
    slug       TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE tenants;
