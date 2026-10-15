-- +goose Up
-- profile is a JSON object of standard OpenID Connect claims.
CREATE TABLE users (
    id             TEXT    NOT NULL PRIMARY KEY,
    tenant_id      TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email          TEXT    NOT NULL,
    email_verified INTEGER NOT NULL,
    status         TEXT    NOT NULL,
    profile        TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    UNIQUE (tenant_id, email),
    -- Lets credentials reference a user within its tenant.
    UNIQUE (tenant_id, id)
) STRICT;

-- hash is a PHC string. The foreign key keeps a password within the tenant
-- of its user.
CREATE TABLE passwords (
    user_id   TEXT    NOT NULL PRIMARY KEY,
    tenant_id TEXT    NOT NULL,
    hash      TEXT    NOT NULL,
    set_at    INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
) STRICT;

-- +goose Down
DROP TABLE passwords;
DROP TABLE users;
