-- +goose Up
-- profile is a JSON object of standard OpenID Connect claims.
CREATE TABLE users (
    id             uuid        NOT NULL PRIMARY KEY,
    tenant_id      uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email          text        NOT NULL,
    email_verified boolean     NOT NULL,
    status         text        NOT NULL,
    profile        jsonb       NOT NULL,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    UNIQUE (tenant_id, email),
    -- Lets credentials reference a user within its tenant.
    UNIQUE (tenant_id, id)
);

-- hash is a PHC string. The foreign key keeps a password within the tenant
-- of its user.
CREATE TABLE passwords (
    user_id   uuid        NOT NULL PRIMARY KEY,
    tenant_id uuid        NOT NULL,
    hash      text        NOT NULL,
    set_at    timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE passwords;
DROP TABLE users;
