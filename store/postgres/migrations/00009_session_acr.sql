-- +goose Up
-- Sessions created before acr values existed (ADR 0019) all come from a
-- password sign-in.
UPDATE sessions SET acr = 'https://clavisid.org/acr/password' WHERE acr = '';

-- +goose Down
-- Nothing to undo: the value describes those sessions correctly.
SELECT 1;
