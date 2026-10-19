-- +goose Up
-- How the response to the request goes back to the client: query or
-- form_post (OAuth 2.0 Form Post Response Mode).
ALTER TABLE authorization_requests ADD COLUMN response_mode TEXT NOT NULL DEFAULT 'query';

-- +goose Down
ALTER TABLE authorization_requests DROP COLUMN response_mode;
