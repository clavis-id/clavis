-- +goose Up
-- login_hint is the email address to suggest on the sign-in form, and
-- hint_subject the user that id_token_hint names, or NULL. The claims columns
-- hold the claim names that the claims parameter asks for.
ALTER TABLE authorization_requests ADD COLUMN login_hint text NOT NULL DEFAULT '';
ALTER TABLE authorization_requests ADD COLUMN hint_subject uuid;
ALTER TABLE authorization_requests ADD COLUMN userinfo_claims text[] NOT NULL DEFAULT '{}';
ALTER TABLE authorization_requests ADD COLUMN id_token_claims text[] NOT NULL DEFAULT '{}';
ALTER TABLE authorization_codes ADD COLUMN userinfo_claims text[] NOT NULL DEFAULT '{}';
ALTER TABLE authorization_codes ADD COLUMN id_token_claims text[] NOT NULL DEFAULT '{}';
ALTER TABLE access_tokens ADD COLUMN userinfo_claims text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE access_tokens DROP COLUMN userinfo_claims;
ALTER TABLE authorization_codes DROP COLUMN id_token_claims;
ALTER TABLE authorization_codes DROP COLUMN userinfo_claims;
ALTER TABLE authorization_requests DROP COLUMN id_token_claims;
ALTER TABLE authorization_requests DROP COLUMN userinfo_claims;
ALTER TABLE authorization_requests DROP COLUMN hint_subject;
ALTER TABLE authorization_requests DROP COLUMN login_hint;
