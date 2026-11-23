package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// Logout is a logout request (OpenID Connect RP-Initiated Logout 1.0) after
// validation (ADR 0023).
type Logout struct {
	// Client is the client that the id_token_hint was issued to, or the zero
	// client.
	Client store.Client
	// RedirectURI is where the browser goes after the logout, with State: the
	// post-logout redirect URI of the request, when the request may use it.
	// It is empty otherwise, and the browser stays at Clavis.
	RedirectURI string
	State       string
	// Problem explains, in fixed text, why the request's post-logout
	// redirect cannot be followed. It is empty for a valid request.
	Problem string
	// Confirm is true when the browser has an active session, which the user
	// must agree to end. Account is the email address of its user.
	Confirm bool
	Account string
}

// ResponseURI returns the post-logout redirect URI with the state, or an
// empty string when the browser stays at Clavis.
func (l Logout) ResponseURI() string {
	if l.RedirectURI == "" {
		return ""
	}
	return oauth.LogoutResponseURI(l.RedirectURI, l.State)
}

// StartLogout validates a logout request from a browser whose session
// cookie hashes to sessionHash (OpenID Connect RP-Initiated Logout 1.0,
// section 2). It changes nothing.
//
// The post-logout redirect URI needs an id_token_hint that the tenant issued
// to a client, which may have expired, and must be registered for that
// client exactly (section 3). A request that fails these checks still lets
// the user sign out; Problem says why the browser then stays at Clavis.
func StartLogout(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, params url.Values,
	sessionHash []byte,
) (Logout, error) {
	var l Logout
	r, err := oauth.ParseLogoutRequest(params)
	if err == nil {
		err = l.target(ctx, d, signer, t, r)
	}
	if err != nil {
		if !errors.Is(err, oauth.ErrInvalidLogoutRequest) {
			return Logout{}, err
		}
		l.Problem = strings.TrimPrefix(err.Error(), oauth.ErrInvalidLogoutRequest.Error()+": ")
		l.RedirectURI, l.State = "", ""
	}
	s, ok, err := activeSession(ctx, d, t.ID, sessionHash)
	if err != nil || !ok {
		return l, err
	}
	l.Confirm = true
	switch u, err := d.Store.Users().Get(ctx, t.ID, s.UserID); {
	case err == nil:
		l.Account = u.Email
	case !errors.Is(err, store.ErrNotFound):
		return Logout{}, fmt.Errorf("looking up the user of the session: %w", err)
	}
	return l, nil
}

// target sets the client and the post-logout redirect of l from r. Errors
// wrap oauth.ErrInvalidLogoutRequest unless the store fails.
func (l *Logout) target(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant,
	r oauth.LogoutRequest,
) error {
	invalid := func(problem string) error { return fmt.Errorf("%w: %s", oauth.ErrInvalidLogoutRequest, problem) }
	if r.IDTokenHint == "" {
		// Section 3: without an id_token_hint, the OP must not redirect.
		if r.PostLogoutRedirectURI != "" {
			return invalid("post_logout_redirect_uri needs an id_token_hint")
		}
		return nil
	}
	client, err := logoutHintClient(ctx, d, signer, t, r.IDTokenHint)
	if err != nil {
		return err
	}
	l.Client = client
	// Section 2: client_id must name the client of the hint.
	if r.ClientID != "" && r.ClientID != client.ClientID {
		return invalid("client_id is not the client the id_token_hint was issued to")
	}
	if r.PostLogoutRedirectURI == "" {
		return nil
	}
	// Section 3: the URI must match a registered one exactly. The browser
	// goes to the registered string, never to the request's.
	i := slices.Index(client.PostLogoutRedirectURIs, r.PostLogoutRedirectURI)
	if i < 0 {
		return invalid("post_logout_redirect_uri is not registered for the client")
	}
	l.RedirectURI, l.State = client.PostLogoutRedirectURIs[i], r.State
	return nil
}

// logoutHintClient returns the client that an id_token_hint was issued to.
// The hint must be an ID token of the tenant, which may have expired
// (OpenID Connect RP-Initiated Logout 1.0, section 2).
func logoutHintClient(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, hint string,
) (store.Client, error) {
	invalid := fmt.Errorf("%w: id_token_hint is not an ID token that this provider issued",
		oauth.ErrInvalidLogoutRequest)
	payload, err := signer.Verify(ctx, t.ID, hint, oidc.IDTokenType)
	switch {
	case errors.Is(err, ErrInvalidToken):
		return store.Client{}, invalid
	case err != nil:
		return store.Client{}, fmt.Errorf("verifying the id_token_hint: %w", err)
	}
	var claims oidc.IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != t.Issuer ||
		oauth.ValidateClientID(claims.Audience) != nil {
		return store.Client{}, invalid
	}
	client, err := d.Store.Clients().GetByClientID(ctx, t.ID, claims.Audience)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Client{}, invalid
	case err != nil:
		return store.Client{}, fmt.Errorf("looking up the client of the id_token_hint: %w", err)
	}
	return client, nil
}

// endSession ends the session s of a tenant and its online access (ADR
// 0023): it deletes s and its codes that were not exchanged, and revokes the
// access tokens of its codes that started no refresh token family. It
// returns how many codes it deleted and how many access tokens it revoked.
func endSession(ctx context.Context, d Deps, tenantID uuid.UUID, s store.Session) (codes, tokens int64, err error) {
	// The session goes first, so no new code comes from it. Deleting its
	// pending codes then makes an exchange in progress fail when it redeems
	// the code. An exchange that redeemed its code already recorded its
	// tokens and its family, which the revocation then sees.
	if err := d.Store.Sessions().Delete(ctx, tenantID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, 0, fmt.Errorf("ending the session: %w", err)
	}
	if codes, err = d.Store.AuthorizationCodes().DeleteBySession(ctx, tenantID, s.ID); err != nil {
		return 0, 0, fmt.Errorf("deleting the codes of the session: %w", err)
	}
	if tokens, err = d.Store.AccessTokens().RevokeBySession(ctx, tenantID, s.ID, d.Now()); err != nil {
		return 0, 0, fmt.Errorf("revoking the access tokens of the session: %w", err)
	}
	return codes, tokens, nil
}

// activeSession returns the session of a tenant whose token hashes to
// tokenHash, provided that it has not expired.
func activeSession(ctx context.Context, d Deps, tenantID uuid.UUID, tokenHash []byte) (store.Session, bool, error) {
	if tokenHash == nil {
		return store.Session{}, false, nil
	}
	s, err := d.Store.Sessions().GetByTokenHash(ctx, tenantID, tokenHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Session{}, false, nil
	case err != nil:
		return store.Session{}, false, fmt.Errorf("looking up the session: %w", err)
	}
	now := d.Now()
	return s, now.Before(s.IdleExpiresAt) && now.Before(s.ExpiresAt), nil
}

// CompleteLogout validates a logout request like StartLogout and ends the
// session whose cookie hashes to sessionHash, with the online access issued
// in it (ADR 0023): its codes that were not exchanged, and the access tokens
// of its codes that started no refresh token family. Refresh token families
// are offline access, which outlives the session (ADR 0021).
func CompleteLogout(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, params url.Values,
	sessionHash []byte,
) (Logout, error) {
	l, err := StartLogout(ctx, d, signer, t, params, sessionHash)
	if err != nil || sessionHash == nil {
		return l, err
	}
	s, err := d.Store.Sessions().GetByTokenHash(ctx, t.ID, sessionHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return l, nil
	case err != nil:
		return Logout{}, fmt.Errorf("looking up the session: %w", err)
	}
	codes, tokens, err := endSession(ctx, d, t.ID, s)
	if err != nil {
		return Logout{}, err
	}
	attrs := []slog.Attr{
		slog.String("tenant_id", t.ID.String()),
		slog.String("user_id", s.UserID.String()),
		slog.String("session_id", s.ID.String()),
		slog.Int64("deleted_authorization_codes", codes),
		slog.Int64("revoked_access_tokens", tokens),
	}
	if l.Client.ClientID != "" {
		attrs = append(attrs, slog.String("client_id", l.Client.ClientID))
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed out", attrs...)
	audit(ctx, d, store.AuditEvent{TenantID: t.ID, Type: EventSignedOut, Actor: store.ActorUser,
		UserID: s.UserID, ClientID: l.Client.ClientID, SessionID: s.ID})
	return l, nil
}
