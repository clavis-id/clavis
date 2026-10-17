package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// ConsentScope is a scope that the consent page asks the user to allow.
type ConsentScope struct {
	Scope string
	// Resource is the name of the API resource that defines the scope, or
	// empty for an OpenID Connect scope.
	Resource string
}

// PendingConsent is an authorization request that waits for the consent of
// the user who authenticated for it, with what the consent page shows.
type PendingConsent struct {
	PendingAuthorization
	Session store.Session
	User    store.User
	// Scopes lists what the client asks the user to allow, in the order of
	// the request.
	Scopes []ConsentScope
}

// consentScopes returns the scopes that r asks the user to allow: its
// scopes, then the scopes that carry the claims it requests individually
// (ADR 0020), without duplicates.
func consentScopes(r store.AuthorizationRequest) []string {
	scopes := slices.Clone(r.Scopes)
	for _, claim := range slices.Concat(r.UserInfoClaims, r.IDTokenClaims) {
		if scope := oidc.ClaimScope(claim); scope != "" && !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// needsConsent reports whether r needs the consent of the user before client
// gets a code (ADR 0020): r carries prompt=consent, or the client does not
// skip consent and r asks for a scope that the user's grant lacks.
func needsConsent(ctx context.Context, d Deps, client store.Client, userID uuid.UUID, r store.AuthorizationRequest,
) (bool, error) {
	switch {
	case r.ForceConsent:
		return true, nil
	case client.SkipConsent:
		return false, nil
	}
	g, err := d.Store.Grants().Get(ctx, client.TenantID, userID, client.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, fmt.Errorf("looking up the grant: %w", err)
	}
	for _, scope := range consentScopes(r) {
		if !slices.Contains(g.Scopes, scope) {
			return true, nil
		}
	}
	return false, nil
}

// FindConsent returns the authorization request with the given ID when it
// waits for consent. The request must belong to the browser whose binding
// cookie hashes to bindingHash, the session that authenticated it must be
// the browser's session, whose cookie hashes to sessionHash, and must not
// have expired, and its user must still be active. Every failure other
// than a store error returns ErrAuthorizationRequestNotFound.
func FindConsent(ctx context.Context, d Deps, tenantID uuid.UUID, id string, bindingHash, sessionHash []byte,
) (PendingConsent, error) {
	p, err := FindAuthorizationRequest(ctx, d, tenantID, id, bindingHash)
	if err != nil {
		return PendingConsent{}, err
	}
	if p.Request.SessionID == uuid.Nil() || sessionHash == nil {
		return PendingConsent{}, ErrAuthorizationRequestNotFound
	}
	s, err := d.Store.Sessions().GetByTokenHash(ctx, tenantID, sessionHash)
	now := d.Now()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return PendingConsent{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return PendingConsent{}, fmt.Errorf("looking up the session: %w", err)
	case s.ID != p.Request.SessionID, !now.Before(s.IdleExpiresAt), !now.Before(s.ExpiresAt):
		return PendingConsent{}, ErrAuthorizationRequestNotFound
	}
	u, err := d.Store.Users().Get(ctx, tenantID, s.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && u.Status != store.UserActive:
		return PendingConsent{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return PendingConsent{}, fmt.Errorf("looking up the user: %w", err)
	}
	owners, err := scopeOwners(ctx, d, tenantID)
	if err != nil {
		return PendingConsent{}, err
	}
	c := PendingConsent{PendingAuthorization: p, Session: s, User: u}
	for _, scope := range consentScopes(p.Request) {
		c.Scopes = append(c.Scopes, ConsentScope{Scope: scope, Resource: owners[scope].Name})
	}
	return c, nil
}

// CompleteConsent answers the authorization request of c, which FindConsent
// returned, with the user's decision (ADR 0020). Allowing adds the scopes of
// the request to the user's grant for the client and issues a code;
// denying ends the request with access_denied. It returns the authorization
// response. A request answered in the meantime returns
// ErrAuthorizationRequestNotFound.
func CompleteConsent(ctx context.Context, d Deps, t AuthorizationTenant, c PendingConsent, allow bool) (string, error) {
	r := c.Request
	switch err := d.Store.AuthorizationRequests().Delete(ctx, t.ID, r.ID); {
	case errors.Is(err, store.ErrNotFound):
		return "", ErrAuthorizationRequestNotFound
	case err != nil:
		return "", fmt.Errorf("completing the authorization request: %w", err)
	}
	attrs := []slog.Attr{
		slog.String("tenant_id", t.ID.String()),
		slog.String("user_id", c.User.ID.String()),
		slog.String("client_id", c.Client.ClientID),
	}
	if !allow {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "user denied a client", attrs...)
		// RFC 6749, section 4.1.2.1.
		return errorResponseURI(r.RedirectURI, t.Issuer, r.State, &oauth.Error{Code: oauth.ErrorAccessDenied,
			Description: "the user denied the request"}), nil
	}

	g, err := d.Store.Grants().Get(ctx, t.ID, c.User.ID, c.Client.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("looking up the grant: %w", err)
	}
	now := d.Now()
	scopes := g.Scopes
	for _, scope := range consentScopes(r) {
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	// Put keeps the ID and creation time of an existing grant.
	if err := d.Store.Grants().Put(ctx, store.Grant{
		ID:        d.NewID(),
		TenantID:  t.ID,
		UserID:    c.User.ID,
		ClientID:  c.Client.ID,
		Scopes:    scopes,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		return "", fmt.Errorf("storing the grant: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user allowed a client", attrs...)
	return issueCode(ctx, d, t, r, c.Session)
}
