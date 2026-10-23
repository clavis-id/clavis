package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
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

// consentScopes returns the scopes that r asks the user to allow for
// client: its scopes, then the scopes that carry the claims it requests
// individually (ADR 0020), without duplicates. offline_access is in the list
// exactly when the client gets a refresh token for r (ADR 0021), so the user
// sees long-term access: an OAuth request gets a refresh token by client
// policy without asking for one, and a client that may not use the refresh
// token grant gets none.
func consentScopes(r store.AuthorizationRequest, client store.Client) []string {
	refresh := issuesRefreshToken(client, r.Scopes)
	scopes := make([]string, 0, len(r.Scopes)+1)
	for _, scope := range r.Scopes {
		if scope != oauth.ScopeOfflineAccess || refresh {
			scopes = append(scopes, scope)
		}
	}
	for _, claim := range slices.Concat(r.UserInfoClaims, r.IDTokenClaims) {
		if scope := oidc.ClaimScope(claim); scope != "" && !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	if refresh && !slices.Contains(scopes, oauth.ScopeOfflineAccess) {
		scopes = append(scopes, oauth.ScopeOfflineAccess)
	}
	return scopes
}

// needsConsent reports whether r needs the consent of the user before client
// gets a code (ADR 0020): r carries prompt=consent, or the client does not
// skip consent and the grant of the user lacks a scope that consentScopes
// lists.
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
	for _, scope := range consentScopes(r, client) {
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
	for _, scope := range consentScopes(p.Request, p.Client) {
		c.Scopes = append(c.Scopes, ConsentScope{Scope: scope, Resource: owners[scope].Name})
	}
	return c, nil
}

// CompleteConsent answers the authorization request of c, which FindConsent
// returned, with the user's decision (ADR 0020). Allowing adds the scopes
// that consentScopes lists to the user's grant for the client and issues a
// code; denying ends the request with access_denied. It returns the
// authorization response. A request answered in the meantime returns
// ErrAuthorizationRequestNotFound.
func CompleteConsent(ctx context.Context, d Deps, t AuthorizationTenant, c PendingConsent, allow bool,
) (AuthorizationResponse, error) {
	r := c.Request
	switch err := d.Store.AuthorizationRequests().Delete(ctx, t.ID, r.ID); {
	case errors.Is(err, store.ErrNotFound):
		return AuthorizationResponse{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return AuthorizationResponse{}, fmt.Errorf("completing the authorization request: %w", err)
	}
	attrs := []slog.Attr{
		slog.String("tenant_id", t.ID.String()),
		slog.String("user_id", c.User.ID.String()),
		slog.String("client_id", c.Client.ClientID),
	}
	event := store.AuditEvent{TenantID: t.ID, Type: EventConsentDenied, Actor: store.ActorUser,
		UserID: c.User.ID, ClientID: c.Client.ClientID, SessionID: c.Session.ID,
		Details: map[string]string{"scopes": strings.Join(consentScopes(r, c.Client), " ")}}
	if !allow {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "user denied a client", attrs...)
		audit(ctx, d, event)
		// RFC 6749, section 4.1.2.1.
		return errorResponse(r.RedirectURI, r.ResponseMode, t.Issuer, r.State, &oauth.Error{
			Code: oauth.ErrorAccessDenied, Description: "the user denied the request"}), nil
	}

	// Two consents of the same user for the same client that complete at
	// the same moment can each read the grant before the other writes it,
	// and the later write then drops the scopes of the earlier one. The
	// next request asks for them again, so the race costs a page, not
	// access; it does not justify a transaction.
	g, err := d.Store.Grants().Get(ctx, t.ID, c.User.ID, c.Client.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return AuthorizationResponse{}, fmt.Errorf("looking up the grant: %w", err)
	}
	now := d.Now()
	scopes := g.Scopes
	for _, scope := range consentScopes(r, c.Client) {
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
		return AuthorizationResponse{}, fmt.Errorf("storing the grant: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user allowed a client", attrs...)
	event.Type = EventConsentAllowed
	audit(ctx, d, event)
	return issueCode(ctx, d, t, r, c.Session)
}
