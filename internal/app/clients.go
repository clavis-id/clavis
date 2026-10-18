package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// Limits on the lists of a client.
const (
	MaxRedirectURIs = 100
	MaxScopes       = 100
)

// Bounds of the token lifetimes a client can override. ADR 0014 sets the
// defaults: 10 minutes for access and ID tokens, 7 days of inactivity and 30
// days in total for refresh tokens.
const (
	minTokenLifetime        = time.Minute
	maxTokenLifetime        = 24 * time.Hour
	minRefreshTokenLifetime = 5 * time.Minute
	maxRefreshTokenLifetime = 365 * 24 * time.Hour
)

// Errors returned by the client use cases. The names of the first two follow
// the error codes of RFC 7591, section 3.2.2.
var (
	ErrInvalidClientMetadata = errors.New("invalid client metadata")
	ErrInvalidRedirectURI    = oauth.ErrInvalidRedirectURI
	ErrClientExists          = errors.New("client already exists")
	ErrClientNotFound        = errors.New("client not found")
	ErrPublicClient          = errors.New("public clients have no secret")
)

// ClientSpec describes a client to register.
type ClientSpec struct {
	// ClientID is the client identifier. When empty, Clavis generates one.
	ClientID string
	// Name is the display name. When empty, it defaults to the client ID.
	Name string
	Type store.ClientType
	// RedirectURIs is required with the authorization code grant and not
	// allowed without it, like PostLogoutRedirectURIs.
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// GrantTypes defaults to the authorization code and refresh token
	// grants.
	GrantTypes []string
	// Scopes defaults to "openid", "profile" and "email" for clients that
	// sign users in, plus "offline_access" when they may use refresh tokens.
	Scopes      []string
	Lifetimes   store.TokenLifetimes
	SkipConsent bool
	// PKCEExempt turns off PKCE for a confidential client (ADR 0018).
	PKCEExempt bool
}

// CreateClient registers a client with a tenant. Clavis generates the secret
// of a confidential client and returns it only here; the store keeps its hash
// (ADR 0014).
func CreateClient(ctx context.Context, d Deps, tenantID uuid.UUID, spec ClientSpec) (store.Client, string, error) {
	c, err := spec.client()
	if err != nil {
		return store.Client{}, "", err
	}
	var secret string
	if c.Type == store.ClientConfidential {
		secret, c.SecretHash = oauth.NewClientSecret()
	}
	now := d.Now()
	c.ID, c.TenantID, c.CreatedAt, c.UpdatedAt = d.NewID(), tenantID, now, now

	switch err := d.Store.Clients().Create(ctx, c); {
	case errors.Is(err, store.ErrConflict):
		return store.Client{}, "", fmt.Errorf("%w: %q", ErrClientExists, c.ClientID)
	case errors.Is(err, store.ErrNotFound):
		return store.Client{}, "", ErrTenantNotFound
	case err != nil:
		return store.Client{}, "", fmt.Errorf("creating client %q: %w", c.ClientID, err)
	}
	attrs := []slog.Attr{
		slog.String("tenant_id", tenantID.String()),
		slog.String("client_id", c.ClientID),
		slog.String("type", string(c.Type)),
	}
	if c.PKCEExempt {
		// ADR 0018: weakening the default is visible.
		d.Logger.LogAttrs(ctx, slog.LevelWarn, "created client that is exempt from PKCE", attrs...)
	} else {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "created client", attrs...)
	}
	return c, secret, nil
}

// client validates the specification and returns the client it describes,
// with defaults applied.
func (spec ClientSpec) client() (store.Client, error) {
	c := store.Client{
		ClientID:               spec.ClientID,
		Name:                   spec.Name,
		Type:                   spec.Type,
		RedirectURIs:           dedupe(spec.RedirectURIs),
		PostLogoutRedirectURIs: dedupe(spec.PostLogoutRedirectURIs),
		GrantTypes:             dedupe(spec.GrantTypes),
		Scopes:                 dedupe(spec.Scopes),
		Lifetimes:              spec.Lifetimes,
		SkipConsent:            spec.SkipConsent,
		PKCEExempt:             spec.PKCEExempt,
	}
	if c.ClientID == "" {
		c.ClientID = oauth.NewClientID()
	} else if err := oauth.ValidateClientID(c.ClientID); err != nil {
		return store.Client{}, fmt.Errorf("%w: %w", ErrInvalidClientMetadata, err)
	}
	if c.Name == "" {
		c.Name = c.ClientID
	}
	if err := validateDisplayName(c.Name); err != nil {
		return store.Client{}, fmt.Errorf("%w: %w", ErrInvalidClientMetadata, err)
	}
	if c.Type != store.ClientConfidential && c.Type != store.ClientPublic {
		return store.Client{}, fmt.Errorf("%w: type must be %q or %q",
			ErrInvalidClientMetadata, store.ClientConfidential, store.ClientPublic)
	}

	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []string{oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken}
	}
	if err := validateGrantTypes(c.Type, c.GrantTypes); err != nil {
		return store.Client{}, err
	}
	signsIn := slices.Contains(c.GrantTypes, oauth.GrantTypeAuthorizationCode)

	if err := validateRedirectURIs("redirect_uris", c.RedirectURIs, signsIn); err != nil {
		return store.Client{}, err
	}
	if err := validateRedirectURIs("post_logout_redirect_uris", c.PostLogoutRedirectURIs, signsIn); err != nil {
		return store.Client{}, err
	}
	if signsIn && len(c.RedirectURIs) == 0 {
		return store.Client{}, fmt.Errorf("%w: the authorization code grant needs at least one redirect URI",
			ErrInvalidRedirectURI)
	}

	if len(c.Scopes) == 0 && signsIn {
		c.Scopes = []string{oauth.ScopeOpenID, oauth.ScopeProfile, oauth.ScopeEmail}
		if slices.Contains(c.GrantTypes, oauth.GrantTypeRefreshToken) {
			c.Scopes = append(c.Scopes, oauth.ScopeOfflineAccess)
		}
	}
	if len(c.Scopes) > MaxScopes {
		return store.Client{}, fmt.Errorf("%w: a client can have at most %d scopes", ErrInvalidClientMetadata, MaxScopes)
	}
	for _, s := range c.Scopes {
		if err := oauth.ValidateScope(s); err != nil {
			return store.Client{}, fmt.Errorf("%w: %w", ErrInvalidClientMetadata, err)
		}
	}

	if err := validateLifetimes(c.Lifetimes); err != nil {
		return store.Client{}, err
	}
	if c.PKCEExempt {
		switch {
		case c.Type == store.ClientPublic:
			return store.Client{}, fmt.Errorf("%w: public clients always require PKCE", ErrInvalidClientMetadata)
		case !signsIn:
			return store.Client{}, fmt.Errorf("%w: the PKCE exemption applies only to the authorization "+
				"code grant", ErrInvalidClientMetadata)
		}
	}
	return c, nil
}

func validateGrantTypes(typ store.ClientType, grantTypes []string) error {
	for _, g := range grantTypes {
		switch g {
		case oauth.GrantTypeAuthorizationCode:
		case oauth.GrantTypeRefreshToken:
			if !slices.Contains(grantTypes, oauth.GrantTypeAuthorizationCode) {
				return fmt.Errorf("%w: the refresh token grant needs the authorization code grant",
					ErrInvalidClientMetadata)
			}
		case oauth.GrantTypeClientCredentials:
			// RFC 6749, section 4.4.
			if typ == store.ClientPublic {
				return fmt.Errorf("%w: the client credentials grant is only for confidential clients",
					ErrInvalidClientMetadata)
			}
		default:
			return fmt.Errorf("%w: unsupported grant type %q; use %s, %s or %s", ErrInvalidClientMetadata, g,
				oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken, oauth.GrantTypeClientCredentials)
		}
	}
	return nil
}

// validateRedirectURIs checks a list of redirect URIs. Only clients that sign
// users in with the authorization code grant redirect the browser.
func validateRedirectURIs(field string, uris []string, signsIn bool) error {
	if len(uris) == 0 {
		return nil
	}
	if !signsIn {
		return fmt.Errorf("%w: %s needs the authorization code grant", ErrInvalidRedirectURI, field)
	}
	if len(uris) > MaxRedirectURIs {
		return fmt.Errorf("%w: %s can have at most %d entries", ErrInvalidRedirectURI, field, MaxRedirectURIs)
	}
	for _, u := range uris {
		if err := oauth.ValidateRedirectURI(u); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	return nil
}

func validateLifetimes(l store.TokenLifetimes) error {
	const tokenBounds, refreshBounds = "1 minute and 24 hours", "5 minutes and 365 days"
	for _, b := range []struct {
		name     string
		value    time.Duration
		min, max time.Duration
		bounds   string
	}{
		{"access token lifetime", l.AccessToken, minTokenLifetime, maxTokenLifetime, tokenBounds},
		{"ID token lifetime", l.IDToken, minTokenLifetime, maxTokenLifetime, tokenBounds},
		{"refresh token idle lifetime", l.RefreshTokenIdle, minRefreshTokenLifetime, maxRefreshTokenLifetime, refreshBounds},
		{"refresh token absolute lifetime", l.RefreshTokenAbsolute, minRefreshTokenLifetime, maxRefreshTokenLifetime, refreshBounds},
	} {
		switch {
		case b.value == 0:
		case b.value < b.min || b.value > b.max:
			return fmt.Errorf("%w: %s must be between %s, or 0 for the default",
				ErrInvalidClientMetadata, b.name, b.bounds)
		case b.value%time.Second != 0:
			return fmt.Errorf("%w: %s must be a whole number of seconds", ErrInvalidClientMetadata, b.name)
		}
	}
	// An idle lifetime may not exceed the absolute lifetime that applies,
	// the default one included. A default idle lifetime above a short
	// absolute lifetime is capped when tokens are issued.
	if l.RefreshTokenIdle > orDefault(l.RefreshTokenAbsolute, DefaultRefreshTokenAbsoluteLifetime) {
		return fmt.Errorf("%w: the refresh token idle lifetime must not exceed the absolute lifetime, "+
			"which is 30 days by default", ErrInvalidClientMetadata)
	}
	return nil
}

// dedupe returns list without repeated entries, keeping the first occurrence
// of each. It runs before the size limits are checked, so it takes linear
// time.
func dedupe(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// GetClient returns the client of a tenant with the given client ID.
func GetClient(ctx context.Context, d Deps, tenantID uuid.UUID, clientID string) (store.Client, error) {
	if oauth.ValidateClientID(clientID) != nil {
		return store.Client{}, fmt.Errorf("%w: %q", ErrClientNotFound, clientID)
	}
	c, err := d.Store.Clients().GetByClientID(ctx, tenantID, clientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Client{}, fmt.Errorf("%w: %q", ErrClientNotFound, clientID)
	case err != nil:
		return store.Client{}, fmt.Errorf("looking up client %q: %w", clientID, err)
	}
	return c, nil
}

// ListClients returns every client of a tenant in ID order, which follows
// creation time.
func ListClients(ctx context.Context, d Deps, tenantID uuid.UUID) ([]store.Client, error) {
	var all []store.Client
	after := uuid.Nil()
	for {
		page, err := d.Store.Clients().List(ctx, tenantID, after, store.MaxPageSize)
		if err != nil {
			return nil, fmt.Errorf("listing clients: %w", err)
		}
		all = append(all, page...)
		if len(page) < store.MaxPageSize {
			return all, nil
		}
		after = page[len(page)-1].ID
	}
}

// RotateClientSecret replaces the secret of a confidential client and returns
// the new one. The previous secret stops working at once.
func RotateClientSecret(ctx context.Context, d Deps, tenantID uuid.UUID, clientID string) (string, error) {
	c, err := GetClient(ctx, d, tenantID, clientID)
	if err != nil {
		return "", err
	}
	if c.Type != store.ClientConfidential {
		return "", fmt.Errorf("%w: %q is a public client", ErrPublicClient, clientID)
	}
	secret, hash := oauth.NewClientSecret()
	switch err := d.Store.Clients().UpdateSecret(ctx, tenantID, c.ID, hash, d.Now()); {
	case errors.Is(err, store.ErrNotFound):
		return "", fmt.Errorf("%w: %q", ErrClientNotFound, clientID)
	case err != nil:
		return "", fmt.Errorf("rotating the secret of client %q: %w", clientID, err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "rotated client secret",
		slog.String("tenant_id", tenantID.String()), slog.String("client_id", c.ClientID))
	return secret, nil
}

// DeleteClient deletes the client of a tenant with the given client ID.
func DeleteClient(ctx context.Context, d Deps, tenantID uuid.UUID, clientID string) error {
	c, err := GetClient(ctx, d, tenantID, clientID)
	if err != nil {
		return err
	}
	switch err := d.Store.Clients().Delete(ctx, tenantID, c.ID); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %q", ErrClientNotFound, clientID)
	case err != nil:
		return fmt.Errorf("deleting client %q: %w", clientID, err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted client",
		slog.String("tenant_id", tenantID.String()), slog.String("client_id", c.ClientID))
	return nil
}
