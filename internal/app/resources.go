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

// maxResourceScopes bounds the scopes of one API resource.
const maxResourceScopes = 100

// Errors returned by the API resource use cases.
var (
	ErrInvalidAPIResource  = errors.New("invalid API resource")
	ErrAPIResourceExists   = errors.New("API resource already exists")
	ErrAPIResourceNotFound = errors.New("API resource not found")
)

// APIResourceSpec describes an API resource to create.
type APIResourceSpec struct {
	// Identifier is an absolute URI that names the resource; tokens that
	// grant its scopes carry it in aud.
	Identifier string
	// Name is the display name. When empty, it defaults to the identifier.
	Name string
	// Scopes lists the scopes the resource defines. Each scope belongs to
	// one resource of the tenant, and OpenID Connect scopes belong to none.
	Scopes []string
}

// CreateAPIResource registers an API resource with a tenant (ADR 0014).
func CreateAPIResource(ctx context.Context, d Deps, tenantID uuid.UUID, spec APIResourceSpec) (store.APIResource, error) {
	if err := oauth.ValidateResourceIdentifier(spec.Identifier); err != nil {
		return store.APIResource{}, fmt.Errorf("%w: %w", ErrInvalidAPIResource, err)
	}
	name := spec.Name
	if name == "" {
		name = spec.Identifier
	} else if err := validateDisplayName(name); err != nil {
		return store.APIResource{}, fmt.Errorf("%w: %w", ErrInvalidAPIResource, err)
	}
	scopes := dedupe(spec.Scopes)
	if len(scopes) == 0 || len(scopes) > maxResourceScopes {
		return store.APIResource{}, fmt.Errorf("%w: a resource defines 1 to %d scopes", ErrInvalidAPIResource,
			maxResourceScopes)
	}
	owners, err := scopeOwners(ctx, d, tenantID)
	if err != nil {
		return store.APIResource{}, err
	}
	for _, scope := range scopes {
		switch {
		case oauth.ValidateScope(scope) != nil:
			return store.APIResource{}, fmt.Errorf("%w: %w", ErrInvalidAPIResource, oauth.ValidateScope(scope))
		case oidc.IsOpenIDScope(scope):
			return store.APIResource{}, fmt.Errorf("%w: %s is an OpenID Connect scope", ErrInvalidAPIResource, scope)
		}
		if owner, ok := owners[scope]; ok {
			return store.APIResource{}, fmt.Errorf("%w: scope %s belongs to %s", ErrInvalidAPIResource, scope,
				owner.Identifier)
		}
	}

	now := d.Now()
	r := store.APIResource{
		ID:         d.NewID(),
		TenantID:   tenantID,
		Identifier: spec.Identifier,
		Name:       name,
		Scopes:     scopes,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	switch err := d.Store.APIResources().Create(ctx, r); {
	case errors.Is(err, store.ErrConflict):
		return store.APIResource{}, fmt.Errorf("%w: %s", ErrAPIResourceExists, r.Identifier)
	case errors.Is(err, store.ErrNotFound):
		return store.APIResource{}, ErrTenantNotFound
	case err != nil:
		return store.APIResource{}, fmt.Errorf("creating API resource: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "created API resource",
		slog.String("tenant_id", tenantID.String()), slog.String("api_resource_id", r.ID.String()))
	return r, nil
}

// ListAPIResources returns every API resource of a tenant in ID order.
func ListAPIResources(ctx context.Context, d Deps, tenantID uuid.UUID) ([]store.APIResource, error) {
	var all []store.APIResource
	after := uuid.Nil()
	for {
		page, err := d.Store.APIResources().List(ctx, tenantID, after, store.MaxPageSize)
		if err != nil {
			return nil, fmt.Errorf("listing API resources: %w", err)
		}
		all = append(all, page...)
		if len(page) < store.MaxPageSize {
			return all, nil
		}
		after = page[len(page)-1].ID
	}
}

// DeleteAPIResource deletes the API resource of a tenant with the given
// identifier. Tokens issued for it stay valid until they expire.
func DeleteAPIResource(ctx context.Context, d Deps, tenantID uuid.UUID, identifier string) error {
	r, err := d.Store.APIResources().GetByIdentifier(ctx, tenantID, identifier)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s", ErrAPIResourceNotFound, identifier)
	case err != nil:
		return fmt.Errorf("looking up API resource: %w", err)
	}
	switch err := d.Store.APIResources().Delete(ctx, tenantID, r.ID); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %s", ErrAPIResourceNotFound, identifier)
	case err != nil:
		return fmt.Errorf("deleting API resource: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted API resource",
		slog.String("tenant_id", tenantID.String()), slog.String("api_resource_id", r.ID.String()))
	return nil
}

// scopeOwners maps every scope defined by an API resource of a tenant to
// that resource.
func scopeOwners(ctx context.Context, d Deps, tenantID uuid.UUID) (map[string]store.APIResource, error) {
	resources, err := ListAPIResources(ctx, d, tenantID)
	if err != nil {
		return nil, err
	}
	owners := make(map[string]store.APIResource)
	for _, r := range resources {
		for _, scope := range r.Scopes {
			owners[scope] = r
		}
	}
	return owners, nil
}

// undefinedScope returns the first of scopes that is neither an OpenID
// Connect scope nor defined by an API resource in owners, or "".
func undefinedScope(scopes []string, owners map[string]store.APIResource) string {
	i := slices.IndexFunc(scopes, func(s string) bool {
		_, ok := owners[s]
		return !ok && !oidc.IsOpenIDScope(s)
	})
	if i < 0 {
		return ""
	}
	return scopes[i]
}
