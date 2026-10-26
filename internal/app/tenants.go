package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"unicode"
	"unicode/utf8"
	"uuid"

	"clavisid.org/clavis/store"
)

// AdminTenantSlug is reserved for the tenant that administers Clavis
// (ADR 0016).
const AdminTenantSlug = "admin"

// MaxNameLength is the longest display name of a tenant or a client, in
// characters.
const MaxNameLength = 200

// maxSlugLength keeps slugs within one DNS label, so a slug can later name a
// subdomain as well as a path segment.
const maxSlugLength = 63

// Errors returned by the tenant use cases.
var (
	ErrInvalidTenant   = errors.New("invalid tenant")
	ErrReservedSlug    = errors.New("reserved tenant slug")
	ErrTenantExists    = errors.New("tenant already exists")
	ErrTenantNotFound  = errors.New("tenant not found")
	ErrProtectedTenant = errors.New("the default and admin tenants cannot be deleted")
	// ErrSignupNotAllowed reports an attempt to let people sign up to the
	// admin tenant, whose users administer Clavis (ADR 0026).
	ErrSignupNotAllowed = errors.New("the admin tenant cannot allow signup")
)

// ValidateTenantSlug reports whether slug can name a tenant: 1 to 63
// characters, lowercase ASCII letters, digits and hyphens, starting with a
// letter and not ending with a hyphen.
func ValidateTenantSlug(slug string) error {
	if slug == "" || len(slug) > maxSlugLength {
		return fmt.Errorf("%w: slug must have 1 to %d characters", ErrInvalidTenant, maxSlugLength)
	}
	for i, c := range []byte(slug) {
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return fmt.Errorf("%w: slug %q must start with a lowercase letter and contain only "+
				"lowercase letters, digits and hyphens", ErrInvalidTenant, slug)
		}
	}
	if slug[len(slug)-1] == '-' {
		return fmt.Errorf("%w: slug %q must not end with a hyphen", ErrInvalidTenant, slug)
	}
	return nil
}

// validateDisplayName reports whether name can be displayed safely: control
// characters, bidirectional formatting characters (which can make text
// display differently from how it is stored) and line or paragraph
// separators are rejected.
func validateDisplayName(name string) error {
	if !utf8.ValidString(name) {
		return errors.New("name is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(name); n == 0 || n > MaxNameLength {
		return fmt.Errorf("name must have 1 to %d characters", MaxNameLength)
	}
	for _, r := range name {
		if unicode.In(r, unicode.Cc, unicode.Bidi_Control, unicode.Zl, unicode.Zp) {
			return errors.New("name must not contain control, bidirectional formatting or " +
				"line separator characters")
		}
	}
	return nil
}

// isReservedSlug reports whether slug belongs to a tenant that Clavis manages
// itself.
func isReservedSlug(slug string) bool {
	return slug == DefaultTenantSlug || slug == AdminTenantSlug
}

// CreateTenant creates a tenant and then its signing keys through
// createKeys, so the tenant can sign tokens as soon as it exists. An empty
// name defaults to the slug. If createKeys fails, the tenant still exists and
// key rotation creates its keys later; the error says so.
func CreateTenant(ctx context.Context, d Deps, createKeys func(context.Context, uuid.UUID) error,
	slug, name string,
) (store.Tenant, error) {
	if err := ValidateTenantSlug(slug); err != nil {
		return store.Tenant{}, err
	}
	if isReservedSlug(slug) {
		return store.Tenant{}, fmt.Errorf("%w: %q", ErrReservedSlug, slug)
	}
	if name == "" {
		name = slug
	}
	if err := validateDisplayName(name); err != nil {
		return store.Tenant{}, fmt.Errorf("%w: %w", ErrInvalidTenant, err)
	}

	now := d.Now()
	t := store.Tenant{ID: d.NewID(), Slug: slug, Name: name, CreatedAt: now, UpdatedAt: now}
	switch err := d.Store.Tenants().Create(ctx, t); {
	case errors.Is(err, store.ErrConflict):
		return store.Tenant{}, fmt.Errorf("%w: %q", ErrTenantExists, slug)
	case err != nil:
		return store.Tenant{}, fmt.Errorf("creating tenant %q: %w", slug, err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "created tenant",
		slog.String("tenant_id", t.ID.String()), slog.String("tenant", t.Slug))

	d.Cache.forgetSlug(t.Slug)

	if err := createKeys(ctx, t.ID); err != nil {
		return t, fmt.Errorf("tenant %q was created, but creating its signing keys failed "+
			"(key rotation retries on the next check): %w", slug, err)
	}
	return t, nil
}

// TenantBySlug returns the tenant served under /t/{slug}. The default tenant
// is served only at the root issuer, so it is not found by slug; neither is
// any slug that fails validation. The Cache of d keeps the answer, a tenant
// or none, for TenantCacheTTL.
func TenantBySlug(ctx context.Context, d Deps, slug string) (store.Tenant, error) {
	if slug == DefaultTenantSlug || ValidateTenantSlug(slug) != nil {
		return store.Tenant{}, ErrTenantNotFound
	}
	now, unknown := d.Now(), d.Cache.unknownSlugMap()
	_, gen, ok := unknown.get(slug, now)
	if ok {
		return store.Tenant{}, ErrTenantNotFound
	}
	return cached(d.Cache.slugMap(), slug, now, func() (store.Tenant, error) {
		t, err := d.Store.Tenants().GetBySlug(ctx, slug)
		switch {
		case errors.Is(err, store.ErrNotFound):
			unknown.put(slug, struct{}{}, now, gen)
			return store.Tenant{}, ErrTenantNotFound
		case err != nil:
			return store.Tenant{}, fmt.Errorf("looking up tenant: %w", err)
		}
		return t, nil
	})
}

// TenantByID returns the tenant with the given ID as stored at most
// TenantCacheTTL ago, which the Cache of d keeps, so a request sees the
// recent settings of a tenant that it found earlier.
func TenantByID(ctx context.Context, d Deps, id uuid.UUID) (store.Tenant, error) {
	return cached(d.Cache.tenantMap(), id, d.Now(), func() (store.Tenant, error) {
		t, err := d.Store.Tenants().Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return store.Tenant{}, ErrTenantNotFound
		case err != nil:
			return store.Tenant{}, fmt.Errorf("looking up tenant: %w", err)
		}
		return t, nil
	})
}

// ListTenants returns every tenant in ID order, which follows creation time
// because IDs are version 7 UUIDs.
func ListTenants(ctx context.Context, d Deps) ([]store.Tenant, error) {
	var all []store.Tenant
	after := uuid.Nil()
	for {
		page, err := d.Store.Tenants().List(ctx, after, store.MaxPageSize)
		if err != nil {
			return nil, fmt.Errorf("listing tenants: %w", err)
		}
		all = append(all, page...)
		if len(page) < store.MaxPageSize {
			return all, nil
		}
		after = page[len(page)-1].ID
	}
}

// FindTenant returns the tenant with the given slug, including the tenants
// Clavis manages itself. It serves administration; requests are routed with
// TenantBySlug.
func FindTenant(ctx context.Context, d Deps, slug string) (store.Tenant, error) {
	t, err := d.Store.Tenants().GetBySlug(ctx, slug)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Tenant{}, fmt.Errorf("%w: %q", ErrTenantNotFound, slug)
	case err != nil:
		return store.Tenant{}, fmt.Errorf("looking up tenant %q: %w", slug, err)
	}
	return t, nil
}

// DeleteTenant deletes the tenant with the given slug together with
// everything it owns. The tenants Clavis manages itself cannot be deleted.
func DeleteTenant(ctx context.Context, d Deps, slug string) error {
	if isReservedSlug(slug) {
		return fmt.Errorf("%w: %q", ErrProtectedTenant, slug)
	}
	t, err := FindTenant(ctx, d, slug)
	if err != nil {
		return err
	}
	switch err := d.Store.Tenants().Delete(ctx, t.ID); {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: %q", ErrTenantNotFound, slug)
	case err != nil:
		return fmt.Errorf("deleting tenant %q: %w", slug, err)
	}
	d.Cache.forgetTenant(t)
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted tenant",
		slog.String("tenant_id", t.ID.String()), slog.String("tenant", t.Slug))
	return nil
}

// TenantChanges are the changes that UpdateTenant makes; nil fields keep
// their values.
type TenantChanges struct {
	Name *string
	// SignupEnabled lets people create their own accounts (ADR 0026).
	SignupEnabled *bool
}

// UpdateTenant changes the name or the settings of the tenant with the given
// slug and returns the result. The admin tenant cannot allow signup.
func UpdateTenant(ctx context.Context, d Deps, slug string, c TenantChanges) (store.Tenant, error) {
	t, err := FindTenant(ctx, d, slug)
	if err != nil {
		return store.Tenant{}, err
	}
	if c.Name != nil {
		if err := validateDisplayName(*c.Name); err != nil {
			return store.Tenant{}, fmt.Errorf("%w: %w", ErrInvalidTenant, err)
		}
		t.Name = *c.Name
	}
	if c.SignupEnabled != nil {
		if *c.SignupEnabled && t.Slug == AdminTenantSlug {
			return store.Tenant{}, ErrSignupNotAllowed
		}
		t.SignupEnabled = *c.SignupEnabled
	}
	t.UpdatedAt = d.Now()
	switch err := d.Store.Tenants().Update(ctx, t); {
	case errors.Is(err, store.ErrNotFound):
		return store.Tenant{}, fmt.Errorf("%w: %q", ErrTenantNotFound, slug)
	case err != nil:
		return store.Tenant{}, fmt.Errorf("updating tenant %q: %w", slug, err)
	}
	d.Cache.forgetTenant(t)
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "updated tenant",
		slog.String("tenant_id", t.ID.String()), slog.String("tenant", t.Slug),
		slog.Bool("signup_enabled", t.SignupEnabled))
	details := make(map[string]string)
	if c.Name != nil {
		details["name"] = t.Name
	}
	if c.SignupEnabled != nil {
		details["signup_enabled"] = strconv.FormatBool(t.SignupEnabled)
	}
	audit(ctx, d, store.AuditEvent{TenantID: t.ID, Type: EventTenantUpdated, Actor: store.ActorOperator,
		Details: details})
	return t, nil
}
