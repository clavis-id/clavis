package app

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"uuid"

	"clavisid.org/clavis/store"
)

func TestValidateTenantSlug(t *testing.T) {
	t.Parallel()

	tests := []struct {
		slug  string
		valid bool
	}{
		{slug: "a", valid: true},
		{slug: "acme", valid: true},
		{slug: "acme-eu-1", valid: true},
		{slug: "a" + strings.Repeat("b", 62), valid: true},
		{slug: ""},
		{slug: "a" + strings.Repeat("b", 63)},
		{slug: "1acme"},
		{slug: "-acme"},
		{slug: "acme-"},
		{slug: "Acme"},
		{slug: "acme_eu"},
		{slug: "acme.eu"},
		{slug: "acme/eu"},
		{slug: "acmé"},
		{slug: "acme eu"},
		{slug: "acme\n"},
	}
	for _, tt := range tests {
		err := ValidateTenantSlug(tt.slug)
		switch {
		case tt.valid && err != nil:
			t.Errorf("ValidateTenantSlug(%q) = %v, want nil", tt.slug, err)
		case !tt.valid && !errors.Is(err, ErrInvalidTenant):
			t.Errorf("ValidateTenantSlug(%q) = %v, want ErrInvalidTenant", tt.slug, err)
		}
	}
}

// validSlug is the documented slug syntax, as an independent oracle for the
// fuzz test.
var validSlug = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

func FuzzValidateTenantSlug(f *testing.F) {
	for _, seed := range []string{"acme", "a-1", "-a", "a-", "A", "", "a/b", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, slug string) {
		err := ValidateTenantSlug(slug)
		if want := validSlug.MatchString(slug); want != (err == nil) {
			t.Errorf("ValidateTenantSlug(%q) = %v, want valid = %v", slug, err, want)
		}
	})
}

// keyRecorder records the tenants whose keys CreateTenant asked for.
type keyRecorder struct {
	ids []uuid.UUID
	err error
}

func (k *keyRecorder) create(_ context.Context, id uuid.UUID) error {
	k.ids = append(k.ids, id)
	return k.err
}

func TestCreateTenant(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	d := newDeps(t, st)
	var keys keyRecorder
	got, err := CreateTenant(t.Context(), d, keys.create, "acme", "Acme Corp")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	if got.Slug != "acme" || got.Name != "Acme Corp" || got.CreatedAt != d.Now() {
		t.Errorf("CreateTenant() = %+v", got)
	}
	if len(keys.ids) != 1 || keys.ids[0] != got.ID {
		t.Errorf("signing keys requested for %v, want [%v]", keys.ids, got.ID)
	}
	stored, err := st.Tenants().GetBySlug(t.Context(), "acme")
	if err != nil || stored.ID != got.ID {
		t.Errorf("stored tenant = %+v, %v", stored, err)
	}
}

func TestCreateTenantDefaultsNameToSlug(t *testing.T) {
	t.Parallel()

	var keys keyRecorder
	got, err := CreateTenant(t.Context(), newDeps(t, openStore(t)), keys.create, "acme", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	if got.Name != "acme" {
		t.Errorf("Name = %q, want the slug", got.Name)
	}
}

func TestCreateTenantRejections(t *testing.T) {
	t.Parallel()

	d := newDeps(t, openStore(t))
	var keys keyRecorder
	if _, err := CreateTenant(t.Context(), d, keys.create, "acme", ""); err != nil {
		t.Fatalf("creating the first tenant: %v", err)
	}
	tests := []struct {
		name, slug, tenantName string
		want                   error
	}{
		{name: "invalid slug", slug: "Acme", want: ErrInvalidTenant},
		{name: "default slug", slug: DefaultTenantSlug, want: ErrReservedSlug},
		{name: "admin slug", slug: AdminTenantSlug, want: ErrReservedSlug},
		{name: "duplicate slug", slug: "acme", want: ErrTenantExists},
		{name: "control character in name", slug: "beta", tenantName: "Beta\nCorp", want: ErrInvalidTenant},
		{name: "name too long", slug: "beta", tenantName: strings.Repeat("x", MaxTenantNameLength+1), want: ErrInvalidTenant},
		{name: "invalid UTF-8 name", slug: "beta", tenantName: "\xff", want: ErrInvalidTenant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CreateTenant(t.Context(), d, keys.create, tt.slug, tt.tenantName); !errors.Is(err, tt.want) {
				t.Errorf("CreateTenant(%q, %q) = %v, want %v", tt.slug, tt.tenantName, err, tt.want)
			}
		})
	}
	if len(keys.ids) != 1 {
		t.Errorf("signing keys requested %d times, want only for the first tenant", len(keys.ids))
	}
}

func TestCreateTenantReportsKeyFailure(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	keys := keyRecorder{err: errors.New("encrypter unavailable")}
	got, err := CreateTenant(t.Context(), newDeps(t, st), keys.create, "acme", "")
	if err == nil || !strings.Contains(err.Error(), "was created") {
		t.Fatalf("CreateTenant() = %v, want an error explaining the tenant exists", err)
	}
	if _, err := st.Tenants().Get(t.Context(), got.ID); err != nil {
		t.Errorf("tenant was not kept: %v", err)
	}
}

func TestTenantBySlug(t *testing.T) {
	t.Parallel()

	d := newDeps(t, openStore(t))
	if _, err := EnsureDefaultTenant(t.Context(), d); err != nil {
		t.Fatalf("EnsureDefaultTenant() unexpected error: %v", err)
	}
	var keys keyRecorder
	acme, err := CreateTenant(t.Context(), d, keys.create, "acme", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}

	got, err := TenantBySlug(t.Context(), d, "acme")
	if err != nil || got.ID != acme.ID {
		t.Errorf("TenantBySlug(acme) = %+v, %v", got, err)
	}
	// The default tenant is served only at the root issuer.
	for _, slug := range []string{DefaultTenantSlug, "missing", "ACME", "acme/x", ""} {
		if _, err := TenantBySlug(t.Context(), d, slug); !errors.Is(err, ErrTenantNotFound) {
			t.Errorf("TenantBySlug(%q) = %v, want ErrTenantNotFound", slug, err)
		}
	}
}

func TestListTenants(t *testing.T) {
	t.Parallel()

	d := newDeps(t, openStore(t))
	var keys keyRecorder
	for _, slug := range []string{"one", "two", "three"} {
		if _, err := CreateTenant(t.Context(), d, keys.create, slug, ""); err != nil {
			t.Fatalf("CreateTenant(%q) unexpected error: %v", slug, err)
		}
	}
	got, err := ListTenants(t.Context(), d)
	if err != nil {
		t.Fatalf("ListTenants() unexpected error: %v", err)
	}
	var slugs []string
	for _, tenant := range got {
		slugs = append(slugs, tenant.Slug)
	}
	if strings.Join(slugs, ",") != "one,two,three" {
		t.Errorf("ListTenants() slugs = %v, want creation order", slugs)
	}
}

// pagedTenants serves List from a fixed slice, to test paging without
// creating thousands of records.
type pagedTenants struct {
	store.Tenants
	all []store.Tenant
}

func (p pagedTenants) List(_ context.Context, after uuid.UUID, limit int) ([]store.Tenant, error) {
	start := 0
	for i, t := range p.all {
		if t.ID == after {
			start = i + 1
		}
	}
	return p.all[start:min(start+limit, len(p.all))], nil
}

type pagedStore struct {
	store.Store
	tenants pagedTenants
}

func (p pagedStore) Tenants() store.Tenants { return p.tenants }

func TestListTenantsReadsEveryPage(t *testing.T) {
	t.Parallel()

	all := make([]store.Tenant, store.MaxPageSize+1)
	for i := range all {
		all[i] = store.Tenant{ID: uuid.NewV7()}
	}
	d := newDeps(t, pagedStore{tenants: pagedTenants{all: all}})
	got, err := ListTenants(t.Context(), d)
	if err != nil {
		t.Fatalf("ListTenants() unexpected error: %v", err)
	}
	if len(got) != len(all) {
		t.Errorf("ListTenants() returned %d tenants, want %d", len(got), len(all))
	}
}

func TestDeleteTenant(t *testing.T) {
	t.Parallel()

	st := openStore(t)
	d := newDeps(t, st)
	if _, err := EnsureDefaultTenant(t.Context(), d); err != nil {
		t.Fatalf("EnsureDefaultTenant() unexpected error: %v", err)
	}
	var keys keyRecorder
	acme, err := CreateTenant(t.Context(), d, keys.create, "acme", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}

	if err := DeleteTenant(t.Context(), d, "acme"); err != nil {
		t.Fatalf("DeleteTenant() unexpected error: %v", err)
	}
	if _, err := st.Tenants().Get(t.Context(), acme.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("tenant still stored: %v", err)
	}
	if err := DeleteTenant(t.Context(), d, "acme"); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("deleting twice = %v, want ErrTenantNotFound", err)
	}
	for _, slug := range []string{DefaultTenantSlug, AdminTenantSlug} {
		if err := DeleteTenant(t.Context(), d, slug); !errors.Is(err, ErrProtectedTenant) {
			t.Errorf("DeleteTenant(%q) = %v, want ErrProtectedTenant", slug, err)
		}
	}
}
