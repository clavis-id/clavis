package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
)

// readCounter counts the reads of a store that a Cache keeps, by method.
type readCounter struct {
	store.Store
	mu    sync.Mutex
	reads map[string]int
	fail  error
	// afterTenant, when set, runs after a tenant is read by ID.
	afterTenant func()
}

func (c *readCounter) read(method string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reads == nil {
		c.reads = make(map[string]int)
	}
	c.reads[method]++
	return c.fail
}

// count returns the reads of method and starts counting again.
func (c *readCounter) count(method string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.reads[method]
	delete(c.reads, method)
	return n
}

// setAfterTenant makes f run after each read of a tenant by ID, or nothing
// when f is nil.
func (c *readCounter) setAfterTenant(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.afterTenant = f
}

// setFailure makes every counted read fail with err, or succeed when err
// is nil.
func (c *readCounter) setFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = err
}

func (c *readCounter) Tenants() store.Tenants {
	return countedTenants{c.Store.Tenants(), c}
}

func (c *readCounter) APIResources() store.APIResources {
	return countedResources{c.Store.APIResources(), c}
}

func (c *readCounter) Brandings() store.Brandings {
	return countedBrandings{c.Store.Brandings(), c}
}

type countedTenants struct {
	store.Tenants
	c *readCounter
}

func (t countedTenants) Get(ctx context.Context, id uuid.UUID) (store.Tenant, error) {
	if err := t.c.read("Tenants.Get"); err != nil {
		return store.Tenant{}, err
	}
	tn, err := t.Tenants.Get(ctx, id)
	t.c.mu.Lock()
	after := t.c.afterTenant
	t.c.mu.Unlock()
	if after != nil {
		after()
	}
	return tn, err
}

func (t countedTenants) GetBySlug(ctx context.Context, slug string) (store.Tenant, error) {
	if err := t.c.read("Tenants.GetBySlug"); err != nil {
		return store.Tenant{}, err
	}
	return t.Tenants.GetBySlug(ctx, slug)
}

type countedResources struct {
	store.APIResources
	c *readCounter
}

func (r countedResources) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.APIResource, error) {
	if err := r.c.read("APIResources.List"); err != nil {
		return nil, err
	}
	return r.APIResources.List(ctx, tenantID, after, limit)
}

type countedBrandings struct {
	store.Brandings
	c *readCounter
}

func (b countedBrandings) Get(ctx context.Context, tenantID uuid.UUID) (store.Branding, error) {
	if err := b.c.read("Brandings.Get"); err != nil {
		return store.Branding{}, err
	}
	return b.Brandings.Get(ctx, tenantID)
}

func (b countedBrandings) GetLogo(ctx context.Context, tenantID uuid.UUID) (store.Logo, error) {
	if err := b.c.read("Brandings.GetLogo"); err != nil {
		return store.Logo{}, err
	}
	return b.Brandings.GetLogo(ctx, tenantID)
}

// cacheFixture is a tenant "acme" read through a Cache with a clock that
// tests move, and the same store without a Cache, as the command line or
// another instance uses it.
type cacheFixture struct {
	d, other Deps
	reads    *readCounter
	tenant   store.Tenant
	now      *time.Time
}

func newCacheFixture(t *testing.T) cacheFixture {
	t.Helper()
	st := openStore(t)
	f := cacheFixture{other: newDeps(t, st), reads: &readCounter{Store: st}}
	now := f.other.Now()
	f.now = &now
	f.d = newDeps(t, f.reads)
	f.d.Now = func() time.Time { return *f.now }
	f.d.Cache = NewCache()
	f.tenant = newTenantForClients(t, f.other)
	return f
}

// ADR 0031: tenants, by ID and by slug, and slugs of no tenant are read
// once per TenantCacheTTL (from the reviews of #43 and #80).
func TestCacheKeepsTenants(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	for range 3 {
		if got, err := TenantBySlug(t.Context(), f.d, "acme"); err != nil || got.ID != f.tenant.ID {
			t.Fatalf("TenantBySlug() = %+v, %v; want the tenant", got, err)
		}
		if got, err := TenantByID(t.Context(), f.d, f.tenant.ID); err != nil || got.Slug != "acme" {
			t.Fatalf("TenantByID() = %+v, %v; want the tenant", got, err)
		}
		if _, err := TenantBySlug(t.Context(), f.d, "nobody"); !errors.Is(err, ErrTenantNotFound) {
			t.Fatalf("TenantBySlug() of no tenant = %v, want ErrTenantNotFound", err)
		}
	}
	if n := f.reads.count("Tenants.GetBySlug"); n != 2 {
		t.Errorf("three lookups of two slugs read the store %d times, want 2", n)
	}
	if n := f.reads.count("Tenants.Get"); n != 1 {
		t.Errorf("three lookups by ID read the store %d times, want 1", n)
	}

	// A change elsewhere applies within TenantCacheTTL.
	name := "Acme Inc."
	if _, err := UpdateTenant(t.Context(), f.other, "acme", TenantChanges{Name: &name}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	if _, err := CreateTenant(t.Context(), f.other, new(keyRecorder).create, "nobody", ""); err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	*f.now = f.now.Add(TenantCacheTTL - time.Second)
	if got, _ := TenantBySlug(t.Context(), f.d, "acme"); got.Name != "acme" {
		t.Errorf("TenantBySlug() before the TTL = %q, want the kept name", got.Name)
	}
	if _, err := TenantBySlug(t.Context(), f.d, "nobody"); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("TenantBySlug() of a kept miss = %v, want ErrTenantNotFound", err)
	}
	*f.now = f.now.Add(time.Second)
	if got, _ := TenantBySlug(t.Context(), f.d, "acme"); got.Name != name {
		t.Errorf("TenantBySlug() after the TTL = %q, want %q", got.Name, name)
	}
	if got, _ := TenantByID(t.Context(), f.d, f.tenant.ID); got.Name != name {
		t.Errorf("TenantByID() after the TTL = %q, want %q", got.Name, name)
	}
	if _, err := TenantBySlug(t.Context(), f.d, "nobody"); err != nil {
		t.Errorf("TenantBySlug() of a new tenant after the TTL = %v, want it found", err)
	}
}

// ADR 0031: a change through the use cases of the same process applies at
// once.
func TestCacheForgetsChangesOfItsProcess(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	if _, err := TenantBySlug(t.Context(), f.d, "beta"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("TenantBySlug() of no tenant = %v, want ErrTenantNotFound", err)
	}
	if _, err := CreateTenant(t.Context(), f.d, new(keyRecorder).create, "beta", ""); err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	if _, err := TenantBySlug(t.Context(), f.d, "beta"); err != nil {
		t.Errorf("TenantBySlug() of a tenant just created = %v, want it found", err)
	}

	if _, err := TenantByID(t.Context(), f.d, f.tenant.ID); err != nil {
		t.Fatalf("TenantByID() unexpected error: %v", err)
	}
	on := true
	if _, err := UpdateTenant(t.Context(), f.d, "acme", TenantChanges{SignupEnabled: &on}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	if got, _ := TenantByID(t.Context(), f.d, f.tenant.ID); !got.SignupEnabled {
		t.Error("TenantByID() after UpdateTenant() kept the old settings")
	}
	if got, _ := TenantBySlug(t.Context(), f.d, "acme"); !got.SignupEnabled {
		t.Error("TenantBySlug() after UpdateTenant() kept the old settings")
	}

	if err := DeleteTenant(t.Context(), f.d, "beta"); err != nil {
		t.Fatalf("DeleteTenant() unexpected error: %v", err)
	}
	if _, err := TenantBySlug(t.Context(), f.d, "beta"); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("TenantBySlug() of a deleted tenant = %v, want ErrTenantNotFound", err)
	}
}

// ADR 0031: the API resources of a tenant are read once per TenantCacheTTL
// (from the review of #52), but a new resource checks its scopes against
// the store.
func TestCacheKeepsAPIResources(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	// The resources are kept before the first one is created.
	if owners, err := scopeOwners(t.Context(), f.d, f.tenant.ID); err != nil || len(owners) != 0 {
		t.Fatalf("scopeOwners() = %v, %v; want none", owners, err)
	}
	if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, APIResourceSpec{
		Identifier: "https://api.example.com", Scopes: []string{"orders:read"}}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	f.reads.count("APIResources.List")
	for range 3 {
		owners, err := scopeOwners(t.Context(), f.d, f.tenant.ID)
		if err != nil || owners["orders:read"].Identifier != "https://api.example.com" {
			t.Fatalf("scopeOwners() = %v, %v; want the resource", owners, err)
		}
	}
	if n := f.reads.count("APIResources.List"); n != 1 {
		t.Errorf("three lookups read the resources %d times, want 1", n)
	}

	// Another process adds a resource the Cache does not know yet.
	if _, err := CreateAPIResource(t.Context(), f.other, f.tenant.ID, APIResourceSpec{
		Identifier: "https://billing.example.com", Scopes: []string{"invoices:read"}}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	if _, err := CreateAPIResource(t.Context(), f.d, f.tenant.ID, APIResourceSpec{
		Identifier: "https://other.example.com", Scopes: []string{"invoices:read"}}); !errors.Is(err, ErrInvalidAPIResource) {
		t.Errorf("CreateAPIResource() with a scope that another process took = %v, want ErrInvalidAPIResource", err)
	}
	if err := DeleteAPIResource(t.Context(), f.d, f.tenant.ID, "https://api.example.com"); err != nil {
		t.Fatalf("DeleteAPIResource() unexpected error: %v", err)
	}
	owners, err := scopeOwners(t.Context(), f.d, f.tenant.ID)
	if _, ok := owners["orders:read"]; err != nil || ok || owners["invoices:read"].Identifier == "" {
		t.Errorf("scopeOwners() after a deletion = %v, %v; want only the other process's resource", owners, err)
	}
}

// ADR 0031: the branding and the logo of a tenant are read once per
// TenantCacheTTL (from the review of #78), and changes to them apply at
// once in the same process.
func TestCacheKeepsBrandingAndLogo(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	for range 3 {
		if _, err := TenantBranding(t.Context(), f.d, f.tenant.ID); err != nil {
			t.Fatalf("TenantBranding() unexpected error: %v", err)
		}
		if _, err := TenantLogo(t.Context(), f.d, f.tenant.ID); !errors.Is(err, ErrLogoNotFound) {
			t.Fatalf("TenantLogo() without a logo = %v, want ErrLogoNotFound", err)
		}
	}
	if n, m := f.reads.count("Brandings.Get"), f.reads.count("Brandings.GetLogo"); n != 1 || m != 1 {
		t.Errorf("three lookups read the branding %d times and the logo %d times, want 1 each", n, m)
	}

	// Each change is made with the branding and the logo kept.
	fill := func() {
		t.Helper()
		if _, err := TenantBranding(t.Context(), f.d, f.tenant.ID); err != nil {
			t.Fatalf("TenantBranding() unexpected error: %v", err)
		}
		if _, err := TenantLogo(t.Context(), f.d, f.tenant.ID); err != nil && !errors.Is(err, ErrLogoNotFound) {
			t.Fatalf("TenantLogo() unexpected error: %v", err)
		}
	}
	logo, err := SetLogo(t.Context(), f.d, f.tenant.ID, encodedImage(t, "png", 2, 2))
	if err != nil {
		t.Fatalf("SetLogo() unexpected error: %v", err)
	}
	if got, err := TenantLogo(t.Context(), f.d, f.tenant.ID); err != nil || got.Hash != logo.Hash {
		t.Errorf("TenantLogo() after SetLogo() = %+v, %v; want the new logo", got, err)
	}
	if got, _ := TenantBranding(t.Context(), f.d, f.tenant.ID); got.LogoHash != logo.Hash {
		t.Errorf("TenantBranding() after SetLogo() = %+v, want the new logo", got)
	}
	fill()
	if err := SetTheme(t.Context(), f.d, f.tenant.ID, store.Theme{Light: store.ThemeColors{Accent: "#0b5cad"}}); err != nil {
		t.Fatalf("SetTheme() unexpected error: %v", err)
	}
	if got, _ := TenantBranding(t.Context(), f.d, f.tenant.ID); got.Theme.Light.Accent != "#0b5cad" {
		t.Errorf("TenantBranding() after SetTheme() = %+v, want the new theme", got)
	}
	fill()
	if err := RemoveLogo(t.Context(), f.d, f.tenant.ID); err != nil {
		t.Fatalf("RemoveLogo() unexpected error: %v", err)
	}
	if _, err := TenantLogo(t.Context(), f.d, f.tenant.ID); !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("TenantLogo() after RemoveLogo() = %v, want ErrLogoNotFound", err)
	}
	if got, _ := TenantBranding(t.Context(), f.d, f.tenant.ID); got.LogoHash != "" {
		t.Errorf("TenantBranding() after RemoveLogo() = %+v, want no logo", got)
	}
	fill()
	if err := ResetBranding(t.Context(), f.d, f.tenant.ID); err != nil {
		t.Fatalf("ResetBranding() unexpected error: %v", err)
	}
	if got, _ := TenantBranding(t.Context(), f.d, f.tenant.ID); got.Theme.Light.Accent != "" {
		t.Errorf("TenantBranding() after ResetBranding() = %+v, want the defaults", got)
	}
}

// ADR 0031: a tenant read before a change of the same process is not kept
// after the change forgot it, so the change still applies at once.
func TestCacheKeepsNoValueReadBeforeAChange(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	read, resume := make(chan struct{}), make(chan struct{})
	f.reads.setAfterTenant(func() {
		read <- struct{}{}
		<-resume
	})
	done := make(chan store.Tenant)
	go func() {
		got, _ := TenantByID(t.Context(), f.d, f.tenant.ID)
		done <- got
	}()
	<-read
	f.reads.setAfterTenant(nil)
	name := "Acme Inc."
	if _, err := UpdateTenant(t.Context(), f.d, "acme", TenantChanges{Name: &name}); err != nil {
		t.Fatalf("UpdateTenant() unexpected error: %v", err)
	}
	close(resume)
	if got := <-done; got.Name != "acme" {
		t.Errorf("TenantByID() that read before the change = %q, want the old name", got.Name)
	}
	if got, err := TenantByID(t.Context(), f.d, f.tenant.ID); err != nil || got.Name != name {
		t.Errorf("TenantByID() after the change = %q, %v; want %q", got.Name, err, name)
	}
}

// ADR 0031: slugs of no tenant have a bound of their own, so many of them
// cannot keep the tenants from being kept.
func TestUnknownSlugsDoNotCrowdOutTenants(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	f.d.Cache = newCache(2, 1)
	for i := range 3 {
		if _, err := TenantBySlug(t.Context(), f.d, fmt.Sprintf("nobody%d", i)); !errors.Is(err, ErrTenantNotFound) {
			t.Fatalf("TenantBySlug() of no tenant = %v, want ErrTenantNotFound", err)
		}
	}
	// The first two are kept, up to the bound.
	for i := range 2 {
		if _, err := TenantBySlug(t.Context(), f.d, fmt.Sprintf("nobody%d", i)); !errors.Is(err, ErrTenantNotFound) {
			t.Fatalf("TenantBySlug() of a kept slug of no tenant = %v, want ErrTenantNotFound", err)
		}
	}
	for range 2 {
		if _, err := TenantBySlug(t.Context(), f.d, "acme"); err != nil {
			t.Fatalf("TenantBySlug() unexpected error: %v", err)
		}
	}
	if n := f.reads.count("Tenants.GetBySlug"); n != 4 {
		t.Errorf("lookups of three slugs of no tenant, two of them twice, and a tenant twice read the store %d "+
			"times, want 4", n)
	}
}

// ADR 0031: when another process changes the logo, the branding and the
// logo that a Cache keeps change together, whichever expires first, so
// that pages name the logo that its route serves.
func TestCacheKeepsBrandingAndLogoInStep(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	setLogo := func(size int) store.Logo {
		t.Helper()
		logo, err := SetLogo(t.Context(), f.other, f.tenant.ID, encodedImage(t, "png", size, size))
		if err != nil {
			t.Fatalf("SetLogo() unexpected error: %v", err)
		}
		return logo
	}
	check := func(when string, want store.Logo) {
		t.Helper()
		if got, err := TenantBranding(t.Context(), f.d, f.tenant.ID); err != nil || got.LogoHash != want.Hash {
			t.Errorf("%s: TenantBranding() = %+v, %v; want logo %s", when, got, err, want.Hash)
		}
		if got, err := TenantLogo(t.Context(), f.d, f.tenant.ID); err != nil || got.Hash != want.Hash {
			t.Errorf("%s: TenantLogo() = %s, %v; want %s", when, got.Hash, err, want.Hash)
		}
	}
	first := setLogo(2)
	// The branding is kept 20 seconds before the logo, so it expires first.
	if got, err := TenantBranding(t.Context(), f.d, f.tenant.ID); err != nil || got.LogoHash != first.Hash {
		t.Fatalf("TenantBranding() = %+v, %v; want logo %s", got, err, first.Hash)
	}
	*f.now = f.now.Add(20 * time.Second)
	if got, err := TenantLogo(t.Context(), f.d, f.tenant.ID); err != nil || got.Hash != first.Hash {
		t.Fatalf("TenantLogo() = %s, %v; want %s", got.Hash, err, first.Hash)
	}
	second := setLogo(3)
	*f.now = f.now.Add(TenantCacheTTL - 19*time.Second)
	check("the branding expired", second)

	// Now the logo is kept 20 seconds before the branding.
	*f.now = f.now.Add(TenantCacheTTL)
	if _, err := TenantLogo(t.Context(), f.d, f.tenant.ID); err != nil {
		t.Fatalf("TenantLogo() unexpected error: %v", err)
	}
	*f.now = f.now.Add(20 * time.Second)
	if _, err := TenantBranding(t.Context(), f.d, f.tenant.ID); err != nil {
		t.Fatalf("TenantBranding() unexpected error: %v", err)
	}
	third := setLogo(4)
	*f.now = f.now.Add(TenantCacheTTL - 19*time.Second)
	if got, err := TenantLogo(t.Context(), f.d, f.tenant.ID); err != nil || got.Hash != third.Hash {
		t.Fatalf("TenantLogo() after it expired = %s, %v; want %s", got.Hash, err, third.Hash)
	}
	check("the logo expired", third)
}

// A failed read is not kept, and without a Cache every read reaches the
// store.
func TestCacheKeepsNoFailuresAndNilKeepsNothing(t *testing.T) {
	t.Parallel()
	f := newCacheFixture(t)
	f.reads.setFailure(errUnavailable)
	if _, err := TenantBySlug(t.Context(), f.d, "acme"); !errors.Is(err, errUnavailable) {
		t.Fatalf("TenantBySlug() with a failing store = %v, want the store error", err)
	}
	f.reads.setFailure(nil)
	if _, err := TenantBySlug(t.Context(), f.d, "acme"); err != nil {
		t.Errorf("TenantBySlug() after the store recovered = %v, want the tenant", err)
	}

	f.d.Cache = nil
	f.reads.count("Tenants.GetBySlug")
	for range 3 {
		if _, err := TenantBySlug(t.Context(), f.d, "acme"); err != nil {
			t.Fatalf("TenantBySlug() without a Cache = %v", err)
		}
	}
	if n := f.reads.count("Tenants.GetBySlug"); n != 3 {
		t.Errorf("three lookups without a Cache read the store %d times, want 3", n)
	}
	var none *Cache
	none.forgetTenant(f.tenant)
	none.forgetSlug("acme")
	none.forgetResources(f.tenant.ID)
	none.forgetBranding(f.tenant.ID)
}

// An expiring map holds at most its bound; when full, it keeps no new entry
// until expired ones make room.
func TestExpiringIsBounded(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	e := newExpiring[string, int](2)
	put := func(k string, v int, now time.Time) {
		_, gen, _ := e.get(k, now)
		e.put(k, v, now, gen)
	}
	put("a", 1, start)
	put("b", 2, start)
	put("c", 3, start)
	if _, _, ok := e.get("c", start); ok {
		t.Error("an entry beyond the bound was kept")
	}
	put("a", 10, start)
	if v, _, ok := e.get("a", start); !ok || v != 10 {
		t.Errorf("get(a) after replacing it = %d, %v; want 10", v, ok)
	}
	later := start.Add(TenantCacheTTL)
	if _, _, ok := e.get("b", later); ok {
		t.Error("an expired entry was returned")
	}
	put("c", 3, later)
	if v, _, ok := e.get("c", later); !ok || v != 3 {
		t.Errorf("get(c) once expired entries made room = %d, %v; want 3", v, ok)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.entries) != 1 {
		t.Errorf("the map holds %d entries, want 1", len(e.entries))
	}
}

// A value loaded after a miss is not kept when forget was called since, and
// a nil expiring map keeps nothing.
func TestExpiringKeepsNoValueLoadedBeforeAForget(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	e := newExpiring[string, int](10)
	_, gen, _ := e.get("a", start)
	e.forget("b")
	e.put("a", 1, start, gen)
	if _, _, ok := e.get("a", start); ok {
		t.Error("a value loaded before a forget was kept")
	}
	_, gen, _ = e.get("a", start)
	e.put("a", 1, start, gen)
	if v, _, ok := e.get("a", start); !ok || v != 1 {
		t.Errorf("get(a) after a put = %d, %v; want 1", v, ok)
	}

	var none *expiring[string, int]
	none.put("a", 1, start, 0)
	none.forget("a")
	if _, _, ok := none.get("a", start); ok {
		t.Error("a nil map returned a value")
	}
}
