package app

import (
	"sync"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
)

// TenantCacheTTL is how long a Cache keeps what it reads about a tenant
// (ADR 0031). A change made by another process, such as the command line or
// another instance, applies within it.
const TenantCacheTTL = 30 * time.Second

// Bounds of a Cache. Beyond them it reads the store without keeping the
// result. Logos have their own bound, since each takes up to MaxLogoBytes.
const (
	maxCachedEntries = 10000
	maxCachedLogos   = 64
)

// Cache keeps, for TenantCacheTTL, what requests read about a tenant on
// their way: the tenant, by ID and by slug, and the slugs of no tenant; its
// API resources; its branding; and its logo (ADR 0031). A use case that
// changes one of them forgets it at once in the Cache of its Deps. A nil
// *Cache keeps nothing, so every read reaches the store. Kept values are
// shared, so callers must not change them.
type Cache struct {
	tenants *expiring[uuid.UUID, store.Tenant]
	slugs   *expiring[string, store.Tenant]
	// unknownSlugs has a bound of its own, so that requests for many slugs
	// of no tenant cannot crowd out the tenants.
	unknownSlugs *expiring[string, struct{}]
	resources    *expiring[uuid.UUID, []store.APIResource]
	brandings    *expiring[uuid.UUID, store.Branding]
	logos        *expiring[uuid.UUID, cachedLogo]
}

// cachedLogo is the logo of a tenant, or no logo.
type cachedLogo struct {
	logo  store.Logo
	found bool
}

// hash returns the hash of the logo, or "" for no logo, as a branding
// names it.
func (l cachedLogo) hash() string {
	if !l.found {
		return ""
	}
	return l.logo.Hash
}

// NewCache returns an empty Cache.
func NewCache() *Cache {
	return newCache(maxCachedEntries, maxCachedLogos)
}

func newCache(maxEntries, maxLogos int) *Cache {
	return &Cache{
		tenants:      newExpiring[uuid.UUID, store.Tenant](maxEntries),
		slugs:        newExpiring[string, store.Tenant](maxEntries),
		unknownSlugs: newExpiring[string, struct{}](maxEntries),
		resources:    newExpiring[uuid.UUID, []store.APIResource](maxEntries),
		brandings:    newExpiring[uuid.UUID, store.Branding](maxEntries),
		logos:        newExpiring[uuid.UUID, cachedLogo](maxLogos),
	}
}

// The accessors return nil for a nil Cache, which cached reads through.

func (c *Cache) tenantMap() *expiring[uuid.UUID, store.Tenant] {
	if c == nil {
		return nil
	}
	return c.tenants
}

func (c *Cache) slugMap() *expiring[string, store.Tenant] {
	if c == nil {
		return nil
	}
	return c.slugs
}

func (c *Cache) unknownSlugMap() *expiring[string, struct{}] {
	if c == nil {
		return nil
	}
	return c.unknownSlugs
}

func (c *Cache) resourceMap() *expiring[uuid.UUID, []store.APIResource] {
	if c == nil {
		return nil
	}
	return c.resources
}

func (c *Cache) brandingMap() *expiring[uuid.UUID, store.Branding] {
	if c == nil {
		return nil
	}
	return c.brandings
}

func (c *Cache) logoMap() *expiring[uuid.UUID, cachedLogo] {
	if c == nil {
		return nil
	}
	return c.logos
}

// forgetTenant forgets t, under its ID and its slug, and what it owns.
func (c *Cache) forgetTenant(t store.Tenant) {
	if c == nil {
		return
	}
	c.tenants.forget(t.ID)
	c.forgetSlug(t.Slug)
	c.forgetResources(t.ID)
	c.forgetBranding(t.ID)
}

// forgetSlug forgets what is kept under slug, such as that no tenant has it.
func (c *Cache) forgetSlug(slug string) {
	if c != nil {
		c.slugs.forget(slug)
		c.unknownSlugs.forget(slug)
	}
}

// forgetResources forgets the API resources of a tenant.
func (c *Cache) forgetResources(tenantID uuid.UUID) {
	if c != nil {
		c.resources.forget(tenantID)
	}
}

// forgetBranding forgets the branding and the logo of a tenant.
func (c *Cache) forgetBranding(tenantID uuid.UUID) {
	if c != nil {
		c.brandings.forget(tenantID)
		c.logos.forget(tenantID)
	}
}

// cached returns the value of k in e, or loads it and keeps it in e for
// TenantCacheTTL when load succeeds. A nil e keeps nothing.
func cached[K comparable, V any](e *expiring[K, V], k K, now time.Time, load func() (V, error)) (V, error) {
	v, gen, ok := e.get(k, now)
	if ok {
		return v, nil
	}
	v, err := load()
	if err == nil {
		e.put(k, v, now, gen)
	}
	return v, err
}

// expiring maps keys to values that expire after TenantCacheTTL. It holds at
// most max entries: when it is full, it removes the expired ones, at most
// once per TenantCacheTTL, and keeps no new entry while it is still full. A
// nil *expiring keeps nothing.
type expiring[K comparable, V any] struct {
	mu      sync.Mutex
	max     int
	entries map[K]expiringValue[V]
	sweep   time.Time
	// gen counts the calls to forget. A value loaded after a miss is kept
	// only when gen is still what the miss returned, so that a value read
	// before a change is not kept after the change forgot it.
	gen uint64
}

type expiringValue[V any] struct {
	value   V
	expires time.Time
}

func newExpiring[K comparable, V any](maxEntries int) *expiring[K, V] {
	return &expiring[K, V]{max: maxEntries, entries: make(map[K]expiringValue[V])}
}

// get returns the value of k, or false and the generation to pass to put
// with a value loaded after the miss.
func (e *expiring[K, V]) get(k K, now time.Time) (value V, gen uint64, ok bool) {
	if e == nil {
		return value, 0, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.entries[k]
	if !ok || !now.Before(v.expires) {
		return value, e.gen, false
	}
	return v.value, e.gen, true
}

// put keeps v under k, unless forget was called since the get that
// returned gen.
func (e *expiring[K, V]) put(k K, v V, now time.Time, gen uint64) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if gen != e.gen {
		return
	}
	if _, ok := e.entries[k]; !ok && len(e.entries) >= e.max {
		if now.Before(e.sweep) {
			return
		}
		for key, old := range e.entries {
			if !now.Before(old.expires) {
				delete(e.entries, key)
			}
		}
		e.sweep = now.Add(TenantCacheTTL)
		if len(e.entries) >= e.max {
			return
		}
	}
	e.entries[k] = expiringValue[V]{value: v, expires: now.Add(TenantCacheTTL)}
}

func (e *expiring[K, V]) forget(k K) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.entries, k)
	e.gen++
}
