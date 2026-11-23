package clavis

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"net/http"
	"sync"
	"testing"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

// readCounter counts the reads of a store that requests repeat, by method.
type readCounter struct {
	store.Store
	mu    sync.Mutex
	reads map[string]int
}

func (c *readCounter) read(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads[method]++
}

// counts returns the reads so far and starts counting again.
func (c *readCounter) counts() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	reads := c.reads
	c.reads = make(map[string]int)
	return reads
}

func (c *readCounter) Tenants() store.Tenants {
	return countedTenants{c.Store.Tenants(), c}
}

func (c *readCounter) SigningKeys() store.SigningKeys {
	return countedKeys{c.Store.SigningKeys(), c}
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
	t.c.read("tenant")
	return t.Tenants.Get(ctx, id)
}

func (t countedTenants) GetBySlug(ctx context.Context, slug string) (store.Tenant, error) {
	t.c.read("tenant by slug")
	return t.Tenants.GetBySlug(ctx, slug)
}

type countedKeys struct {
	store.SigningKeys
	c *readCounter
}

func (k countedKeys) List(ctx context.Context, tenantID uuid.UUID) ([]store.SigningKey, error) {
	k.c.read("signing keys")
	return k.SigningKeys.List(ctx, tenantID)
}

type countedResources struct {
	store.APIResources
	c *readCounter
}

func (r countedResources) List(ctx context.Context, tenantID, after uuid.UUID, limit int) ([]store.APIResource, error) {
	r.c.read("API resources")
	return r.APIResources.List(ctx, tenantID, after, limit)
}

type countedBrandings struct {
	store.Brandings
	c *readCounter
}

func (b countedBrandings) Get(ctx context.Context, tenantID uuid.UUID) (store.Branding, error) {
	b.c.read("branding")
	return b.Brandings.Get(ctx, tenantID)
}

func (b countedBrandings) GetLogo(ctx context.Context, tenantID uuid.UUID) (store.Logo, error) {
	b.c.read("logo")
	return b.Brandings.GetLogo(ctx, tenantID)
}

// ADR 0031: repeated requests read what they share about a tenant once:
// the tenant, unknown slugs, signing keys, API resources, branding and the
// logo (from the reviews of #43, #52, #78 and #80).
func TestRequestsShareTheTenantCache(t *testing.T) {
	t.Parallel()
	reads := &readCounter{Store: openStore(t), reads: make(map[string]int)}
	s := newTestServer(t, reads)
	h := s.Handler()
	ctx := t.Context()
	tn, err := app.CreateTenant(ctx, s.deps, s.keys.Rotate, "acme", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatalf("encoding the logo: %v", err)
	}
	logo, err := app.SetLogo(ctx, s.deps, tn.ID, data.Bytes())
	if err != nil {
		t.Fatalf("SetLogo() unexpected error: %v", err)
	}
	if _, err := app.CreateAPIResource(ctx, s.deps, s.defaultTenant.ID, app.APIResourceSpec{
		Identifier: "https://api.example.com/orders", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	_, secret, err := app.CreateClient(ctx, s.deps, s.defaultTenant.ID, app.ClientSpec{
		ClientID: "service", Type: store.ClientConfidential, GrantTypes: []string{"client_credentials"},
		Scopes: []string{"orders:read"},
	})
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	service := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("service:"+secret))}}
	reads.counts()

	for range 3 {
		for _, path := range []string{
			"/.well-known/openid-configuration",
			"/t/acme/.well-known/openid-configuration",
			"/t/nobody/.well-known/openid-configuration",
			"/account/login",
			"/t/acme/account/login",
			"/t/acme/branding/logo-" + logo.Hash + ".png",
		} {
			if rec := serve(t, h, http.MethodGet, path); rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s = %d", path, rec.Code)
			}
		}
		rec := post(t, h, "/oauth2/token", formContentType, "grant_type=client_credentials", service)
		if rec.Code != http.StatusOK {
			t.Fatalf("token = %d %s", rec.Code, rec.Body.String())
		}
	}
	want := map[string]int{
		// The default tenant by ID; acme and nobody by slug.
		"tenant":         1,
		"tenant by slug": 2,
		"signing keys":   1,
		"API resources":  1,
		// Of the default tenant and acme.
		"branding": 2,
		"logo":     1,
	}
	got := reads.counts()
	for method, n := range want {
		if got[method] != n {
			t.Errorf("reads of %s = %d, want %d (all reads: %v)", method, got[method], n, got)
		}
	}
}
