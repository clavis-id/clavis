package app

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"uuid"
)

func TestAPIResources(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	d := newDeps(t, st)
	tn := newTenantForClients(t, d)

	orders, err := CreateAPIResource(t.Context(), d, tn.ID, APIResourceSpec{
		Identifier: "https://api.example.com/orders",
		Scopes:     []string{"orders:read", "orders:write", "orders:read"},
	})
	if err != nil {
		t.Fatalf("CreateAPIResource() unexpected error: %v", err)
	}
	if orders.Name != orders.Identifier || !slices.Equal(orders.Scopes, []string{"orders:read", "orders:write"}) ||
		!orders.CreatedAt.Equal(d.Now()) {
		t.Errorf("CreateAPIResource() = %+v", orders)
	}
	if _, err := CreateAPIResource(t.Context(), d, tn.ID, APIResourceSpec{
		Identifier: "urn:example:billing", Name: "Billing", Scopes: []string{"billing"},
	}); err != nil {
		t.Fatalf("CreateAPIResource(billing) unexpected error: %v", err)
	}

	tests := []struct {
		name string
		spec APIResourceSpec
		want error
	}{
		{"same identifier", APIResourceSpec{Identifier: orders.Identifier, Scopes: []string{"other"}}, ErrAPIResourceExists},
		{"relative identifier", APIResourceSpec{Identifier: "/orders", Scopes: []string{"x"}}, ErrInvalidAPIResource},
		{"no scopes", APIResourceSpec{Identifier: "https://x.example"}, ErrInvalidAPIResource},
		{"too many scopes", APIResourceSpec{Identifier: "https://x.example", Scopes: manyScopes(maxResourceScopes + 1)}, ErrInvalidAPIResource},
		{"invalid scope", APIResourceSpec{Identifier: "https://x.example", Scopes: []string{"a b"}}, ErrInvalidAPIResource},
		{"OpenID scope", APIResourceSpec{Identifier: "https://x.example", Scopes: []string{"email"}}, ErrInvalidAPIResource},
		{"offline_access", APIResourceSpec{Identifier: "https://x.example", Scopes: []string{"offline_access"}}, ErrInvalidAPIResource},
		{"scope of another resource", APIResourceSpec{Identifier: "https://x.example", Scopes: []string{"orders:read"}}, ErrInvalidAPIResource},
		{"control character in name", APIResourceSpec{Identifier: "https://x.example", Name: "a\nb", Scopes: []string{"x"}}, ErrInvalidAPIResource},
	}
	for _, tt := range tests {
		if _, err := CreateAPIResource(t.Context(), d, tn.ID, tt.spec); !errors.Is(err, tt.want) {
			t.Errorf("%s: CreateAPIResource() = %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, err := CreateAPIResource(t.Context(), d, uuid.NewV7(), APIResourceSpec{
		Identifier: "https://x.example", Scopes: []string{"x"},
	}); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("CreateAPIResource() in an unknown tenant = %v, want ErrTenantNotFound", err)
	}

	list, err := ListAPIResources(t.Context(), d, tn.ID)
	if err != nil || len(list) != 2 || list[0].ID != orders.ID {
		t.Errorf("ListAPIResources() = %v, %v", list, err)
	}
	if err := DeleteAPIResource(t.Context(), d, tn.ID, orders.Identifier); err != nil {
		t.Fatalf("DeleteAPIResource() unexpected error: %v", err)
	}
	if err := DeleteAPIResource(t.Context(), d, tn.ID, orders.Identifier); !errors.Is(err, ErrAPIResourceNotFound) {
		t.Errorf("second DeleteAPIResource() = %v, want ErrAPIResourceNotFound", err)
	}
	// Its scopes are free again.
	if _, err := CreateAPIResource(t.Context(), d, tn.ID, APIResourceSpec{
		Identifier: "https://api.example.com/v2/orders", Scopes: []string{"orders:read"},
	}); err != nil {
		t.Errorf("CreateAPIResource() with a released scope = %v, want nil", err)
	}
}

func manyScopes(n int) []string {
	scopes := make([]string, n)
	for i := range scopes {
		scopes[i] = "s" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	return scopes
}
