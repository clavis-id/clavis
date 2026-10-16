package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// newTenantForClients creates a tenant to hold the clients of a test.
func newTenantForClients(t *testing.T, d Deps) store.Tenant {
	t.Helper()
	var keys keyRecorder
	tn, err := CreateTenant(t.Context(), d, keys.create, "acme", "")
	if err != nil {
		t.Fatalf("CreateTenant() unexpected error: %v", err)
	}
	return tn
}

func webAppSpec() ClientSpec {
	return ClientSpec{
		ClientID:     "web-app",
		Type:         store.ClientConfidential,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
}

func TestCreateConfidentialClient(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	d := newDeps(t, st)
	tn := newTenantForClients(t, d)

	got, secret, err := CreateClient(t.Context(), d, tn.ID, webAppSpec())
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	want := store.Client{
		ID:           got.ID,
		TenantID:     tn.ID,
		ClientID:     "web-app",
		Name:         "web-app",
		Type:         store.ClientConfidential,
		SecretHash:   got.SecretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		CreatedAt:    d.Now(),
		UpdatedAt:    d.Now(),
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("CreateClient() mismatch (-want +got):\n%s", diff)
	}
	if !oauth.ClientSecretMatches(got.SecretHash, secret) {
		t.Error("the returned secret does not match the stored hash")
	}
	stored, err := st.Clients().GetByClientID(t.Context(), tn.ID, "web-app")
	if err != nil {
		t.Fatalf("client not stored: %v", err)
	}
	if diff := cmp.Diff(got, stored, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("stored client mismatch (-returned +stored):\n%s", diff)
	}
}

func TestCreatePublicClientHasNoSecret(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)

	spec := webAppSpec()
	spec.Type = store.ClientPublic
	got, secret, err := CreateClient(t.Context(), d, tn.ID, spec)
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if secret != "" || got.SecretHash != nil {
		t.Errorf("public client got secret %q and hash %x, want neither", secret, got.SecretHash)
	}
}

func TestCreateClientGeneratesClientID(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)

	spec := webAppSpec()
	spec.ClientID = ""
	spec.Name = "Web app"
	got, _, err := CreateClient(t.Context(), d, tn.ID, spec)
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if len(got.ClientID) != 26 || oauth.ValidateClientID(got.ClientID) != nil {
		t.Errorf("generated client ID %q, want 26 valid characters", got.ClientID)
	}
	if got.Name != "Web app" {
		t.Errorf("Name = %q, want the given name", got.Name)
	}
}

func TestCreateClientDefaultScopes(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)

	tests := []struct {
		clientID   string
		grantTypes []string
		redirect   bool
		want       []string
	}{
		{"code-only", []string{"authorization_code"}, true, []string{"openid", "profile", "email"}},
		{"code-and-refresh", []string{"authorization_code", "refresh_token"}, true,
			[]string{"openid", "profile", "email", "offline_access"}},
		{"machine", []string{"client_credentials"}, false, nil},
	}
	for _, tt := range tests {
		spec := ClientSpec{ClientID: tt.clientID, Type: store.ClientConfidential, GrantTypes: tt.grantTypes}
		if tt.redirect {
			spec.RedirectURIs = []string{"https://app.example.com/callback"}
		}
		got, _, err := CreateClient(t.Context(), d, tn.ID, spec)
		if err != nil {
			t.Fatalf("%s: CreateClient() unexpected error: %v", tt.clientID, err)
		}
		if diff := cmp.Diff(tt.want, got.Scopes, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("%s: scopes mismatch (-want +got):\n%s", tt.clientID, diff)
		}
	}
}

func TestCreateClientKeepsSettingsAndRemovesDuplicates(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)

	spec := ClientSpec{
		ClientID:               "web-app",
		Name:                   "Web app",
		Type:                   store.ClientConfidential,
		RedirectURIs:           []string{"https://a.example.com/cb", "https://b.example.com/cb", "https://a.example.com/cb"},
		PostLogoutRedirectURIs: []string{"https://a.example.com/", "https://a.example.com/"},
		GrantTypes:             []string{"authorization_code", "client_credentials", "authorization_code"},
		Scopes:                 []string{"openid", "orders:read", "openid"},
		Lifetimes: store.TokenLifetimes{
			AccessToken:          time.Minute,
			IDToken:              24 * time.Hour,
			RefreshTokenIdle:     time.Hour,
			RefreshTokenAbsolute: time.Hour,
		},
		SkipConsent: true,
		PKCEExempt:  true,
	}
	got, _, err := CreateClient(t.Context(), d, tn.ID, spec)
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	want := spec
	want.RedirectURIs = []string{"https://a.example.com/cb", "https://b.example.com/cb"}
	want.PostLogoutRedirectURIs = []string{"https://a.example.com/"}
	want.GrantTypes = []string{"authorization_code", "client_credentials"}
	want.Scopes = []string{"openid", "orders:read"}
	gotSpec := ClientSpec{
		ClientID: got.ClientID, Name: got.Name, Type: got.Type, RedirectURIs: got.RedirectURIs,
		PostLogoutRedirectURIs: got.PostLogoutRedirectURIs, GrantTypes: got.GrantTypes, Scopes: got.Scopes,
		Lifetimes: got.Lifetimes, SkipConsent: got.SkipConsent, PKCEExempt: got.PKCEExempt,
	}
	if diff := cmp.Diff(want, gotSpec); diff != "" {
		t.Errorf("CreateClient() settings mismatch (-want +got):\n%s", diff)
	}
}

func TestCreateClientRejections(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)
	if _, _, err := CreateClient(t.Context(), d, tn.ID, webAppSpec()); err != nil {
		t.Fatalf("creating the first client: %v", err)
	}

	tests := []struct {
		name   string
		modify func(*ClientSpec)
		want   error
	}{
		{"duplicate client ID", func(s *ClientSpec) { s.ClientID = "web-app" }, ErrClientExists},
		{"invalid client ID", func(s *ClientSpec) { s.ClientID = "-web" }, ErrInvalidClientMetadata},
		{"client ID with a colon", func(s *ClientSpec) { s.ClientID = "web:app" }, ErrInvalidClientMetadata},
		{"control character in name", func(s *ClientSpec) { s.Name = "Web\napp" }, ErrInvalidClientMetadata},
		{"bidirectional override in name", func(s *ClientSpec) { s.Name = "Web\u202Eppa" }, ErrInvalidClientMetadata},
		{"name too long", func(s *ClientSpec) { s.Name = strings.Repeat("x", MaxNameLength+1) }, ErrInvalidClientMetadata},
		{"missing type", func(s *ClientSpec) { s.Type = "" }, ErrInvalidClientMetadata},
		{"unknown type", func(s *ClientSpec) { s.Type = "trusted" }, ErrInvalidClientMetadata},
		{"unknown grant type", func(s *ClientSpec) { s.GrantTypes = []string{"password"} }, ErrInvalidClientMetadata},
		{"implicit grant", func(s *ClientSpec) { s.GrantTypes = []string{"implicit"} }, ErrInvalidClientMetadata},
		{"refresh without code", func(s *ClientSpec) {
			s.GrantTypes = []string{"client_credentials", "refresh_token"}
			s.RedirectURIs = nil
		}, ErrInvalidClientMetadata},
		{"client credentials for a public client", func(s *ClientSpec) {
			s.Type = store.ClientPublic
			s.GrantTypes = []string{"authorization_code", "client_credentials"}
		}, ErrInvalidClientMetadata},
		{"code flow without redirect URIs", func(s *ClientSpec) { s.RedirectURIs = nil }, ErrInvalidRedirectURI},
		{"redirect URIs without the code flow", func(s *ClientSpec) {
			s.GrantTypes = []string{"client_credentials"}
		}, ErrInvalidRedirectURI},
		{"post-logout URIs without the code flow", func(s *ClientSpec) {
			s.GrantTypes = []string{"client_credentials"}
			s.RedirectURIs = nil
			s.PostLogoutRedirectURIs = []string{"https://app.example.com/"}
		}, ErrInvalidRedirectURI},
		{"invalid redirect URI", func(s *ClientSpec) {
			s.RedirectURIs = []string{"http://app.example.com/callback"}
		}, oauth.ErrInvalidRedirectURI},
		{"invalid post-logout redirect URI", func(s *ClientSpec) {
			s.PostLogoutRedirectURIs = []string{"https://app.example.com/#x"}
		}, ErrInvalidRedirectURI},
		{"too many redirect URIs", func(s *ClientSpec) {
			s.RedirectURIs = nil
			for i := range MaxRedirectURIs + 1 {
				s.RedirectURIs = append(s.RedirectURIs, "https://app.example.com/"+strings.Repeat("x", i))
			}
		}, ErrInvalidRedirectURI},
		{"invalid scope", func(s *ClientSpec) { s.Scopes = []string{`a"b`} }, oauth.ErrInvalidScope},
		{"too many scopes", func(s *ClientSpec) {
			for i := range MaxScopes + 1 {
				s.Scopes = append(s.Scopes, "scope"+strings.Repeat("x", i))
			}
		}, ErrInvalidClientMetadata},
		{"access token lifetime too short", func(s *ClientSpec) { s.Lifetimes.AccessToken = time.Second }, ErrInvalidClientMetadata},
		{"access token lifetime too long", func(s *ClientSpec) { s.Lifetimes.AccessToken = 25 * time.Hour }, ErrInvalidClientMetadata},
		{"negative ID token lifetime", func(s *ClientSpec) { s.Lifetimes.IDToken = -time.Minute }, ErrInvalidClientMetadata},
		{"fractional lifetime", func(s *ClientSpec) { s.Lifetimes.IDToken = time.Minute + time.Millisecond }, ErrInvalidClientMetadata},
		{"refresh lifetime too short", func(s *ClientSpec) { s.Lifetimes.RefreshTokenIdle = time.Minute }, ErrInvalidClientMetadata},
		{"refresh lifetime too long", func(s *ClientSpec) {
			s.Lifetimes.RefreshTokenAbsolute = 366 * 24 * time.Hour
		}, ErrInvalidClientMetadata},
		{"idle lifetime above absolute", func(s *ClientSpec) {
			s.Lifetimes.RefreshTokenIdle = 2 * time.Hour
			s.Lifetimes.RefreshTokenAbsolute = time.Hour
		}, ErrInvalidClientMetadata},
		{"PKCE exemption for a public client", func(s *ClientSpec) {
			s.Type = store.ClientPublic
			s.PKCEExempt = true
		}, ErrInvalidClientMetadata},
		{"PKCE exemption without the code flow", func(s *ClientSpec) {
			s.GrantTypes = []string{"client_credentials"}
			s.RedirectURIs = nil
			s.PKCEExempt = true
		}, ErrInvalidClientMetadata},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := webAppSpec()
			spec.ClientID = "other"
			tt.modify(&spec)
			if _, _, err := CreateClient(t.Context(), d, tn.ID, spec); !errors.Is(err, tt.want) {
				t.Errorf("CreateClient() = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestCreateClientRejectsHugeListsQuickly guards against work that grows
// faster than the input: the lists are deduplicated before their size limits
// apply, and the admin API will pass them from request bodies.
func TestCreateClientRejectsHugeListsQuickly(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)

	const n = 200_000 // A quadratic deduplication takes minutes.
	spec := webAppSpec()
	spec.RedirectURIs = make([]string, n)
	spec.Scopes = make([]string, n)
	for i := range n {
		spec.RedirectURIs[i] = "https://app.example.com/" + strconv.Itoa(i)
		spec.Scopes[i] = "scope" + strconv.Itoa(i)
	}
	if _, _, err := CreateClient(t.Context(), d, tn.ID, spec); !errors.Is(err, ErrInvalidRedirectURI) {
		t.Errorf("CreateClient() = %v, want ErrInvalidRedirectURI", err)
	}
	spec.RedirectURIs = []string{"https://app.example.com/callback"}
	if _, _, err := CreateClient(t.Context(), d, tn.ID, spec); !errors.Is(err, ErrInvalidClientMetadata) {
		t.Errorf("CreateClient() = %v, want ErrInvalidClientMetadata", err)
	}
}

func TestCreateClientInUnknownTenant(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	if _, _, err := CreateClient(t.Context(), d, uuid.NewV7(), webAppSpec()); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("CreateClient() = %v, want ErrTenantNotFound", err)
	}
}

func TestCreateClientWarnsAboutPKCEExemption(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	var logs bytes.Buffer
	d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	tn := newTenantForClients(t, d)

	spec := webAppSpec()
	spec.PKCEExempt = true
	if _, _, err := CreateClient(t.Context(), d, tn.ID, spec); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="created client that is exempt from PKCE"`) ||
		!strings.Contains(logs.String(), "client_id=web-app") {
		t.Errorf("logs do not warn about the PKCE exemption:\n%s", logs.String())
	}
}

func TestGetClient(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)
	created, _, err := CreateClient(t.Context(), d, tn.ID, webAppSpec())
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	got, err := GetClient(t.Context(), d, tn.ID, "web-app")
	if err != nil || got.ID != created.ID {
		t.Errorf("GetClient(web-app) = %v, %v; want client %v", got.ID, err, created.ID)
	}
	for _, clientID := range []string{"missing", "WEB-APP", "", "web app"} {
		if _, err := GetClient(t.Context(), d, tn.ID, clientID); !errors.Is(err, ErrClientNotFound) {
			t.Errorf("GetClient(%q) = %v, want ErrClientNotFound", clientID, err)
		}
	}
	if _, err := GetClient(t.Context(), d, uuid.NewV7(), "web-app"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("GetClient() in another tenant = %v, want ErrClientNotFound", err)
	}
}

func TestListClients(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)
	for _, clientID := range []string{"one", "two", "three"} {
		spec := webAppSpec()
		spec.ClientID = clientID
		if _, _, err := CreateClient(t.Context(), d, tn.ID, spec); err != nil {
			t.Fatalf("CreateClient(%q) unexpected error: %v", clientID, err)
		}
	}
	got, err := ListClients(t.Context(), d, tn.ID)
	if err != nil {
		t.Fatalf("ListClients() unexpected error: %v", err)
	}
	var ids []string
	for _, c := range got {
		ids = append(ids, c.ClientID)
	}
	if strings.Join(ids, ",") != "one,two,three" {
		t.Errorf("ListClients() client IDs = %v, want creation order", ids)
	}
}

// pagedClients serves List from a fixed slice, to test paging without
// creating thousands of records.
type pagedClients struct {
	store.Clients
	all []store.Client
}

func (p pagedClients) List(_ context.Context, _, after uuid.UUID, limit int) ([]store.Client, error) {
	start := 0
	for i, c := range p.all {
		if c.ID == after {
			start = i + 1
		}
	}
	return p.all[start:min(start+limit, len(p.all))], nil
}

type pagedClientStore struct {
	store.Store
	clients pagedClients
}

func (p pagedClientStore) Clients() store.Clients { return p.clients }

func TestListClientsReadsEveryPage(t *testing.T) {
	t.Parallel()
	all := make([]store.Client, store.MaxPageSize+1)
	for i := range all {
		all[i] = store.Client{ID: uuid.NewV7()}
	}
	d := newDeps(t, pagedClientStore{clients: pagedClients{all: all}})
	got, err := ListClients(t.Context(), d, uuid.NewV7())
	if err != nil {
		t.Fatalf("ListClients() unexpected error: %v", err)
	}
	if len(got) != len(all) {
		t.Errorf("ListClients() returned %d clients, want %d", len(got), len(all))
	}
}

func TestRotateClientSecret(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	d := newDeps(t, st)
	tn := newTenantForClients(t, d)
	_, oldSecret, err := CreateClient(t.Context(), d, tn.ID, webAppSpec())
	if err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}

	later := d.Now().Add(time.Hour)
	d.Now = func() time.Time { return later }
	newSecret, err := RotateClientSecret(t.Context(), d, tn.ID, "web-app")
	if err != nil {
		t.Fatalf("RotateClientSecret() unexpected error: %v", err)
	}
	stored, err := st.Clients().GetByClientID(t.Context(), tn.ID, "web-app")
	if err != nil {
		t.Fatalf("GetByClientID() unexpected error: %v", err)
	}
	if !oauth.ClientSecretMatches(stored.SecretHash, newSecret) {
		t.Error("the new secret does not match the stored hash")
	}
	if oauth.ClientSecretMatches(stored.SecretHash, oldSecret) {
		t.Error("the old secret still matches after rotation")
	}
	if !stored.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", stored.UpdatedAt, later)
	}

	public := webAppSpec()
	public.ClientID, public.Type = "spa", store.ClientPublic
	if _, _, err := CreateClient(t.Context(), d, tn.ID, public); err != nil {
		t.Fatalf("CreateClient(spa) unexpected error: %v", err)
	}
	if _, err := RotateClientSecret(t.Context(), d, tn.ID, "spa"); !errors.Is(err, ErrPublicClient) {
		t.Errorf("RotateClientSecret(spa) = %v, want ErrPublicClient", err)
	}
	if _, err := RotateClientSecret(t.Context(), d, tn.ID, "missing"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("RotateClientSecret(missing) = %v, want ErrClientNotFound", err)
	}
}

func TestDeleteClient(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)
	if _, _, err := CreateClient(t.Context(), d, tn.ID, webAppSpec()); err != nil {
		t.Fatalf("CreateClient() unexpected error: %v", err)
	}
	if err := DeleteClient(t.Context(), d, tn.ID, "web-app"); err != nil {
		t.Fatalf("DeleteClient() unexpected error: %v", err)
	}
	if _, err := GetClient(t.Context(), d, tn.ID, "web-app"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("GetClient() after DeleteClient() = %v, want ErrClientNotFound", err)
	}
	if err := DeleteClient(t.Context(), d, tn.ID, "web-app"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("second DeleteClient() = %v, want ErrClientNotFound", err)
	}
}

func TestFindTenant(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	def, err := EnsureDefaultTenant(t.Context(), d)
	if err != nil {
		t.Fatalf("EnsureDefaultTenant() unexpected error: %v", err)
	}
	// Unlike TenantBySlug, FindTenant also finds the default tenant.
	if got, err := FindTenant(t.Context(), d, DefaultTenantSlug); err != nil || got.ID != def.ID {
		t.Errorf("FindTenant(default) = %v, %v; want %v", got.ID, err, def.ID)
	}
	if _, err := FindTenant(t.Context(), d, "missing"); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("FindTenant(missing) = %v, want ErrTenantNotFound", err)
	}
	if _, err := FindTenant(t.Context(), newDeps(t, failingStore{}), "acme"); !errors.Is(err, errUnavailable) {
		t.Errorf("FindTenant() with a failing store = %v, want the store error", err)
	}
}
