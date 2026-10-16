package keys

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"uuid"

	"github.com/go-jose/go-jose/v4"

	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	policy := DefaultPolicy()
	policy.Algorithms = []string{RS256, ES256, EdDSA}
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), policy)
	mustRotate(t, m, f.tenant.ID)

	for _, alg := range policy.Algorithms {
		token, err := m.Sign(t.Context(), f.tenant.ID, alg, "at+jwt", []byte(`{"sub":"ada"}`))
		if err != nil {
			t.Fatalf("Sign(%s) unexpected error: %v", alg, err)
		}
		obj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
		if err != nil {
			t.Fatalf("parsing the %s token: %v", alg, err)
		}
		if h := obj.Signatures[0].Header; h.KeyID != currentKIDFor(t, m, f.tenant.ID, alg) || h.ExtraHeaders[jose.HeaderType] != "at+jwt" {
			t.Errorf("%s header = %+v", alg, h)
		}
		payload, err := m.Verify(t.Context(), f.tenant.ID, token, "at+jwt")
		if err != nil || string(payload) != `{"sub":"ada"}` {
			t.Errorf("Verify(%s) = %q, %v", alg, payload, err)
		}
	}
}

func currentKIDFor(t *testing.T, m *Manager, tenantID uuid.UUID, alg string) string {
	t.Helper()
	s, err := m.Signer(t.Context(), tenantID, alg)
	if err != nil {
		t.Fatalf("Signer(%s) unexpected error: %v", alg, err)
	}
	return s.KeyID
}

func TestVerifyRejectsForeignAndAlteredTokens(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	mustRotate(t, m, f.tenant.ID)
	other := store.Tenant{ID: uuid.NewV7(), Slug: "other", Name: "Other", CreatedAt: f.clock.Now(), UpdatedAt: f.clock.Now()}
	if err := f.store.Tenants().Create(t.Context(), other); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	mustRotate(t, m, other.ID)

	sign := func(tenantID uuid.UUID, typ string) string {
		t.Helper()
		token, err := m.Sign(t.Context(), tenantID, RS256, typ, []byte(`{"sub":"ada"}`))
		if err != nil {
			t.Fatalf("Sign() unexpected error: %v", err)
		}
		return token
	}
	valid := sign(f.tenant.ID, "at+jwt")
	if _, err := m.Verify(t.Context(), f.tenant.ID, sign(f.tenant.ID, "application/AT+JWT"), "at+jwt"); err != nil {
		t.Errorf("Verify() of a typ with the application prefix = %v, want nil", err)
	}

	parts := strings.Split(valid, ".")
	altered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"eve"}`)) + "." + parts[2]
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + "." + parts[1] + "."
	for name, token := range map[string]string{
		"other tenant":  sign(other.ID, "at+jwt"),
		"other type":    sign(f.tenant.ID, "JWT"),
		"no type":       sign(f.tenant.ID, ""),
		"altered":       altered,
		"unsigned":      unsigned,
		"not a JWS":     "abc",
		"two parts":     parts[0] + "." + parts[1],
		"JSON encoding": `{"payload":"e30","signatures":[]}`,
	} {
		if _, err := m.Verify(t.Context(), f.tenant.ID, token, "at+jwt"); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: Verify() = %v, want ErrInvalidToken", name, err)
		}
	}

	// An algorithm outside the policy is refused even with a valid key.
	es := DefaultPolicy()
	es.Algorithms = []string{RS256, ES256}
	m2 := f.manager(t, newEncrypter(t, kek.GenerateSecret()), es)
	third := store.Tenant{ID: uuid.NewV7(), Slug: "third", Name: "Third", CreatedAt: f.clock.Now(), UpdatedAt: f.clock.Now()}
	if err := f.store.Tenants().Create(t.Context(), third); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	mustRotate(t, m2, third.ID)
	token, err := m2.Sign(t.Context(), third.ID, ES256, "at+jwt", []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign(ES256) unexpected error: %v", err)
	}
	if _, err := m.Verify(t.Context(), third.ID, token, "at+jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify() of an ES256 token with an RS256-only policy = %v, want ErrInvalidToken", err)
	}

	// A token outlives its key only until the key expires.
	f.clock.Advance(DefaultPolicy().RotationPeriod + DefaultPolicy().Retention + DefaultPolicy().PublishAhead)
	if _, err := m.Verify(t.Context(), f.tenant.ID, valid, "at+jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify() after the key expired = %v, want ErrInvalidToken", err)
	}
}

func TestSignWithoutActiveKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	if _, err := m.Sign(t.Context(), f.tenant.ID, RS256, "JWT", []byte(`{}`)); !errors.Is(err, ErrNoActiveKey) {
		t.Errorf("Sign() before any rotation = %v, want ErrNoActiveKey", err)
	}
}

func TestVerifyAcceptsOnlyTheCompactSerialization(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	mustRotate(t, m, f.tenant.ID)
	token, err := m.Sign(t.Context(), f.tenant.ID, RS256, "at+jwt", []byte(`{"sub":"ada"}`))
	if err != nil {
		t.Fatalf("Sign() unexpected error: %v", err)
	}
	// The same signature in the flattened JSON serialization (RFC 7515,
	// section 7.2.2), which can carry unsigned headers.
	parts := strings.Split(token, ".")
	flattened := `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] +
		`","header":{"kid":"other"}}`
	if _, err := m.Verify(t.Context(), f.tenant.ID, flattened, "at+jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify() of the JSON serialization = %v, want ErrInvalidToken", err)
	}
}
