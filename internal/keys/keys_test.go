package keys

import (
	"bytes"
	"crypto/x509"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"

	"github.com/clavis-id/clavis/kek"
	"github.com/clavis-id/clavis/store"
	"github.com/clavis-id/clavis/store/sqlite"
)

// clock is a manually advanced time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	store  *sqlite.Store
	clock  *clock
	tenant store.Tenant
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "clavis.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	c := newClock()
	tn := store.Tenant{ID: uuid.NewV7(), Slug: "acme", Name: "Acme", CreatedAt: c.Now(), UpdatedAt: c.Now()}
	if err := s.Tenants().Create(t.Context(), tn); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	return &fixture{store: s, clock: c, tenant: tn}
}

func (f *fixture) manager(t *testing.T, enc kek.Encrypter, policy Policy) *Manager {
	t.Helper()
	m, err := NewManager(Config{
		Store:     f.store,
		Encrypter: enc,
		Policy:    policy,
		Logger:    slog.New(slog.DiscardHandler),
		Now:       f.clock.Now,
		NewID:     uuid.NewV7,
	})
	if err != nil {
		t.Fatalf("NewManager() unexpected error: %v", err)
	}
	return m
}

func newEncrypter(t *testing.T, primary []byte, previous ...[]byte) *kek.Local {
	t.Helper()
	l, err := kek.NewLocal(primary, previous...)
	if err != nil {
		t.Fatalf("kek.NewLocal() unexpected error: %v", err)
	}
	return l
}

func mustRotate(t *testing.T, m *Manager, tenantID uuid.UUID) {
	t.Helper()
	if err := m.Rotate(t.Context(), tenantID); err != nil {
		t.Fatalf("Rotate() unexpected error: %v", err)
	}
}

func kids(t *testing.T, m *Manager, tenantID uuid.UUID) []string {
	t.Helper()
	set, err := m.JWKS(t.Context(), tenantID)
	if err != nil {
		t.Fatalf("JWKS() unexpected error: %v", err)
	}
	out := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

func currentKID(t *testing.T, m *Manager, tenantID uuid.UUID) string {
	t.Helper()
	s, err := m.Signer(t.Context(), tenantID, RS256)
	if err != nil {
		t.Fatalf("Signer() unexpected error: %v", err)
	}
	return s.KeyID
}

func TestSignaturesVerifyAgainstPublishedKeys(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	policy := DefaultPolicy()
	policy.Algorithms = []string{RS256, ES256, EdDSA}
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), policy)
	mustRotate(t, m, f.tenant.ID)

	jwks, err := m.JWKS(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("JWKS() unexpected error: %v", err)
	}
	if len(jwks.Keys) != 3 {
		t.Fatalf("JWKS() has %d keys, want one per algorithm", len(jwks.Keys))
	}

	for _, alg := range policy.Algorithms {
		t.Run(alg, func(t *testing.T) {
			signer, err := m.Signer(t.Context(), f.tenant.ID, alg)
			if err != nil {
				t.Fatalf("Signer() unexpected error: %v", err)
			}
			js, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(alg),
				Key:       jose.JSONWebKey{Key: signer.Key, KeyID: signer.KeyID},
			}, nil)
			if err != nil {
				t.Fatalf("jose.NewSigner() unexpected error: %v", err)
			}
			sig, err := js.Sign([]byte("payload"))
			if err != nil {
				t.Fatalf("Sign() unexpected error: %v", err)
			}
			compact, err := sig.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize() unexpected error: %v", err)
			}

			parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
			if err != nil {
				t.Fatalf("ParseSigned() unexpected error: %v", err)
			}
			published := jwks.Key(parsed.Signatures[0].Header.KeyID)
			if len(published) != 1 {
				t.Fatalf("kid %q matches %d published keys, want 1", signer.KeyID, len(published))
			}
			if published[0].Algorithm != alg || published[0].Use != "sig" || !published[0].IsPublic() {
				t.Errorf("published key = alg %q use %q public %v", published[0].Algorithm, published[0].Use, published[0].IsPublic())
			}
			if _, err := parsed.Verify(published[0]); err != nil {
				t.Errorf("signature does not verify with the published key: %v", err)
			}
		})
	}
}

func TestRotationLifecycle(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	policy := DefaultPolicy() // 30 days, published 24h ahead, retained 48h
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), policy)

	mustRotate(t, m, f.tenant.ID)
	first := currentKID(t, m, f.tenant.ID)

	// Just before the publish-ahead window: nothing changes.
	f.clock.Advance(policy.RotationPeriod - policy.PublishAhead - time.Second)
	mustRotate(t, m, f.tenant.ID)
	if got := kids(t, m, f.tenant.ID); len(got) != 1 {
		t.Fatalf("published keys = %v, want only the first key", got)
	}

	// Entering the window: the successor is published but does not sign yet.
	f.clock.Advance(time.Second)
	mustRotate(t, m, f.tenant.ID)
	published := kids(t, m, f.tenant.ID)
	if len(published) != 2 || published[0] != first {
		t.Fatalf("published keys = %v, want the first key and its successor", published)
	}
	second := published[1]
	if got := currentKID(t, m, f.tenant.ID); got != first {
		t.Errorf("signing key before the switch = %q, want %q", got, first)
	}
	mustRotate(t, m, f.tenant.ID) // idempotent while the successor is pending
	if got := kids(t, m, f.tenant.ID); len(got) != 2 {
		t.Errorf("a second rotation in the window published %v", got)
	}

	// At the scheduled switch the successor signs and the first key remains
	// published for verification.
	f.clock.Advance(policy.PublishAhead)
	if got := currentKID(t, m, f.tenant.ID); got != second {
		t.Errorf("signing key after the switch = %q, want %q", got, second)
	}
	if got := kids(t, m, f.tenant.ID); len(got) != 2 {
		t.Errorf("published keys right after the switch = %v, want both", got)
	}

	// After the retention period the first key disappears.
	f.clock.Advance(policy.Retention)
	if err := m.RotateAll(t.Context()); err != nil {
		t.Fatalf("RotateAll() unexpected error: %v", err)
	}
	if got := kids(t, m, f.tenant.ID); len(got) != 1 || got[0] != second {
		t.Errorf("published keys after retention = %v, want only %q", got, second)
	}
	stored, err := f.store.SigningKeys().List(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("listing stored keys: %v", err)
	}
	if len(stored) != 1 {
		t.Errorf("store holds %d keys after cleanup, want 1", len(stored))
	}
}

func TestRecoveryAfterOutage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	mustRotate(t, m, f.tenant.ID)
	stale := currentKID(t, m, f.tenant.ID)

	f.clock.Advance(90 * 24 * time.Hour)
	if _, err := m.Signer(t.Context(), f.tenant.ID, RS256); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Signer() after the outage error = %v, want ErrNoActiveKey", err)
	}
	mustRotate(t, m, f.tenant.ID)
	fresh := currentKID(t, m, f.tenant.ID)
	if fresh == stale {
		t.Error("rotation after the outage reused the stale key")
	}
	if got := kids(t, m, f.tenant.ID); len(got) != 1 || got[0] != fresh {
		t.Errorf("published keys = %v, want only the fresh key %q", got, fresh)
	}
}

func TestConcurrentManagersAgree(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enc := newEncrypter(t, kek.GenerateSecret())
	managers := []*Manager{
		f.manager(t, enc, DefaultPolicy()),
		f.manager(t, enc, DefaultPolicy()),
		f.manager(t, enc, DefaultPolicy()),
	}

	var wg sync.WaitGroup
	errs := make([]error, len(managers))
	for i, m := range managers {
		wg.Go(func() { errs[i] = m.Rotate(t.Context(), f.tenant.ID) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent Rotate() unexpected error: %v", err)
	}

	stored, err := f.store.SigningKeys().List(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("listing stored keys: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("concurrent rotations stored %d keys, want 1", len(stored))
	}
	for i, m := range managers {
		if got := currentKID(t, m, f.tenant.ID); got != stored[0].KeyID {
			t.Errorf("manager %d signs with %q, want %q", i, got, stored[0].KeyID)
		}
	}
}

func TestPrivateKeysAreEncryptedAtRest(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	mustRotate(t, m, f.tenant.ID)
	signer, err := m.Signer(t.Context(), f.tenant.ID, RS256)
	if err != nil {
		t.Fatalf("Signer() unexpected error: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer.Key)
	if err != nil {
		t.Fatalf("encoding private key: %v", err)
	}

	stored, err := f.store.SigningKeys().List(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("listing stored keys: %v", err)
	}
	if bytes.Contains(stored[0].PrivateKey, pkcs8[len(pkcs8)-64:]) {
		t.Error("the stored private key contains plaintext key material")
	}

	other := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	if _, err := other.Signer(t.Context(), f.tenant.ID, RS256); !errors.Is(err, kek.ErrDecrypt) {
		t.Errorf("Signer() with the wrong encryption key error = %v, want kek.ErrDecrypt", err)
	}
}

func TestEncryptionKeyRotation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	oldSecret, newSecret := kek.GenerateSecret(), kek.GenerateSecret()
	policy := DefaultPolicy()
	before := f.manager(t, newEncrypter(t, oldSecret), policy)
	mustRotate(t, before, f.tenant.ID)

	rotated := newEncrypter(t, newSecret, oldSecret)
	after := f.manager(t, rotated, policy)
	if _, err := after.Signer(t.Context(), f.tenant.ID, RS256); err != nil {
		t.Fatalf("Signer() with the previous encryption key unexpected error: %v", err)
	}

	f.clock.Advance(policy.RotationPeriod)
	mustRotate(t, after, f.tenant.ID)
	stored, err := f.store.SigningKeys().List(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("listing stored keys: %v", err)
	}
	newest := stored[len(stored)-1]
	if newest.EncryptionKeyID != rotated.PrimaryKeyID() {
		t.Errorf("new key encrypted with %q, want the new primary %q", newest.EncryptionKeyID, rotated.PrimaryKeyID())
	}
}

func TestCiphertextIsBoundToItsRecord(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	mustRotate(t, m, f.tenant.ID)
	stored, err := f.store.SigningKeys().List(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("listing stored keys: %v", err)
	}

	// Copy the encrypted key into a record for another tenant, as an
	// attacker with write access to the database might.
	victim := store.Tenant{ID: uuid.NewV7(), Slug: "victim", Name: "Victim", CreatedAt: f.clock.Now(), UpdatedAt: f.clock.Now()}
	if err := f.store.Tenants().Create(t.Context(), victim); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	copied := stored[0]
	copied.ID, copied.TenantID = uuid.NewV7(), victim.ID
	if err := f.store.SigningKeys().Create(t.Context(), copied); err != nil {
		t.Fatalf("storing copied key: %v", err)
	}
	if _, err := m.Signer(t.Context(), victim.ID, RS256); !errors.Is(err, kek.ErrDecrypt) {
		t.Errorf("Signer() with a moved ciphertext error = %v, want kek.ErrDecrypt", err)
	}
}

func TestPolicyValidation(t *testing.T) {
	t.Parallel()
	valid := DefaultPolicy()
	if err := valid.Validate(); err != nil {
		t.Fatalf("DefaultPolicy() is invalid: %v", err)
	}

	tests := map[string]func(*Policy){
		"missing RS256":             func(p *Policy) { p.Algorithms = []string{ES256} },
		"unsupported algorithm":     func(p *Policy) { p.Algorithms = []string{RS256, "HS256"} },
		"duplicate algorithm":       func(p *Policy) { p.Algorithms = []string{RS256, RS256} },
		"publish ahead too long":    func(p *Policy) { p.PublishAhead = p.RotationPeriod },
		"publish ahead not set":     func(p *Policy) { p.PublishAhead = 0 },
		"retention not positive":    func(p *Policy) { p.Retention = 0 },
		"rotation period too short": func(p *Policy) { p.RotationPeriod = time.Hour },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := DefaultPolicy()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate() accepted a policy with %s", name)
			}
		})
	}
}
