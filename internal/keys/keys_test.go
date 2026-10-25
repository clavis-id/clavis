package keys

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
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
	policy := DefaultPolicy() // 30 days, published 24h ahead, retained 15 days
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), policy)

	mustRotate(t, m, f.tenant.ID)
	first := currentKID(t, m, f.tenant.ID)

	// Just before the window that starts PublishAhead plus CheckInterval
	// before the switch: nothing changes.
	lead := policy.PublishAhead + policy.CheckInterval
	f.clock.Advance(policy.RotationPeriod - lead - time.Second)
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
	f.clock.Advance(lead)
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
	m.mu.Lock()
	lists := len(m.lists)
	m.mu.Unlock()
	if lists != 0 {
		t.Errorf("the Manager keeps %d key lists after the cleanup, want none", lists)
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
		"missing RS256":                      func(p *Policy) { p.Algorithms = []string{ES256} },
		"unsupported algorithm":              func(p *Policy) { p.Algorithms = []string{RS256, "HS256"} },
		"duplicate algorithm":                func(p *Policy) { p.Algorithms = []string{RS256, RS256} },
		"publish ahead too long":             func(p *Policy) { p.PublishAhead = p.RotationPeriod },
		"publish ahead not set":              func(p *Policy) { p.PublishAhead = 0 },
		"publish ahead below the minimum":    func(p *Policy) { p.PublishAhead, p.CheckInterval = 10*time.Minute, time.Minute },
		"check interval not set":             func(p *Policy) { p.CheckInterval = 0 },
		"check interval above publish ahead": func(p *Policy) { p.CheckInterval = p.PublishAhead + time.Second },
		"no room for the successor":          func(p *Policy) { p.RotationPeriod = p.PublishAhead + p.CheckInterval },
		"retention not positive":             func(p *Policy) { p.Retention = 0 },
		"rotation period too short":          func(p *Policy) { p.RotationPeriod = time.Hour },
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

func TestRotationMetrics(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	reader := sdkmetric.NewManualReader()
	policy := DefaultPolicy()
	policy.Algorithms = []string{RS256, ES256}
	m, err := NewManager(Config{
		Store:         f.store,
		Encrypter:     newEncrypter(t, kek.GenerateSecret()),
		Policy:        policy,
		Logger:        slog.New(slog.DiscardHandler),
		Now:           f.clock.Now,
		NewID:         uuid.NewV7,
		MeterProvider: sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)),
	})
	if err != nil {
		t.Fatalf("NewManager() unexpected error: %v", err)
	}
	mustRotate(t, m, f.tenant.ID)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}
	got := make(map[string]int64)
	for _, sm := range rm.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name != "clavis.signing_keys.created" {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data has type %T, want a sum", metric.Data)
			}
			for _, dp := range sum.DataPoints {
				alg, _ := dp.Attributes.Value(attribute.Key("algorithm"))
				got[alg.AsString()] = dp.Value
			}
		}
	}
	if got[RS256] != 1 || got[ES256] != 1 {
		t.Errorf("created keys by algorithm = %v, want one RS256 and one ES256", got)
	}
}

// runFixture starts Run inside a synctest bubble, where time is virtual.
type runFixture struct {
	store  *sqlite.Store
	tenant store.Tenant
	reader *sdkmetric.ManualReader
	cancel context.CancelFunc
	done   chan struct{}
}

func startRun(t *testing.T, policy Policy) *runFixture {
	t.Helper()
	s, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "clavis.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	tn := store.Tenant{ID: uuid.NewV7(), Slug: "acme", Name: "Acme", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.Tenants().Create(t.Context(), tn); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	reader := sdkmetric.NewManualReader()
	m, err := NewManager(Config{
		Store:         s,
		Encrypter:     newEncrypter(t, kek.GenerateSecret()),
		Policy:        policy,
		Logger:        slog.New(slog.DiscardHandler),
		Now:           time.Now,
		NewID:         uuid.NewV7,
		MeterProvider: sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)),
	})
	if err != nil {
		t.Fatalf("NewManager() unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	f := &runFixture{store: s, tenant: tn, reader: reader, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		m.Run(ctx)
	}()
	return f
}

func (f *runFixture) stop() {
	f.cancel()
	<-f.done
	_ = f.store.Close()
}

func (f *runFixture) keyCount(t *testing.T) int {
	t.Helper()
	keys, err := f.store.SigningKeys().List(t.Context(), f.tenant.ID)
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	return len(keys)
}

func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == name {
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
			}
		}
	}
	return total
}

func TestRunRotatesOnSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy := Policy{
			Algorithms:     []string{RS256},
			RotationPeriod: 4 * time.Hour,
			PublishAhead:   2 * time.Hour,
			Retention:      time.Hour,
			CheckInterval:  30 * time.Minute,
		}
		f := startRun(t, policy)
		defer f.stop()

		synctest.Wait()
		if n := f.keyCount(t); n != 0 {
			t.Fatalf("Run() created %d keys before its first tick, want 0", n)
		}

		// The first tick creates the initial key.
		time.Sleep(30 * time.Minute)
		synctest.Wait()
		if n := f.keyCount(t); n != 1 {
			t.Fatalf("keys after the first tick = %d, want 1", n)
		}

		// Two hours before the first key retires, a tick schedules its successor.
		time.Sleep(policy.RotationPeriod - policy.PublishAhead)
		synctest.Wait()
		if n := f.keyCount(t); n != 2 {
			t.Fatalf("keys inside the publish-ahead window = %d, want 2", n)
		}
		if got := counterValue(t, f.reader, "clavis.signing_keys.created"); got != 2 {
			t.Errorf("created keys counter = %d, want 2", got)
		}
	})
}

func TestRunCountsFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy := DefaultPolicy()
		policy.CheckInterval = time.Minute
		f := startRun(t, policy)
		defer f.stop()

		// A closed store makes every rotation fail.
		if err := f.store.Close(); err != nil {
			t.Fatalf("closing store: %v", err)
		}
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if got := counterValue(t, f.reader, "clavis.signing_keys.rotation_failures"); got != 3 {
			t.Errorf("rotation failures counter = %d, want 3", got)
		}
	})
}

func TestAddedAlgorithmIsPublishedAhead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enc := newEncrypter(t, kek.GenerateSecret())
	mustRotate(t, f.manager(t, enc, DefaultPolicy()), f.tenant.ID)

	policy := DefaultPolicy()
	policy.Algorithms = []string{RS256, ES256}
	m := f.manager(t, enc, policy)
	mustRotate(t, m, f.tenant.ID)

	if got := kids(t, m, f.tenant.ID); len(got) != 2 {
		t.Fatalf("published keys = %v, want the RS256 key and the new ES256 key", got)
	}
	if _, err := m.Signer(t.Context(), f.tenant.ID, ES256); !errors.Is(err, ErrNoActiveKey) {
		t.Errorf("ES256 Signer() before publish-ahead elapsed error = %v, want ErrNoActiveKey", err)
	}
	f.clock.Advance(policy.PublishAhead)
	if _, err := m.Signer(t.Context(), f.tenant.ID, ES256); err != nil {
		t.Errorf("ES256 Signer() after publish-ahead unexpected error: %v", err)
	}
}

func TestJWKSSkipsCorruptKeys(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := f.manager(t, newEncrypter(t, kek.GenerateSecret()), DefaultPolicy())
	mustRotate(t, m, f.tenant.ID)
	healthy := currentKID(t, m, f.tenant.ID)

	corrupt := store.SigningKey{
		ID:              uuid.NewV7(),
		TenantID:        f.tenant.ID,
		Algorithm:       ES256,
		Generation:      1,
		KeyID:           "corrupt",
		PublicKey:       []byte("not a public key"),
		PrivateKey:      []byte("not a private key"),
		EncryptionKeyID: "local:0000000000000000",
		ActivatesAt:     f.clock.Now(),
		RetiresAt:       f.clock.Now().Add(time.Hour),
		ExpiresAt:       f.clock.Now().Add(2 * time.Hour),
		CreatedAt:       f.clock.Now(),
	}
	if err := f.store.SigningKeys().Create(t.Context(), corrupt); err != nil {
		t.Fatalf("storing corrupt key: %v", err)
	}
	f.clock.Advance(JWKSCacheTTL)

	if got := kids(t, m, f.tenant.ID); len(got) != 1 || got[0] != healthy {
		t.Errorf("published keys = %v, want only the healthy key %q", got, healthy)
	}
}

func TestJWKSIsCached(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enc := newEncrypter(t, kek.GenerateSecret())
	policy := DefaultPolicy()
	m := f.manager(t, enc, policy)
	mustRotate(t, m, f.tenant.ID)

	// Fill the cache at the moment another instance schedules a successor.
	f.clock.Advance(policy.RotationPeriod - policy.PublishAhead - policy.CheckInterval)
	if got := kids(t, m, f.tenant.ID); len(got) != 1 {
		t.Fatalf("published keys = %v, want 1", got)
	}
	mustRotate(t, f.manager(t, enc, policy), f.tenant.ID)

	if got := kids(t, m, f.tenant.ID); len(got) != 1 {
		t.Errorf("published keys before the cache expires = %v, want the cached single key", got)
	}
	f.clock.Advance(JWKSCacheTTL)
	if got := kids(t, m, f.tenant.ID); len(got) != 2 {
		t.Errorf("published keys after the cache expires = %v, want 2", got)
	}
}

// countingStore counts the lists of signing keys.
type countingStore struct {
	store.Store
	mu    sync.Mutex
	lists int
}

func (s *countingStore) SigningKeys() store.SigningKeys {
	return countingKeys{s.Store.SigningKeys(), s}
}

func (s *countingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lists
}

type countingKeys struct {
	store.SigningKeys
	s *countingStore
}

func (k countingKeys) List(ctx context.Context, tenantID uuid.UUID) ([]store.SigningKey, error) {
	k.s.mu.Lock()
	k.s.lists++
	k.s.mu.Unlock()
	return k.SigningKeys.List(ctx, tenantID)
}

// The signer reuses the list of keys for JWKSCacheTTL, and the successor
// that the list holds takes over when it activates (from the review of #52).
func TestSignerReusesTheKeyList(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enc := newEncrypter(t, kek.GenerateSecret())
	policy := DefaultPolicy()
	counting := &countingStore{Store: f.store}
	m, err := NewManager(Config{Store: counting, Encrypter: enc, Policy: policy,
		Logger: slog.New(slog.DiscardHandler), Now: f.clock.Now, NewID: uuid.NewV7})
	if err != nil {
		t.Fatalf("NewManager() unexpected error: %v", err)
	}
	mustRotate(t, m, f.tenant.ID)
	first := currentKID(t, m, f.tenant.ID)
	// Another instance schedules the successor.
	f.clock.Advance(policy.RotationPeriod - policy.PublishAhead - policy.CheckInterval)
	mustRotate(t, f.manager(t, enc, policy), f.tenant.ID)
	before := counting.count()
	for range 3 {
		if got := currentKID(t, m, f.tenant.ID); got != first {
			t.Fatalf("Signer() = %q, want the current key %q", got, first)
		}
	}
	if n := counting.count() - before; n != 1 {
		t.Errorf("three signers listed the keys %d times, want once", n)
	}

	// The list read now holds the successor, which takes over without
	// another read when the current key retires.
	f.clock.Advance(policy.PublishAhead + policy.CheckInterval - time.Second)
	successor := currentKID(t, m, f.tenant.ID)
	if successor != first {
		t.Fatalf("Signer() before the successor activates = %q, want %q", successor, first)
	}
	before = counting.count()
	f.clock.Advance(time.Second)
	if got := currentKID(t, m, f.tenant.ID); got == first {
		t.Errorf("Signer() after the current key retired = %q, want the successor", got)
	}
	if n := counting.count() - before; n != 0 {
		t.Errorf("the successor took %d lists of the keys, want none", n)
	}

	// A key that the Manager creates itself makes it read the list again.
	f.clock.Advance(policy.RotationPeriod - policy.PublishAhead - policy.CheckInterval)
	currentKID(t, m, f.tenant.ID)
	mustRotate(t, m, f.tenant.ID)
	before = counting.count()
	currentKID(t, m, f.tenant.ID)
	if n := counting.count() - before; n != 1 {
		t.Errorf("a signer after the Manager created a key listed the keys %d times, want once", n)
	}
}

// A key that another instance creates to sign at once, after an outage,
// is found although the list of keys is reused.
func TestSignerFindsAKeyThatSignsAtOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enc := newEncrypter(t, kek.GenerateSecret())
	policy := DefaultPolicy()
	m := f.manager(t, enc, policy)
	mustRotate(t, m, f.tenant.ID)
	first := currentKID(t, m, f.tenant.ID)

	// Every key retires during an outage; the list is read after that.
	f.clock.Advance(policy.RotationPeriod)
	if _, err := m.Signer(t.Context(), f.tenant.ID, RS256); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Signer() after every key retired = %v, want ErrNoActiveKey", err)
	}
	mustRotate(t, f.manager(t, enc, policy), f.tenant.ID)
	if got := currentKID(t, m, f.tenant.ID); got == first {
		t.Errorf("Signer() after another instance rotated = %q, want the new key", got)
	}
}
