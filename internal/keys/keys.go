// Package keys manages the lifecycle of token signing keys.
//
// Each tenant has one key sequence per signing algorithm. A key's schedule is
// fixed at creation: it is published immediately, signs from ActivatesAt to
// RetiresAt, and stays published until ExpiresAt so that tokens it signed can
// still be verified. A successor is created PublishAhead before the current
// key retires, so relying parties that cache the JWK set see it before it
// signs anything.
//
// Private keys are encrypted with a kek.Encrypter before they reach the
// store. The additional data binds each ciphertext to its tenant, record and
// algorithm, so ciphertexts cannot be swapped between records.
package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
	"uuid"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store"
)

// Supported JWS algorithms.
const (
	RS256 = "RS256"
	ES256 = "ES256"
	EdDSA = "EdDSA"
)

// rsaKeyBits is the RSA modulus size for RS256 keys.
const rsaKeyBits = 2048

// tenantPageSize is the page size used when rotating every tenant.
const tenantPageSize = 100

// MinPublishAhead is the shortest allowed PublishAhead. Clients cache the
// JWK set (the HTTP layer allows five minutes) and the Manager caches it for
// JWKSCacheTTL, so a key must be published well before it signs.
const MinPublishAhead = 15 * time.Minute

// JWKSCacheTTL is how long the Manager reuses a tenant's JWK set before
// reading the store again.
const JWKSCacheTTL = time.Minute

// ErrNoActiveKey is returned by Signer when no key is active for the tenant
// and algorithm, which happens until the first rotation runs.
var ErrNoActiveKey = errors.New("keys: no active signing key")

// Policy controls the rotation schedule.
type Policy struct {
	// Algorithms lists the algorithms every tenant signs with. OpenID
	// Connect requires RS256, so it must be included.
	Algorithms []string
	// RotationPeriod is how long each key signs.
	RotationPeriod time.Duration
	// PublishAhead is how long a successor is published before it starts
	// signing. It must be shorter than RotationPeriod.
	PublishAhead time.Duration
	// Retention is how long a retired key stays published. It must exceed
	// the lifetime of every token the key can sign.
	Retention time.Duration
	// CheckInterval is how often Run rotates keys. Successors are created
	// PublishAhead plus CheckInterval before the switch, so they are
	// published for at least PublishAhead whatever the timing of the check.
	CheckInterval time.Duration
}

// DefaultPolicy returns the policy used when none is configured.
func DefaultPolicy() Policy {
	return Policy{
		Algorithms:     []string{RS256},
		RotationPeriod: 30 * 24 * time.Hour,
		PublishAhead:   24 * time.Hour,
		Retention:      48 * time.Hour,
		CheckInterval:  time.Hour,
	}
}

// Validate reports every problem in p, joined into a single error.
func (p Policy) Validate() error {
	var errs []error
	if !slices.Contains(p.Algorithms, RS256) {
		errs = append(errs, errors.New("algorithms must include RS256, which OpenID Connect requires"))
	}
	seen := make(map[string]bool, len(p.Algorithms))
	for _, alg := range p.Algorithms {
		switch {
		case !slices.Contains([]string{RS256, ES256, EdDSA}, alg):
			errs = append(errs, fmt.Errorf("unsupported algorithm %q (supported: RS256, ES256, EdDSA)", alg))
		case seen[alg]:
			errs = append(errs, fmt.Errorf("algorithm %q is listed more than once", alg))
		}
		seen[alg] = true
	}
	if p.PublishAhead < MinPublishAhead {
		errs = append(errs, fmt.Errorf("publish_ahead must be at least %s, got %s", MinPublishAhead, p.PublishAhead))
	}
	if p.CheckInterval <= 0 || p.CheckInterval > p.PublishAhead {
		errs = append(errs, fmt.Errorf("check_interval (%s) must be positive and no longer than publish_ahead (%s)",
			p.CheckInterval, p.PublishAhead))
	}
	if p.RotationPeriod <= p.PublishAhead+p.CheckInterval {
		errs = append(errs, fmt.Errorf("rotation_period (%s) must be longer than publish_ahead plus check_interval (%s)",
			p.RotationPeriod, p.PublishAhead+p.CheckInterval))
	}
	if p.Retention <= 0 {
		errs = append(errs, fmt.Errorf("retention must be positive, got %s", p.Retention))
	}
	return errors.Join(errs...)
}

// Signer is the key that currently signs for a tenant and algorithm.
type Signer struct {
	// KeyID is the "kid" header value for tokens signed with this key.
	KeyID string
	// Algorithm is the JWS "alg" header value.
	Algorithm string
	// Key is the private key: *rsa.PrivateKey, *ecdsa.PrivateKey or
	// ed25519.PrivateKey.
	Key crypto.Signer
}

// Config holds the dependencies of a Manager.
type Config struct {
	Store     store.Store
	Encrypter kek.Encrypter
	Policy    Policy
	Logger    *slog.Logger
	Now       func() time.Time
	NewID     func() uuid.UUID
	// MeterProvider records rotation metrics. When nil, metrics are
	// discarded.
	MeterProvider metric.MeterProvider
}

// Manager creates, rotates, publishes and loads signing keys. It is safe for
// concurrent use, and several Managers may share one store.
type Manager struct {
	store     store.Store
	encrypter kek.Encrypter
	policy    Policy
	logger    *slog.Logger
	now       func() time.Time
	newID     func() uuid.UUID

	created  metric.Int64Counter
	failures metric.Int64Counter

	mu      sync.Mutex
	signers map[uuid.UUID]crypto.Signer // decrypted private keys by record ID
	jwks    map[uuid.UUID]cachedSet     // published key sets by tenant ID
}

// cachedSet is a tenant's JWK set and the time it stops being reused.
type cachedSet struct {
	set     jose.JSONWebKeySet
	expires time.Time
}

// NewManager validates cfg and returns a Manager.
func NewManager(cfg Config) (*Manager, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("keys: invalid policy: %w", err)
	}
	if cfg.Store == nil || cfg.Encrypter == nil || cfg.Logger == nil || cfg.Now == nil || cfg.NewID == nil {
		return nil, errors.New("keys: Store, Encrypter, Logger, Now and NewID are required")
	}
	mp := cfg.MeterProvider
	if mp == nil {
		mp = noop.NewMeterProvider()
	}
	meter := mp.Meter("clavisid.org/clavis/internal/keys")
	created, err := meter.Int64Counter("clavis.signing_keys.created",
		metric.WithDescription("Signing keys created by rotation."), metric.WithUnit("{key}"))
	if err != nil {
		return nil, fmt.Errorf("keys: creating metric: %w", err)
	}
	failures, err := meter.Int64Counter("clavis.signing_keys.rotation_failures",
		metric.WithDescription("Background rotation runs that failed."), metric.WithUnit("{run}"))
	if err != nil {
		return nil, fmt.Errorf("keys: creating metric: %w", err)
	}
	return &Manager{
		store:     cfg.Store,
		encrypter: cfg.Encrypter,
		policy:    cfg.Policy,
		logger:    cfg.Logger,
		now:       cfg.Now,
		newID:     cfg.NewID,
		created:   created,
		failures:  failures,
		signers:   make(map[uuid.UUID]crypto.Signer),
		jwks:      make(map[uuid.UUID]cachedSet),
	}, nil
}

// Run rotates every tenant's keys each Policy.CheckInterval until ctx is
// canceled. Failures are logged and retried on the next tick.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.policy.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.RotateAll(ctx); err != nil && ctx.Err() == nil {
				m.failures.Add(ctx, 1)
				m.logger.LogAttrs(ctx, slog.LevelError, "signing key rotation failed", slog.String("error", err.Error()))
			}
		}
	}
}

// RotateAll rotates the keys of every tenant and deletes expired keys. It
// keeps going when a tenant fails and reports every failure.
func (m *Manager) RotateAll(ctx context.Context) error {
	var errs []error
	after := uuid.Nil()
	for {
		page, err := m.store.Tenants().List(ctx, after, tenantPageSize)
		if err != nil {
			return fmt.Errorf("keys: listing tenants: %w", err)
		}
		for _, t := range page {
			if err := m.Rotate(ctx, t.ID); err != nil {
				errs = append(errs, err)
			}
		}
		if len(page) < tenantPageSize {
			break
		}
		after = page[len(page)-1].ID
	}

	n, err := m.store.SigningKeys().DeleteExpired(ctx, m.now())
	if err != nil {
		errs = append(errs, fmt.Errorf("keys: deleting expired keys: %w", err))
	} else if n > 0 {
		m.logger.LogAttrs(ctx, slog.LevelInfo, "deleted expired signing keys", slog.Int64("count", n))
		m.forgetDeleted(ctx)
	}
	return errors.Join(errs...)
}

// Rotate brings one tenant's keys in line with the policy. For each
// algorithm it creates:
//
//   - a successor, once the current key is within PublishAhead plus
//     CheckInterval of retiring, scheduled to sign when the current key
//     retires;
//   - the first key of an algorithm added to a tenant that already signs
//     with another one, published PublishAhead before it signs;
//   - a key that signs immediately when the tenant has no current key at
//     all: a new tenant, or one whose keys all retired during an outage.
//     Availability then wins over caches, which may briefly miss the key.
func (m *Manager) Rotate(ctx context.Context, tenantID uuid.UUID) error {
	all, err := m.store.SigningKeys().List(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("keys: listing keys of tenant %s: %w", tenantID, err)
	}
	now := m.now()
	tenantSigns := slices.ContainsFunc(all, func(k store.SigningKey) bool { return signsAt(k, now) })
	var errs []error
	for _, alg := range m.policy.Algorithms {
		latest, ok := latestKey(all, alg)
		switch {
		case !ok && tenantSigns:
			errs = append(errs, m.create(ctx, tenantID, alg, 1, now.Add(m.policy.PublishAhead)))
		case !ok:
			errs = append(errs, m.create(ctx, tenantID, alg, 1, now))
		case !now.Before(latest.RetiresAt):
			errs = append(errs, m.create(ctx, tenantID, alg, latest.Generation+1, now))
		case !latest.ActivatesAt.After(now) &&
			!now.Before(latest.RetiresAt.Add(-(m.policy.PublishAhead + m.policy.CheckInterval))):
			errs = append(errs, m.create(ctx, tenantID, alg, latest.Generation+1, latest.RetiresAt))
		}
	}
	return errors.Join(errs...)
}

// create generates, encrypts and stores a key. A conflict means another
// instance created the same generation first, which is not an error.
func (m *Manager) create(ctx context.Context, tenantID uuid.UUID, alg string, generation int64, activatesAt time.Time) error {
	priv, err := generate(alg)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("keys: encoding private key: %w", err)
	}
	defer clear(pkcs8)
	pub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return fmt.Errorf("keys: encoding public key: %w", err)
	}
	kid, err := thumbprint(priv.Public())
	if err != nil {
		return err
	}

	id := m.newID()
	ciphertext, err := m.encrypter.Encrypt(ctx, pkcs8, additionalData(tenantID, id, alg))
	if err != nil {
		return fmt.Errorf("keys: encrypting private key: %w", err)
	}
	retiresAt := activatesAt.Add(m.policy.RotationPeriod)
	k := store.SigningKey{
		ID:              id,
		TenantID:        tenantID,
		Algorithm:       alg,
		Generation:      generation,
		KeyID:           kid,
		PublicKey:       pub,
		PrivateKey:      ciphertext.Data,
		EncryptionKeyID: ciphertext.KeyID,
		ActivatesAt:     activatesAt,
		RetiresAt:       retiresAt,
		ExpiresAt:       retiresAt.Add(m.policy.Retention),
		CreatedAt:       m.now(),
	}
	switch err := m.store.SigningKeys().Create(ctx, k); {
	case errors.Is(err, store.ErrConflict):
		return nil
	case err != nil:
		return fmt.Errorf("keys: storing key: %w", err)
	}
	m.mu.Lock()
	delete(m.jwks, tenantID)
	m.mu.Unlock()
	m.created.Add(ctx, 1, metric.WithAttributes(attribute.String("algorithm", alg)))
	m.logger.LogAttrs(ctx, slog.LevelInfo, "created signing key",
		slog.String("tenant_id", tenantID.String()),
		slog.String("algorithm", alg),
		slog.Int64("generation", generation),
		slog.String("kid", kid),
		slog.Time("activates_at", activatesAt))
	return nil
}

// Signer returns the key that signs for the tenant and algorithm now.
func (m *Manager) Signer(ctx context.Context, tenantID uuid.UUID, alg string) (Signer, error) {
	all, err := m.store.SigningKeys().List(ctx, tenantID)
	if err != nil {
		return Signer{}, fmt.Errorf("keys: listing keys of tenant %s: %w", tenantID, err)
	}
	now := m.now()
	var current *store.SigningKey
	for i := range all {
		k := &all[i]
		if k.Algorithm == alg && signsAt(*k, now) && (current == nil || k.Generation > current.Generation) {
			current = k
		}
	}
	if current == nil {
		return Signer{}, fmt.Errorf("%w for tenant %s and algorithm %s", ErrNoActiveKey, tenantID, alg)
	}
	key, err := m.decrypt(ctx, *current)
	if err != nil {
		return Signer{}, err
	}
	return Signer{KeyID: current.KeyID, Algorithm: alg, Key: key}, nil
}

// JWKS returns the public keys of the tenant that relying parties must
// accept: the current key, its scheduled successor and retired keys that
// have not expired. The set is cached for JWKSCacheTTL, so frequent requests
// to the public endpoint do not reach the store. A key whose stored public
// key cannot be parsed is logged and left out instead of failing the whole
// set, so one damaged record cannot stop verification of every token.
func (m *Manager) JWKS(ctx context.Context, tenantID uuid.UUID) (jose.JSONWebKeySet, error) {
	now := m.now()
	m.mu.Lock()
	cached, ok := m.jwks[tenantID]
	m.mu.Unlock()
	if ok && now.Before(cached.expires) {
		return cached.set, nil
	}

	all, err := m.store.SigningKeys().List(ctx, tenantID)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("keys: listing keys of tenant %s: %w", tenantID, err)
	}
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(all))}
	for _, k := range all {
		if !now.Before(k.ExpiresAt) {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(k.PublicKey)
		if err != nil {
			m.logger.LogAttrs(ctx, slog.LevelError, "skipping signing key with a corrupt public key",
				slog.String("tenant_id", tenantID.String()),
				slog.String("kid", k.KeyID),
				slog.String("error", err.Error()))
			continue
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: pub, KeyID: k.KeyID, Algorithm: k.Algorithm, Use: "sig"})
	}

	m.mu.Lock()
	m.jwks[tenantID] = cachedSet{set: set, expires: now.Add(JWKSCacheTTL)}
	m.mu.Unlock()
	return set, nil
}

// decrypt returns the private key of k, decrypting it on first use.
func (m *Manager) decrypt(ctx context.Context, k store.SigningKey) (crypto.Signer, error) {
	m.mu.Lock()
	cached, ok := m.signers[k.ID]
	m.mu.Unlock()
	if ok {
		return cached, nil
	}

	pkcs8, err := m.encrypter.Decrypt(ctx, kek.Ciphertext{KeyID: k.EncryptionKeyID, Data: k.PrivateKey},
		additionalData(k.TenantID, k.ID, k.Algorithm))
	if err != nil {
		return nil, fmt.Errorf("keys: decrypting key %s: %w", k.KeyID, err)
	}
	defer clear(pkcs8)
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("keys: parsing key %s: %w", k.KeyID, err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("keys: key %s is not a signing key", k.KeyID)
	}
	pub, err := x509.ParsePKIXPublicKey(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keys: corrupt public key %s: %w", k.KeyID, err)
	}
	if eq, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(pub) {
		return nil, fmt.Errorf("keys: private key %s does not match its public key", k.KeyID)
	}

	m.mu.Lock()
	m.signers[k.ID] = signer
	m.mu.Unlock()
	return signer, nil
}

// forgetDeleted drops cached JWK sets and private keys after expired keys are
// deleted. Expired keys never sign, so this only bounds memory and keeps the
// published sets in step with the store.
func (m *Manager) forgetDeleted(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwks = make(map[uuid.UUID]cachedSet)
	if len(m.signers) == 0 {
		return
	}
	m.signers = make(map[uuid.UUID]crypto.Signer)
	m.logger.LogAttrs(ctx, slog.LevelDebug, "cleared signing key cache")
}

// signsAt reports whether k is the signing key at time t.
func signsAt(k store.SigningKey, t time.Time) bool {
	return !k.ActivatesAt.After(t) && t.Before(k.RetiresAt)
}

// latestKey returns the key with the highest generation for alg.
func latestKey(all []store.SigningKey, alg string) (store.SigningKey, bool) {
	var latest store.SigningKey
	found := false
	for _, k := range all {
		if k.Algorithm == alg && (!found || k.Generation > latest.Generation) {
			latest, found = k, true
		}
	}
	return latest, found
}

// generate creates a private key for alg.
func generate(alg string) (crypto.Signer, error) {
	switch alg {
	case RS256:
		k, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, fmt.Errorf("keys: generating RSA key: %w", err)
		}
		return k, nil
	case ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("keys: generating ECDSA key: %w", err)
		}
		return k, nil
	case EdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("keys: generating Ed25519 key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("keys: unsupported algorithm %q", alg)
	}
}

// thumbprint returns the RFC 7638 JWK thumbprint of pub, base64url encoded,
// which serves as the key ID.
func thumbprint(pub crypto.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("keys: computing thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// additionalData binds an encrypted private key to its record.
func additionalData(tenantID, id uuid.UUID, alg string) []byte {
	return []byte("clavis/signing-key/v1|" + tenantID.String() + "|" + id.String() + "|" + alg)
}
