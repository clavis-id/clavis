// Package password hashes and verifies passwords (ADR 0015).
//
// New hashes use argon2id, or PBKDF2-HMAC-SHA-256 when the process runs in
// FIPS 140-3 mode. Hashes are PHC strings that carry their algorithm and
// parameters, so the policy can change without invalidating stored hashes:
// Verify reports when a hash is below the current policy, and the caller
// replaces it with a new one after a successful login.
package password

import (
	"context"
	"crypto/fips140"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Algorithm identifiers, as they appear in PHC strings.
const (
	Argon2id     = "argon2id"
	PBKDF2SHA256 = "pbkdf2-sha256"
)

// Length limits of new passwords, in characters. MinLength bounds
// Config.MinLength from below; MaxLength is large enough for any password
// manager.
const (
	MinLength = 8
	MaxLength = 256
)

// maxBytes bounds the encoded length of a password, which normalization can
// shrink to MaxLength characters. Verify rejects longer input after hashing
// only its first maxBytes bytes, so it costs no more than any other attempt.
const maxBytes = 16 * MaxLength

// Sizes of new hashes. FIPS 140-3 requires salts of at least 128 bits and
// keys of at least 112 bits for PBKDF2 (SP 800-132).
const (
	saltLength = 16
	keyLength  = 32
)

// Errors returned by this package.
var (
	// ErrPolicy reports a new password that the policy rejects.
	ErrPolicy = errors.New("password does not meet the policy")
	// ErrMalformedHash reports a stored hash that cannot be parsed.
	ErrMalformedHash = errors.New("malformed password hash")
	// ErrUnsupportedHash reports a stored hash whose algorithm cannot be
	// verified, such as argon2id in FIPS mode when Config.FIPSMigrateArgon2id
	// is false.
	ErrUnsupportedHash = errors.New("unsupported password hash")
)

// Argon2idParams are the cost parameters of argon2id.
type Argon2idParams struct {
	// MemoryKiB is the memory used by one hash, in KiB.
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// Config is the password policy.
type Config struct {
	// MinLength is the minimum number of characters of a new password.
	MinLength int
	// Argon2id sets the cost of new argon2id hashes.
	Argon2id Argon2idParams
	// PBKDF2Iterations is the iteration count of new PBKDF2-HMAC-SHA-256
	// hashes, used in FIPS mode.
	PBKDF2Iterations int
	// MaxConcurrent bounds how many hashes are computed at once; further
	// calls wait. Zero uses the number of CPUs available to the process.
	MaxConcurrent int
	// FIPS makes new hashes use PBKDF2-HMAC-SHA-256 even when the process
	// does not run in FIPS 140-3 mode. In FIPS mode they always do.
	FIPS bool
	// FIPSMigrateArgon2id lets FIPS mode verify an argon2id hash, created
	// before FIPS mode was enabled, so the login replaces it with a PBKDF2
	// hash (ADR 0015). argon2id is not a FIPS-approved algorithm: when this
	// is false, such hashes are refused and their users must reset their
	// passwords.
	FIPSMigrateArgon2id bool
}

// DefaultConfig returns the policy of ADR 0015: the OWASP baseline for
// argon2id (19 MiB, 2 iterations, 1 lane) and 600,000 PBKDF2 iterations.
func DefaultConfig() Config {
	return Config{
		MinLength:           MinLength,
		Argon2id:            Argon2idParams{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1},
		PBKDF2Iterations:    600_000,
		FIPSMigrateArgon2id: true,
	}
}

// Bounds of the configurable costs. The lower bounds are the OWASP
// recommendations; the upper bounds keep a single hash from exhausting the
// process. Stored hashes are parsed with the same upper bounds.
const (
	minArgon2Memory     = 19 * 1024
	maxArgon2Memory     = 1024 * 1024
	minArgon2Iterations = 2
	maxArgon2Iterations = 100
	maxArgon2Lanes      = 64
	minPBKDF2Iterations = 600_000
	maxPBKDF2Iterations = 10_000_000
	maxConcurrentHashes = 1024
)

// Validate reports the first setting outside its bounds.
func (c Config) Validate() error {
	switch {
	case c.MinLength < MinLength || c.MinLength > MaxLength:
		return fmt.Errorf("min_length must be between %d and %d, got %d", MinLength, MaxLength, c.MinLength)
	case c.Argon2id.MemoryKiB < minArgon2Memory || c.Argon2id.MemoryKiB > maxArgon2Memory:
		return fmt.Errorf("argon2id memory must be between %d and %d KiB, got %d",
			minArgon2Memory, maxArgon2Memory, c.Argon2id.MemoryKiB)
	case c.Argon2id.Iterations < minArgon2Iterations || c.Argon2id.Iterations > maxArgon2Iterations:
		return fmt.Errorf("argon2id iterations must be between %d and %d, got %d",
			minArgon2Iterations, maxArgon2Iterations, c.Argon2id.Iterations)
	case c.Argon2id.Parallelism < 1 || c.Argon2id.Parallelism > maxArgon2Lanes:
		return fmt.Errorf("argon2id parallelism must be between 1 and %d, got %d", maxArgon2Lanes, c.Argon2id.Parallelism)
	case c.PBKDF2Iterations < minPBKDF2Iterations || c.PBKDF2Iterations > maxPBKDF2Iterations:
		return fmt.Errorf("pbkdf2 iterations must be between %d and %d, got %d",
			minPBKDF2Iterations, maxPBKDF2Iterations, c.PBKDF2Iterations)
	case c.MaxConcurrent < 0 || c.MaxConcurrent > maxConcurrentHashes:
		return fmt.Errorf("max concurrent hashes must be between 0 and %d, got %d", maxConcurrentHashes, c.MaxConcurrent)
	}
	return nil
}

// Hasher hashes and verifies passwords under one policy. It is safe for
// concurrent use.
type Hasher struct {
	cfg  Config
	fips bool
	// sem holds one token per hash being computed.
	sem chan struct{}
	// dummySalt is used by VerifyDummy.
	dummySalt []byte
}

// New returns a Hasher for cfg.
func New(cfg Config) (*Hasher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	return newHasher(cfg), nil
}

// newHasher builds a Hasher without validating cfg, which lets tests use
// cheap parameters.
func newHasher(cfg Config) *Hasher {
	limit := cfg.MaxConcurrent
	if limit == 0 {
		limit = runtime.GOMAXPROCS(0)
	}
	salt := make([]byte, saltLength)
	_, _ = rand.Read(salt) // Never fails; see crypto/rand.Read.
	return &Hasher{
		cfg:       cfg,
		fips:      cfg.FIPS || fips140.Enabled(),
		sem:       make(chan struct{}, limit),
		dummySalt: salt,
	}
}

// FIPS reports whether new hashes use PBKDF2-HMAC-SHA-256.
func (h *Hasher) FIPS() bool { return h.fips }

// CheckNew reports whether password can be set as a new password: valid
// UTF-8 with MinLength to MaxLength characters after normalization.
func (h *Hasher) CheckNew(password string) error {
	if !utf8.ValidString(password) {
		return fmt.Errorf("%w: the password is not valid UTF-8", ErrPolicy)
	}
	if n := utf8.RuneCountInString(normalize(password)); n < h.cfg.MinLength || n > MaxLength ||
		len(password) > maxBytes {
		return fmt.Errorf("%w: the password must have %d to %d characters", ErrPolicy, h.cfg.MinLength, MaxLength)
	}
	return nil
}

// Hash returns the PHC string of a new hash of password. It does not check
// the policy; call CheckNew first.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, saltLength)
	_, _ = rand.Read(salt) // Never fails; see crypto/rand.Read.
	p := h.current(salt)
	key, err := h.derive(ctx, p, normalize(password), keyLength)
	if err != nil {
		return "", err
	}
	p.key = key
	return p.encode(), nil
}

// Verification is the outcome of Verify.
type Verification struct {
	// Match reports whether the password matches the hash.
	Match bool
	// Rehash reports that the hash is below the current policy and should be
	// replaced with a new hash of the same password. It is set only on a
	// match.
	Rehash bool
	// Algorithm is the algorithm of the stored hash.
	Algorithm string
}

// Verify reports whether password matches the PHC string encoded. Hashes that
// cannot be verified return ErrMalformedHash or ErrUnsupportedHash after the
// same work as a real verification, so the response time does not reveal
// them.
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (Verification, error) {
	p, err := parse(encoded)
	if err == nil && p.algorithm == Argon2id && h.fips && !h.cfg.FIPSMigrateArgon2id {
		err = fmt.Errorf("%w: argon2id is refused in FIPS mode", ErrUnsupportedHash)
	}
	if err != nil {
		if dummyErr := h.VerifyDummy(ctx, password); dummyErr != nil {
			return Verification{}, dummyErr
		}
		return Verification{}, err
	}
	tooLong := len(password) > maxBytes
	if tooLong {
		password = password[:maxBytes]
	}
	key, err := h.derive(ctx, p, normalize(password), len(p.key))
	if err != nil {
		return Verification{}, err
	}
	v := Verification{Algorithm: p.algorithm, Match: subtle.ConstantTimeCompare(key, p.key) == 1 && !tooLong}
	v.Rehash = v.Match && h.belowPolicy(p)
	return v, nil
}

// VerifyDummy does the work of verifying password against a hash with the
// current parameters, and discards the result. Logins for unknown accounts
// call it, so the response time does not reveal whether an account exists.
func (h *Hasher) VerifyDummy(ctx context.Context, password string) error {
	if len(password) > maxBytes {
		password = password[:maxBytes]
	}
	_, err := h.derive(ctx, h.current(h.dummySalt), normalize(password), keyLength)
	return err
}

// current returns the parameters of a new hash with the given salt.
func (h *Hasher) current(salt []byte) params {
	if h.fips {
		iterations := uint32(h.cfg.PBKDF2Iterations) //nolint:gosec // New validates the bounds.
		return params{algorithm: PBKDF2SHA256, iterations: iterations, salt: salt}
	}
	a := h.cfg.Argon2id
	return params{algorithm: Argon2id, memory: a.MemoryKiB, iterations: a.Iterations, lanes: a.Parallelism, salt: salt}
}

// belowPolicy reports whether a stored hash is weaker than a new one, or uses
// another algorithm than new hashes.
func (h *Hasher) belowPolicy(p params) bool {
	want := h.current(nil)
	switch {
	case p.algorithm != want.algorithm, len(p.salt) < saltLength, len(p.key) < keyLength:
		return true
	case p.algorithm == PBKDF2SHA256:
		return p.iterations < want.iterations
	default:
		return p.memory < want.memory || p.iterations < want.iterations || p.lanes < want.lanes
	}
}

// derive computes the key of password with the parameters p, waiting for a
// free slot first.
func (h *Hasher) derive(ctx context.Context, p params, password string, length int) ([]byte, error) {
	if length < minKeyLength || length > maxKeyLength {
		return nil, fmt.Errorf("password: key length %d is outside [%d, %d]", length, minKeyLength, maxKeyLength)
	}
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("password: waiting to hash: %w", ctx.Err())
	}
	defer func() { <-h.sem }()

	if p.algorithm == PBKDF2SHA256 {
		// parse and Validate bound the count; checking it here keeps the
		// conversion safe where int has 32 bits.
		iterations := p.iterations
		if iterations < 1 || iterations > maxPBKDF2Iterations {
			return nil, fmt.Errorf("password: %d PBKDF2 iterations is outside [1, %d]", iterations, maxPBKDF2Iterations)
		}
		key, err := pbkdf2.Key(sha256.New, password, p.salt, int(iterations), length)
		if err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
		return key, nil
	}
	return argon2.IDKey([]byte(password), p.salt, p.iterations, p.memory, p.lanes, uint32(length)), nil
}

// normalize applies Unicode normalization form NFKC, so a password typed with
// different input methods hashes the same (NIST SP 800-63B-4, section
// 3.1.1.2).
func normalize(password string) string {
	return norm.NFKC.String(password)
}
