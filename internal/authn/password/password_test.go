package password

import (
	"context"
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
)

// cheapConfig keeps tests fast. Only newHasher accepts it: Validate rejects
// costs below the policy of ADR 0015.
func cheapConfig() Config {
	return Config{
		MinLength:           MinLength,
		Argon2id:            Argon2idParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1},
		PBKDF2Iterations:    1000,
		MaxConcurrent:       4,
		FIPSMigrateArgon2id: true,
	}
}

// newAlgorithm is the algorithm of new hashes in this process.
func newAlgorithm(cfg Config) string {
	if cfg.FIPS || fips140.Enabled() {
		return PBKDF2SHA256
	}
	return Argon2id
}

func mustHash(t *testing.T, h *Hasher, password string) string {
	t.Helper()
	encoded, err := h.Hash(t.Context(), password)
	if err != nil {
		t.Fatalf("Hash() unexpected error: %v", err)
	}
	return encoded
}

func mustVerify(t *testing.T, h *Hasher, encoded, password string) Verification {
	t.Helper()
	v, err := h.Verify(t.Context(), encoded, password)
	if err != nil {
		t.Fatalf("Verify() unexpected error: %v", err)
	}
	return v
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() = %v", err)
	}
	h, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig()) unexpected error: %v", err)
	}
	encoded := mustHash(t, h, "correct horse battery staple")
	want := "$argon2id$v=19$m=19456,t=2,p=1$"
	if fips140.Enabled() {
		want = "$pbkdf2-sha256$i=600000$"
	}
	if !strings.HasPrefix(encoded, want) {
		t.Errorf("Hash() = %q, want the prefix %q", encoded, want)
	}
	if v := mustVerify(t, h, encoded, "correct horse battery staple"); !v.Match || v.Rehash {
		t.Errorf("Verify() = %+v, want a match that needs no rehash", v)
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Config){
		"short minimum length":   func(c *Config) { c.MinLength = MinLength - 1 },
		"long minimum length":    func(c *Config) { c.MinLength = MaxLength + 1 },
		"little memory":          func(c *Config) { c.Argon2id.MemoryKiB = 19*1024 - 1 },
		"too much memory":        func(c *Config) { c.Argon2id.MemoryKiB = 1024*1024 + 1 },
		"one iteration":          func(c *Config) { c.Argon2id.Iterations = 1 },
		"too many iterations":    func(c *Config) { c.Argon2id.Iterations = 101 },
		"no lanes":               func(c *Config) { c.Argon2id.Parallelism = 0 },
		"too many lanes":         func(c *Config) { c.Argon2id.Parallelism = 65 },
		"few PBKDF2 iterations":  func(c *Config) { c.PBKDF2Iterations = 599_999 },
		"many PBKDF2 iterations": func(c *Config) { c.PBKDF2Iterations = 10_000_001 },
		"negative concurrency":   func(c *Config) { c.MaxConcurrent = -1 },
		"excessive concurrency":  func(c *Config) { c.MaxConcurrent = 1025 },
	}
	for name, modify := range tests {
		cfg := DefaultConfig()
		modify(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", name)
		}
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New() = nil error, want an error", name)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	t.Parallel()
	for _, fips := range []bool{false, true} {
		cfg := cheapConfig()
		cfg.FIPS = fips
		h := newHasher(cfg)
		if h.FIPS() != (fips || fips140.Enabled()) {
			t.Errorf("FIPS() = %v with Config.FIPS %v", h.FIPS(), fips)
		}
		encoded := mustHash(t, h, "correct horse battery staple")
		if !strings.HasPrefix(encoded, "$"+newAlgorithm(cfg)+"$") {
			t.Errorf("FIPS %v: Hash() = %q, want algorithm %s", fips, encoded, newAlgorithm(cfg))
		}
		if v := mustVerify(t, h, encoded, "correct horse battery staple"); !v.Match || v.Rehash || v.Algorithm != newAlgorithm(cfg) {
			t.Errorf("FIPS %v: Verify(right password) = %+v", fips, v)
		}
		for _, wrong := range []string{"correct horse battery stapl", "Correct horse battery staple", ""} {
			if v := mustVerify(t, h, encoded, wrong); v.Match || v.Rehash {
				t.Errorf("FIPS %v: Verify(%q) = %+v, want no match", fips, wrong, v)
			}
		}
		if other := mustHash(t, h, "correct horse battery staple"); other == encoded {
			t.Errorf("FIPS %v: two hashes of the same password are equal; salts must differ", fips)
		}
	}
}

func TestVerifyNormalizesUnicode(t *testing.T) {
	t.Parallel()
	h := newHasher(cheapConfig())
	// U+00E9 and "e" followed by U+0301 are the same character; so are the
	// ligature U+FB01 and "fi" under NFKC.
	encoded := mustHash(t, h, "café ﬁne password")
	if v := mustVerify(t, h, encoded, "café fine password"); !v.Match {
		t.Error("an equivalent Unicode spelling does not match")
	}
}

func TestVerifyRejectsOverlongPasswords(t *testing.T) {
	t.Parallel()
	h := newHasher(cheapConfig())
	long := strings.Repeat("a", maxBytes+1)
	encoded := mustHash(t, h, long[:maxBytes])
	if v := mustVerify(t, h, encoded, long); v.Match {
		t.Error("a password longer than the limit matched the hash of its prefix")
	}
	if v := mustVerify(t, h, encoded, long[:maxBytes]); !v.Match {
		t.Error("a password at the limit does not match")
	}
}

func TestRehash(t *testing.T) {
	t.Parallel()
	weakArgon := cheapConfig()
	weakArgon.Argon2id.MemoryKiB = 32
	weakPBKDF2 := cheapConfig()
	weakPBKDF2.FIPS = true
	weakPBKDF2.PBKDF2Iterations = 500

	tests := []struct {
		name       string
		stored     Config
		current    Config
		wantRehash bool
		skipFIPS   bool
	}{
		{name: "same policy", stored: cheapConfig(), current: cheapConfig()},
		{name: "less argon2id memory", stored: weakArgon, current: cheapConfig(), wantRehash: true, skipFIPS: true},
		{name: "fewer argon2id iterations", stored: func() Config {
			c := cheapConfig()
			c.Argon2id.MemoryKiB, c.Argon2id.Iterations = 128, 1
			return c
		}(), current: func() Config {
			c := cheapConfig()
			c.Argon2id.MemoryKiB, c.Argon2id.Iterations = 128, 2
			return c
		}(), wantRehash: true, skipFIPS: true},
		{name: "fewer argon2id lanes", stored: cheapConfig(), current: func() Config {
			c := cheapConfig()
			c.Argon2id.Parallelism = 2
			return c
		}(), wantRehash: true, skipFIPS: true},
		{name: "stronger stored argon2id", stored: func() Config {
			c := cheapConfig()
			c.Argon2id.MemoryKiB = 128
			return c
		}(), current: cheapConfig(), skipFIPS: true},
		{name: "argon2id in FIPS mode", stored: cheapConfig(), current: weakPBKDF2, wantRehash: true, skipFIPS: true},
		{name: "fewer PBKDF2 iterations", stored: weakPBKDF2, current: func() Config {
			c := cheapConfig()
			c.FIPS = true
			return c
		}(), wantRehash: true},
		{name: "PBKDF2 outside FIPS mode", stored: weakPBKDF2, current: cheapConfig(), wantRehash: true, skipFIPS: true},
	}
	for _, tt := range tests {
		if tt.skipFIPS && fips140.Enabled() {
			// New hashes are always PBKDF2 in FIPS mode.
			continue
		}
		encoded := mustHash(t, newHasher(tt.stored), "correct horse battery staple")
		h := newHasher(tt.current)
		if v := mustVerify(t, h, encoded, "correct horse battery staple"); !v.Match || v.Rehash != tt.wantRehash {
			t.Errorf("%s: Verify() = %+v, want a match with Rehash %v", tt.name, v, tt.wantRehash)
		}
		if v := mustVerify(t, h, encoded, "wrong password"); v.Match || v.Rehash {
			t.Errorf("%s: Verify(wrong password) = %+v, want no match and no rehash", tt.name, v)
		}
	}
}

func TestShortKeysAreRehashed(t *testing.T) {
	t.Parallel()
	h := newHasher(cheapConfig())
	p := h.current(make([]byte, saltLength))
	key, err := h.derive(t.Context(), p, "correct horse battery staple", minKeyLength)
	if err != nil {
		t.Fatalf("derive() unexpected error: %v", err)
	}
	p.key = key
	if v := mustVerify(t, h, p.encode(), "correct horse battery staple"); !v.Match || !v.Rehash {
		t.Errorf("Verify() of a hash with a short key = %+v, want a match that needs a rehash", v)
	}
}

func TestFIPSCanRefuseArgon2id(t *testing.T) {
	t.Parallel()
	argonCfg := cheapConfig()
	if fips140.Enabled() {
		t.Skip("argon2id hashes cannot be created in FIPS mode")
	}
	encoded := mustHash(t, newHasher(argonCfg), "correct horse battery staple")

	migrate := cheapConfig()
	migrate.FIPS = true
	if v := mustVerify(t, newHasher(migrate), encoded, "correct horse battery staple"); !v.Match || !v.Rehash ||
		v.Algorithm != Argon2id {
		t.Errorf("Verify() with FIPSMigrateArgon2id = %+v, want an argon2id match that needs a rehash", v)
	}

	refuse := migrate
	refuse.FIPSMigrateArgon2id = false
	if _, err := newHasher(refuse).Verify(t.Context(), encoded, "correct horse battery staple"); !errors.Is(err, ErrUnsupportedHash) {
		t.Errorf("Verify() without FIPSMigrateArgon2id error = %v, want ErrUnsupportedHash", err)
	}
}

func TestVerifyRejectsUnusableHashes(t *testing.T) {
	t.Parallel()
	h := newHasher(cheapConfig())
	salt, key := b64.EncodeToString(make([]byte, 16)), b64.EncodeToString(make([]byte, 32))
	tests := map[string]struct {
		encoded string
		want    error
	}{
		"empty":                   {"", ErrMalformedHash},
		"no leading dollar":       {"argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key, ErrMalformedHash},
		"unknown algorithm":       {"$bcrypt$12$" + salt + "$" + key, ErrUnsupportedHash},
		"argon2i":                 {"$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key, ErrUnsupportedHash},
		"old argon2 version":      {"$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key, ErrUnsupportedHash},
		"missing field":           {"$argon2id$v=19$m=64,t=1,p=1$" + salt, ErrMalformedHash},
		"parameters out of order": {"$argon2id$v=19$t=1,m=64,p=1$" + salt + "$" + key, ErrMalformedHash},
		"leading zero":            {"$argon2id$v=19$m=064,t=1,p=1$" + salt + "$" + key, ErrMalformedHash},
		"huge memory":             {"$argon2id$v=19$m=4294967295,t=1,p=1$" + salt + "$" + key, ErrMalformedHash},
		"memory below lanes":      {"$argon2id$v=19$m=15,t=1,p=2$" + salt + "$" + key, ErrMalformedHash},
		"no iterations":           {"$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key, ErrMalformedHash},
		"too many lanes":          {"$argon2id$v=19$m=1024,t=1,p=65$" + salt + "$" + key, ErrMalformedHash},
		"number overflow":         {"$argon2id$v=19$m=99999999999,t=1,p=1$" + salt + "$" + key, ErrMalformedHash},
		"huge PBKDF2 iterations":  {"$pbkdf2-sha256$i=10000001$" + salt + "$" + key, ErrMalformedHash},
		"no PBKDF2 iterations":    {"$pbkdf2-sha256$i=0$" + salt + "$" + key, ErrMalformedHash},
		"PBKDF2 extra field":      {"$pbkdf2-sha256$i=1000$x$" + salt + "$" + key, ErrMalformedHash},
		"padded salt":             {"$pbkdf2-sha256$i=1000$" + salt + "==$" + key, ErrMalformedHash},
		"short salt":              {"$pbkdf2-sha256$i=1000$AAAA$" + key, ErrMalformedHash},
		"64-bit salt":             {"$pbkdf2-sha256$i=1000$AAAAAAAAAAA$" + key, ErrMalformedHash},
		"short key":               {"$pbkdf2-sha256$i=1000$" + salt + "$AAAA", ErrMalformedHash},
		"too long":                {"$pbkdf2-sha256$i=1000$" + salt + "$" + strings.Repeat("A", maxEncodedLength), ErrMalformedHash},
	}
	for name, tt := range tests {
		v, err := h.Verify(t.Context(), tt.encoded, "correct horse battery staple")
		if !errors.Is(err, tt.want) || v.Match {
			t.Errorf("%s: Verify() = %+v, %v; want %v", name, v, err, tt.want)
		}
	}
}

func TestCheckNew(t *testing.T) {
	t.Parallel()
	cfg := cheapConfig()
	cfg.MinLength = 10
	h := newHasher(cfg)
	if h.MinLength() != 10 {
		t.Errorf("MinLength() = %d, want the configured 10", h.MinLength())
	}
	for _, valid := range []string{
		strings.Repeat("a", 10),
		strings.Repeat("ñ", 10),
		strings.Repeat("a", MaxLength),
		"correct horse battery staple",
	} {
		if err := h.CheckNew(valid); err != nil {
			t.Errorf("CheckNew(%d characters) = %v, want nil", len([]rune(valid)), err)
		}
	}
	for name, invalid := range map[string]string{
		"too short":         strings.Repeat("a", 9),
		"too long":          strings.Repeat("a", MaxLength+1),
		"invalid UTF-8":     "abcdefghij\xff",
		"empty":             "",
		"long when encoded": strings.Repeat("é́́́́́́", MaxLength),
	} {
		if err := h.CheckNew(invalid); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: CheckNew() = %v, want ErrPolicy", name, err)
		}
	}
	// Normalization can combine characters: "e" and U+0301 count as one.
	if err := h.CheckNew(strings.Repeat("é", 9)); !errors.Is(err, ErrPolicy) {
		t.Errorf("CheckNew(9 composed characters) = %v, want ErrPolicy", err)
	}
	// The byte bound comes before validation and normalization, whose cost
	// grows with the input, so an oversized password fails on its length even
	// when it is not valid UTF-8.
	if err := h.CheckNew(strings.Repeat("a", maxBytes) + "\xff"); !errors.Is(err, ErrPolicy) ||
		strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("CheckNew(oversized invalid UTF-8) = %v, want the length error", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := cheapConfig()
		cfg.MaxConcurrent = 1
		h := newHasher(cfg)
		h.sem <- struct{}{} // Another hash is in progress.

		done := make(chan error, 1)
		go func() {
			_, err := h.Hash(t.Context(), "correct horse battery staple")
			done <- err
		}()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("Hash() returned %v while every slot was taken", err)
		default:
		}

		<-h.sem // The other hash finishes.
		synctest.Wait()
		if err := <-done; err != nil {
			t.Errorf("Hash() after a slot freed = %v", err)
		}

		h.sem <- struct{}{}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := h.Hash(ctx, "correct horse battery staple"); !errors.Is(err, context.Canceled) {
			t.Errorf("Hash() with a canceled context = %v, want context.Canceled", err)
		}
		if err := h.VerifyDummy(ctx, "x"); !errors.Is(err, context.Canceled) {
			t.Errorf("VerifyDummy() with a canceled context = %v, want context.Canceled", err)
		}
		if _, err := h.Verify(ctx, "malformed", "x"); !errors.Is(err, context.Canceled) {
			t.Errorf("Verify() with a canceled context = %v, want context.Canceled", err)
		}
		<-h.sem
	})
}

func TestDefaultConcurrencyUsesTheCPUs(t *testing.T) {
	t.Parallel()
	cfg := cheapConfig()
	cfg.MaxConcurrent = 0
	if got := cap(newHasher(cfg).sem); got < 1 {
		t.Errorf("default concurrency limit = %d, want at least 1", got)
	}
}

func TestVerifyDummyUsesTheCurrentParameters(t *testing.T) {
	t.Parallel()
	for _, fips := range []bool{false, true} {
		cfg := cheapConfig()
		cfg.FIPS = fips
		h := newHasher(cfg)
		p := h.current(h.dummySalt)
		if p.algorithm != newAlgorithm(cfg) || len(p.salt) != saltLength {
			t.Errorf("FIPS %v: dummy parameters = %+v, want the parameters of new hashes", fips, p)
		}
		if err := h.VerifyDummy(t.Context(), strings.Repeat("a", maxBytes+1)); err != nil {
			t.Errorf("FIPS %v: VerifyDummy() = %v", fips, err)
		}
	}
}

// TestDeriveRejectsOutOfRangeParameters covers the guards in derive, which
// parse and Validate make unreachable from the exported API.
func TestDeriveRejectsOutOfRangeParameters(t *testing.T) {
	t.Parallel()
	h := newHasher(cheapConfig())
	salt := make([]byte, saltLength)
	for name, tt := range map[string]struct {
		p      params
		length int
	}{
		"short key":           {params{algorithm: Argon2id, memory: 64, iterations: 1, lanes: 1, salt: salt}, minKeyLength - 1},
		"long key":            {params{algorithm: Argon2id, memory: 64, iterations: 1, lanes: 1, salt: salt}, maxKeyLength + 1},
		"no PBKDF2 iteration": {params{algorithm: PBKDF2SHA256, iterations: 0, salt: salt}, keyLength},
		"too many iterations": {params{algorithm: PBKDF2SHA256, iterations: maxPBKDF2Iterations + 1, salt: salt}, keyLength},
	} {
		if _, err := h.derive(t.Context(), tt.p, "password", tt.length); err == nil {
			t.Errorf("%s: derive() succeeded, want an error", name)
		}
	}
}
