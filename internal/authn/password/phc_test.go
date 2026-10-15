package password

import (
	"testing"
)

func TestEncodeParseRoundTrip(t *testing.T) {
	t.Parallel()
	for _, p := range []params{
		{algorithm: Argon2id, memory: 19456, iterations: 2, lanes: 1, salt: make([]byte, 16), key: make([]byte, 32)},
		{algorithm: PBKDF2SHA256, iterations: 600_000, salt: make([]byte, 16), key: make([]byte, 32)},
	} {
		encoded := p.encode()
		got, err := parse(encoded)
		if err != nil {
			t.Fatalf("parse(%q) unexpected error: %v", encoded, err)
		}
		if got.encode() != encoded {
			t.Errorf("parse(%q) round trip = %q", encoded, got.encode())
		}
	}
}

// FuzzParse checks that parsing never panics, accepts only parameters within
// the bounds that keep verification affordable, and accepts only canonical
// strings.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$pbkdf2-sha256$i=600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=4294967295,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$bcrypt$12$x$y",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		p, err := parse(encoded)
		if err != nil {
			return
		}
		switch p.algorithm {
		case Argon2id:
			if p.memory > maxArgon2Memory || p.iterations > maxArgon2Iterations || p.lanes > maxArgon2Lanes ||
				p.iterations < 1 || p.lanes < 1 || p.memory < 8*uint32(p.lanes) {
				t.Errorf("parse(%q) accepted argon2id parameters %+v", encoded, p)
			}
		case PBKDF2SHA256:
			if p.iterations < 1 || p.iterations > maxPBKDF2Iterations {
				t.Errorf("parse(%q) accepted %d PBKDF2 iterations", encoded, p.iterations)
			}
		default:
			t.Errorf("parse(%q) accepted algorithm %q", encoded, p.algorithm)
		}
		if len(p.salt) < minSaltLength || len(p.salt) > maxSaltLength || len(p.key) < minKeyLength || len(p.key) > maxKeyLength {
			t.Errorf("parse(%q) accepted a salt of %d bytes and a key of %d bytes", encoded, len(p.salt), len(p.key))
		}
		if p.encode() != encoded {
			t.Errorf("parse(%q) accepted a non-canonical string; it encodes as %q", encoded, p.encode())
		}
	})
}
