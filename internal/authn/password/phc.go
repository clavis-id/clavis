package password

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Bounds of the parts of a stored hash. Keys may be shorter than those of new
// hashes, which Verify then reports for rehashing. Salts must have at least
// 128 bits, which FIPS 140-only mode enforces for PBKDF2.
const (
	maxEncodedLength = 512
	minSaltLength    = saltLength
	maxSaltLength    = 64
	minKeyLength     = 16
	maxKeyLength     = 64
)

// b64 is the encoding of salts and keys in PHC strings: standard base64
// without padding. Strict decoding keeps every string canonical.
var b64 = base64.RawStdEncoding.Strict()

// params is a parsed PHC string.
type params struct {
	algorithm string
	// memory (in KiB) and lanes apply to argon2id only.
	memory     uint32
	iterations uint32
	lanes      uint8
	salt, key  []byte
}

// encode returns p as a PHC string:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//	$pbkdf2-sha256$i=600000$<salt>$<key>
func (p params) encode() string {
	salt, key := b64.EncodeToString(p.salt), b64.EncodeToString(p.key)
	if p.algorithm == PBKDF2SHA256 {
		return fmt.Sprintf("$%s$i=%d$%s$%s", PBKDF2SHA256, p.iterations, salt, key)
	}
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Argon2id, argon2.Version, p.memory, p.iterations, p.lanes, salt, key)
}

// parse reads a PHC string written by encode. It accepts only canonical
// strings, and only parameters within the bounds a Config allows, so a stored
// hash cannot make a verification arbitrarily expensive.
func parse(encoded string) (params, error) {
	if len(encoded) > maxEncodedLength {
		return params{}, fmt.Errorf("%w: longer than %d bytes", ErrMalformedHash, maxEncodedLength)
	}
	if strings.ContainsAny(encoded, "\r\n") {
		// The base64 decoder skips line breaks.
		return params{}, fmt.Errorf("%w: contains a line break", ErrMalformedHash)
	}
	fields := strings.Split(encoded, "$")
	if len(fields) < 2 || fields[0] != "" {
		return params{}, fmt.Errorf("%w: not a PHC string", ErrMalformedHash)
	}

	var p params
	var rest []string
	switch p.algorithm = fields[1]; p.algorithm {
	case Argon2id:
		if len(fields) != 6 {
			return params{}, fmt.Errorf("%w: argon2id needs 5 fields", ErrMalformedHash)
		}
		if fields[2] != "v="+strconv.Itoa(argon2.Version) {
			return params{}, fmt.Errorf("%w: argon2id version %q", ErrUnsupportedHash, fields[2])
		}
		values, err := parseValues(fields[3], "m", "t", "p")
		if err != nil {
			return params{}, err
		}
		p.memory, p.iterations = values[0], values[1]
		switch lanes := values[2]; {
		case lanes < 1 || lanes > maxArgon2Lanes:
			return params{}, fmt.Errorf("%w: argon2id parallelism %d", ErrMalformedHash, lanes)
		case p.iterations < 1 || p.iterations > maxArgon2Iterations:
			return params{}, fmt.Errorf("%w: argon2id iterations %d", ErrMalformedHash, p.iterations)
		case p.memory < 8*lanes || p.memory > maxArgon2Memory:
			return params{}, fmt.Errorf("%w: argon2id memory %d", ErrMalformedHash, p.memory)
		default:
			p.lanes = uint8(lanes)
		}
		rest = fields[4:]
	case PBKDF2SHA256:
		if len(fields) != 5 {
			return params{}, fmt.Errorf("%w: pbkdf2-sha256 needs 4 fields", ErrMalformedHash)
		}
		values, err := parseValues(fields[2], "i")
		if err != nil {
			return params{}, err
		}
		if p.iterations = values[0]; p.iterations < 1 || p.iterations > maxPBKDF2Iterations {
			return params{}, fmt.Errorf("%w: pbkdf2 iterations %d", ErrMalformedHash, p.iterations)
		}
		rest = fields[3:]
	default:
		return params{}, fmt.Errorf("%w: algorithm %q", ErrUnsupportedHash, p.algorithm)
	}

	var err error
	if p.salt, err = b64.DecodeString(rest[0]); err != nil || len(p.salt) < minSaltLength || len(p.salt) > maxSaltLength {
		return params{}, fmt.Errorf("%w: invalid salt", ErrMalformedHash)
	}
	if p.key, err = b64.DecodeString(rest[1]); err != nil || len(p.key) < minKeyLength || len(p.key) > maxKeyLength {
		return params{}, fmt.Errorf("%w: invalid key", ErrMalformedHash)
	}
	return p, nil
}

// parseValues reads a list such as "m=19456,t=2,p=1" whose names come in the
// given order. Values are canonical decimal numbers that fit in 32 bits.
func parseValues(s string, names ...string) ([]uint32, error) {
	var got []string
	var values []uint32
	for part := range strings.SplitSeq(s, ",") {
		name, v, _ := strings.Cut(part, "=")
		if v == "" || (v[0] == '0' && len(v) > 1) {
			return nil, fmt.Errorf("%w: parameters %q", ErrMalformedHash, s)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: parameters %q", ErrMalformedHash, s)
		}
		got = append(got, name)
		values = append(values, uint32(n))
	}
	if !slices.Equal(got, names) {
		return nil, fmt.Errorf("%w: parameters %q", ErrMalformedHash, s)
	}
	return values, nil
}
