// Package kek protects data at rest with key encryption keys.
//
// Clavis encrypts every private signing key before it reaches the store. The
// Encrypter interface lets deployments choose where the key encryption key
// lives: Local keeps it in process memory, and other implementations can
// delegate to a key management service.
package kek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// SecretSize is the size in bytes of a Local key encryption key (AES-256).
const SecretSize = 32

// ErrDecrypt is returned when a ciphertext cannot be decrypted: the key is
// unknown, the data was modified, or the additional data does not match.
var ErrDecrypt = errors.New("kek: decryption failed")

// Ciphertext is encrypted data together with the identifier of the key that
// encrypted it.
type Ciphertext struct {
	// KeyID identifies the key encryption key. It is not secret.
	KeyID string
	// Data is the encrypted payload.
	Data []byte
}

// Encrypter encrypts and decrypts small payloads such as private keys.
//
// Additional data is authenticated but not encrypted: decryption fails unless
// the same additional data is supplied. Callers bind ciphertexts to their
// context (for example a record ID) this way, so a ciphertext cannot be moved
// to another record.
type Encrypter interface {
	Encrypt(ctx context.Context, plaintext, additionalData []byte) (Ciphertext, error)
	Decrypt(ctx context.Context, c Ciphertext, additionalData []byte) ([]byte, error)
}

// Local is an Encrypter that holds AES-256 keys in memory and encrypts with
// AES-GCM. New data is encrypted with the primary key; older keys remain
// available for decryption, which allows rotating the primary key without
// re-encrypting existing data first.
type Local struct {
	primary string
	aeads   map[string]cipher.AEAD
}

var _ Encrypter = (*Local)(nil)

// NewLocal returns a Local encrypter. primary encrypts new data; previous
// keys only decrypt. Every secret must be SecretSize bytes of uniformly
// random data, for example from GenerateSecret.
func NewLocal(primary []byte, previous ...[]byte) (*Local, error) {
	l := &Local{aeads: make(map[string]cipher.AEAD, 1+len(previous))}
	for i, secret := range append([][]byte{primary}, previous...) {
		if len(secret) != SecretSize {
			return nil, fmt.Errorf("kek: key %d is %d bytes, want %d", i, len(secret), SecretSize)
		}
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, fmt.Errorf("kek: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("kek: %w", err)
		}
		id := localKeyID(secret)
		if i == 0 {
			l.primary = id
		}
		l.aeads[id] = aead
	}
	return l, nil
}

// PrimaryKeyID returns the identifier of the key that encrypts new data.
func (l *Local) PrimaryKeyID() string { return l.primary }

// Encrypt encrypts plaintext with the primary key. The random nonce is
// prepended to the returned data.
func (l *Local) Encrypt(_ context.Context, plaintext, additionalData []byte) (Ciphertext, error) {
	aead := l.aeads[l.primary]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	_, _ = rand.Read(nonce) // crypto/rand.Read never returns an error.
	return Ciphertext{KeyID: l.primary, Data: aead.Seal(nonce, nonce, plaintext, additionalData)}, nil
}

// Decrypt decrypts c with the key it names.
func (l *Local) Decrypt(_ context.Context, c Ciphertext, additionalData []byte) ([]byte, error) {
	aead, ok := l.aeads[c.KeyID]
	if !ok {
		return nil, fmt.Errorf("%w: unknown key %q", ErrDecrypt, c.KeyID)
	}
	if len(c.Data) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecrypt)
	}
	nonce, sealed := c.Data[:aead.NonceSize()], c.Data[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, additionalData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// GenerateSecret returns a new random key encryption key.
func GenerateSecret() []byte {
	secret := make([]byte, SecretSize)
	_, _ = rand.Read(secret) // crypto/rand.Read never returns an error.
	return secret
}

// ParseSecret decodes a key encryption key from standard base64.
func ParseSecret(encoded string) ([]byte, error) {
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("kek: secret is not valid base64")
	}
	if len(secret) != SecretSize {
		return nil, fmt.Errorf("kek: secret is %d bytes, want %d", len(secret), SecretSize)
	}
	return secret, nil
}

// localKeyID derives a stable, non-secret identifier from a secret. A
// truncated SHA-256 of 256 bits of random data reveals nothing usable about
// the secret.
func localKeyID(secret []byte) string {
	sum := sha256.Sum256(secret)
	return "local:" + hex.EncodeToString(sum[:8])
}
