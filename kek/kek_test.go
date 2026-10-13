package kek

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func mustLocal(t *testing.T, primary []byte, previous ...[]byte) *Local {
	t.Helper()
	l, err := NewLocal(primary, previous...)
	if err != nil {
		t.Fatalf("NewLocal() unexpected error: %v", err)
	}
	return l
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	l := mustLocal(t, GenerateSecret())
	plaintext, aad := []byte("private key bytes"), []byte("tenant/key-1")

	c, err := l.Encrypt(t.Context(), plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() unexpected error: %v", err)
	}
	if c.KeyID != l.PrimaryKeyID() {
		t.Errorf("KeyID = %q, want the primary %q", c.KeyID, l.PrimaryKeyID())
	}
	if bytes.Contains(c.Data, plaintext) {
		t.Error("ciphertext contains the plaintext")
	}
	got, err := l.Decrypt(t.Context(), c, aad)
	if err != nil {
		t.Fatalf("Decrypt() unexpected error: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt() = %q, want %q", got, plaintext)
	}
}

func TestEncryptUsesFreshNonces(t *testing.T) {
	t.Parallel()
	l := mustLocal(t, GenerateSecret())
	a, _ := l.Encrypt(t.Context(), []byte("same"), nil)
	b, _ := l.Encrypt(t.Context(), []byte("same"), nil)
	if bytes.Equal(a.Data, b.Data) {
		t.Error("two encryptions of the same plaintext produced identical ciphertexts")
	}
}

func TestDecryptFailures(t *testing.T) {
	t.Parallel()
	l := mustLocal(t, GenerateSecret())
	c, err := l.Encrypt(t.Context(), []byte("secret"), []byte("record-1"))
	if err != nil {
		t.Fatalf("Encrypt() unexpected error: %v", err)
	}
	tampered := Ciphertext{KeyID: c.KeyID, Data: bytes.Clone(c.Data)}
	tampered.Data[len(tampered.Data)-1] ^= 1

	tests := map[string]struct {
		c   Ciphertext
		aad []byte
	}{
		"other additional data": {c: c, aad: []byte("record-2")},
		"modified data":         {c: tampered, aad: []byte("record-1")},
		"unknown key":           {c: Ciphertext{KeyID: "local:0000000000000000", Data: c.Data}, aad: []byte("record-1")},
		"truncated data":        {c: Ciphertext{KeyID: c.KeyID, Data: c.Data[:4]}, aad: []byte("record-1")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := l.Decrypt(t.Context(), tt.c, tt.aad); !errors.Is(err, ErrDecrypt) {
				t.Errorf("Decrypt() error = %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestPrimaryRotation(t *testing.T) {
	t.Parallel()
	oldSecret, newSecret := GenerateSecret(), GenerateSecret()
	old := mustLocal(t, oldSecret)
	c, _ := old.Encrypt(t.Context(), []byte("payload"), nil)

	rotated := mustLocal(t, newSecret, oldSecret)
	if got, err := rotated.Decrypt(t.Context(), c, nil); err != nil || string(got) != "payload" {
		t.Errorf("Decrypt() with a previous key = (%q, %v), want payload", got, err)
	}
	fresh, _ := rotated.Encrypt(t.Context(), []byte("payload"), nil)
	if fresh.KeyID == c.KeyID || fresh.KeyID != rotated.PrimaryKeyID() {
		t.Errorf("new data encrypted with %q, want the new primary %q", fresh.KeyID, rotated.PrimaryKeyID())
	}
	if _, err := old.Decrypt(t.Context(), fresh, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("old encrypter decrypted data from the new primary: %v", err)
	}
}

func TestKeyIDsAreStableAndDistinct(t *testing.T) {
	t.Parallel()
	secret := GenerateSecret()
	first, second := mustLocal(t, secret), mustLocal(t, secret)
	if first.PrimaryKeyID() != second.PrimaryKeyID() {
		t.Error("the same secret produced different key IDs")
	}
	if mustLocal(t, secret).PrimaryKeyID() == mustLocal(t, GenerateSecret()).PrimaryKeyID() {
		t.Error("different secrets produced the same key ID")
	}
	if id := mustLocal(t, secret).PrimaryKeyID(); strings.Contains(id, base64.StdEncoding.EncodeToString(secret)[:8]) {
		t.Errorf("key ID %q appears to contain secret material", id)
	}
}

func TestNewLocalRejectsWrongSizes(t *testing.T) {
	t.Parallel()
	if _, err := NewLocal(make([]byte, 16)); err == nil {
		t.Error("NewLocal() accepted a 16-byte primary key")
	}
	if _, err := NewLocal(GenerateSecret(), make([]byte, 31)); err == nil {
		t.Error("NewLocal() accepted a 31-byte previous key")
	}
}

func TestParseSecret(t *testing.T) {
	t.Parallel()
	secret := GenerateSecret()
	got, err := ParseSecret(base64.StdEncoding.EncodeToString(secret))
	if err != nil || !bytes.Equal(got, secret) {
		t.Errorf("ParseSecret() = (%x, %v), want the original secret", got, err)
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := ParseSecret(bad); err == nil {
			t.Errorf("ParseSecret(%q) succeeded, want an error", bad)
		}
	}
}

// FuzzDecrypt feeds arbitrary ciphertexts to Decrypt, which must fail with
// ErrDecrypt rather than panic. Stored ciphertexts are untrusted: anyone with
// write access to the database can change them.
func FuzzDecrypt(f *testing.F) {
	l, err := NewLocal(make([]byte, SecretSize))
	if err != nil {
		f.Fatalf("NewLocal() unexpected error: %v", err)
	}
	valid, err := l.Encrypt(f.Context(), []byte("private key"), []byte("record"))
	if err != nil {
		f.Fatalf("Encrypt() unexpected error: %v", err)
	}
	f.Add(valid.Data, []byte("record"))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 28), []byte("record"))
	f.Fuzz(func(t *testing.T, data, aad []byte) {
		got, err := l.Decrypt(t.Context(), Ciphertext{KeyID: l.PrimaryKeyID(), Data: data}, aad)
		if err != nil {
			if !errors.Is(err, ErrDecrypt) {
				t.Fatalf("Decrypt() error = %v, want ErrDecrypt", err)
			}
			return
		}
		// Only genuine ciphertexts decrypt. Fuzz workers run in separate
		// processes with their own seed ciphertexts, so compare the content
		// rather than the bytes.
		if string(got) != "private key" || string(aad) != "record" {
			t.Fatalf("Decrypt() accepted forged data and returned %q", got)
		}
	})
}

// TestDecryptsStoredFormat pins the storage format: a random 96-bit nonce,
// then the AES-256-GCM ciphertext and tag. The vector was produced by the
// first implementation, so data stored by any release stays readable.
func TestDecryptsStoredFormat(t *testing.T) {
	t.Parallel()
	secret := make([]byte, SecretSize)
	for i := range secret {
		secret[i] = byte(i)
	}
	data, err := hex.DecodeString("000102030405060708090a0b3770bf6da491a73be624eeabdc880c08f1bfe658da3b6f4dc135e0cc9b3520d51bb728f7")
	if err != nil {
		t.Fatalf("decoding vector: %v", err)
	}
	l := mustLocal(t, secret)
	got, err := l.Decrypt(t.Context(), Ciphertext{KeyID: l.PrimaryKeyID(), Data: data}, []byte("clavis/test"))
	if err != nil {
		t.Fatalf("Decrypt() unexpected error: %v", err)
	}
	if string(got) != "private key material" {
		t.Errorf("Decrypt() = %q, want %q", got, "private key material")
	}
}
