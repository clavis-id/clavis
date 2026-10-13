package kek_test

import (
	"context"
	"encoding/base64"
	"fmt"

	"clavisid.org/clavis/kek"
)

// Encrypt binds a ciphertext to its additional data; decryption with other
// additional data fails.
func ExampleNewLocal() {
	enc, err := kek.NewLocal(kek.GenerateSecret())
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	c, err := enc.Encrypt(ctx, []byte("private key"), []byte("record-1"))
	if err != nil {
		panic(err)
	}

	plaintext, err := enc.Decrypt(ctx, c, []byte("record-1"))
	fmt.Println(string(plaintext), err)

	_, err = enc.Decrypt(ctx, c, []byte("record-2"))
	fmt.Println(err)
	// Output:
	// private key <nil>
	// kek: decryption failed
}

// Keep the primary secret outside the database, for example in a secrets
// manager, and pass it base64 encoded.
func ExampleParseSecret() {
	encoded := base64.StdEncoding.EncodeToString(kek.GenerateSecret())
	secret, err := kek.ParseSecret(encoded)
	fmt.Println(len(secret), err)
	// Output: 32 <nil>
}
