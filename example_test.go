package clavis_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"clavisid.org/clavis"
	"clavisid.org/clavis/kek"
	"clavisid.org/clavis/store/sqlite"
)

// Clavis mounts on any router. Here it serves every route below /auth/ of an
// existing application and keeps its data in an embedded SQLite file.
func ExampleNew() {
	dir, err := os.MkdirTemp("", "clavis-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(dir, "clavis.db"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Load the key encryption key from a secrets manager in production.
	enc, err := kek.NewLocal(kek.GenerateSecret())
	if err != nil {
		panic(err)
	}

	auth, err := clavis.New(ctx, clavis.Config{
		Issuer:       "https://app.example.com/auth",
		Store:        db,
		KeyEncrypter: enc,
	})
	if err != nil {
		panic(err)
	}
	defer auth.Close()

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/readyz", http.NoBody)
	mux.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output: 200
}

// When the issuer has a path, RFC 8414 metadata lives outside it, at the root
// of the host, so the application mounts WellKnownHandler there as well.
func ExampleServer_WellKnownHandler() {
	dir, err := os.MkdirTemp("", "clavis-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(dir, "clavis.db"))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	enc, err := kek.NewLocal(kek.GenerateSecret())
	if err != nil {
		panic(err)
	}
	auth, err := clavis.New(ctx, clavis.Config{
		Issuer:       "https://app.example.com/auth",
		Store:        db,
		KeyEncrypter: enc,
	})
	if err != nil {
		panic(err)
	}
	defer auth.Close()

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
	mux.Handle("/.well-known/oauth-authorization-server/", auth.WellKnownHandler())

	for _, path := range []string{
		"/auth/.well-known/openid-configuration",       // OpenID Connect Discovery
		"/.well-known/oauth-authorization-server/auth", // RFC 8414
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, path, http.NoBody))
		fmt.Println(rec.Code, path)
	}
	// Output:
	// 200 /auth/.well-known/openid-configuration
	// 200 /.well-known/oauth-authorization-server/auth
}
