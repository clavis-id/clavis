package clavis_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/clavis-id/clavis"
	"github.com/clavis-id/clavis/store/sqlite"
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

	auth, err := clavis.New(ctx, clavis.Config{
		Issuer: "https://app.example.com/auth",
		Store:  db,
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/readyz", http.NoBody)
	mux.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output: 200
}
