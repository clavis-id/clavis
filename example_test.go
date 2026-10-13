package clavis_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/clavis-id/clavis"
)

// Clavis mounts on any router. Here it serves every route below /auth/ of an
// existing application.
func ExampleNew() {
	auth, err := clavis.New(context.Background(), clavis.Config{
		Issuer: "https://app.example.com/auth",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/healthz", http.NoBody)
	mux.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output: 200
}
