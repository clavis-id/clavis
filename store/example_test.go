package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite"
)

// List pages through records in ID order: pass the last ID of a page to get
// the next one.
func ExampleTenants_List() {
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

	var s store.Store = db
	now := time.Now()
	for _, slug := range []string{"alpha", "beta", "gamma"} {
		t := store.Tenant{ID: uuid.NewV7(), Slug: slug, Name: slug, CreatedAt: now, UpdatedAt: now}
		if err := s.Tenants().Create(ctx, t); err != nil {
			panic(err)
		}
	}

	after := uuid.Nil()
	for {
		page, err := s.Tenants().List(ctx, after, 2)
		if err != nil {
			panic(err)
		}
		if len(page) == 0 {
			break
		}
		for _, t := range page {
			fmt.Println(t.Slug)
		}
		after = page[len(page)-1].ID
	}
	// Output:
	// alpha
	// beta
	// gamma
}
