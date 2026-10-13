package sqlite_test

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

func ExampleOpen() {
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

	now := time.Now()
	err = db.Tenants().Create(ctx, store.Tenant{ID: uuid.NewV7(), Slug: "acme", Name: "Acme", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		panic(err)
	}
	t, err := db.Tenants().GetBySlug(ctx, "acme")
	fmt.Println(t.Name, err)
	// Output: Acme <nil>
}

// Deployments that run migrations as a separate step open the store without
// migrating and call Migrate from the deployment job.
func ExampleWithoutMigrations() {
	dir, err := os.MkdirTemp("", "clavis-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(dir, "clavis.db"), sqlite.WithoutMigrations())
	if err != nil {
		panic(err)
	}
	defer db.Close()
	fmt.Println(db.Migrate(ctx))
	// Output: <nil>
}
