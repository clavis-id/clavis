package postgres_test

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"clavisid.org/clavis/store/postgres"
)

// An application that already has a connection pool shares it with Clavis.
// The pool stays owned by the application, so Close does not close it.
func ExampleNew() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	db, err := postgres.New(ctx, pool, postgres.WithoutMigrations())
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		panic(err)
	}
}
