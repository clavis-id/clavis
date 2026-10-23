package cli

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres"
	"clavisid.org/clavis/store/sqlite"
)

// migrator is implemented by every first-party store adapter.
type migrator interface {
	Migrate(ctx context.Context) error
}

// openedStore is a store together with the means to migrate and release it.
type openedStore struct {
	store.Store
	migrator
	close func()
}

// openStore opens the store selected by cfg. Pending migrations are applied
// when migrate is true.
func openStore(ctx context.Context, cfg config.Database, migrate bool) (openedStore, error) {
	switch cfg.Driver {
	case config.DriverSQLite:
		var opts []sqlite.Option
		if !migrate {
			opts = append(opts, sqlite.WithoutMigrations())
		}
		s, err := sqlite.Open(ctx, cfg.DSN, opts...)
		if err != nil {
			return openedStore{}, err
		}
		return openedStore{Store: s, migrator: s, close: func() { _ = s.Close() }}, nil
	case config.DriverPostgres:
		var opts []postgres.Option
		if !migrate {
			opts = append(opts, postgres.WithoutMigrations())
		}
		s, err := postgres.Open(ctx, cfg.DSN, opts...)
		if err != nil {
			return openedStore{}, err
		}
		return openedStore{Store: s, migrator: s, close: s.Close}, nil
	default:
		return openedStore{}, fmt.Errorf("unsupported database driver %q", cfg.Driver)
	}
}

// withTenant loads the configuration with load, opens the database, resolves
// the tenant with the given slug and calls fn, for commands that manage the
// records of one tenant. The work of fn is an operator's: its audit events
// say so (ADR 0029).
//
// Only commands that create records pass createDefault: the server creates
// the default tenant when it first starts, and its signing keys on every
// start, so records can be created before that. Other commands report a
// missing default tenant, which also reveals a mistyped database location.
func withTenant(cmd *cobra.Command, load func(string, []string) (config.Result, error), configPath string,
	environ []string, slug string, createDefault bool,
	fn func(context.Context, config.Config, app.Deps, store.Tenant) error,
) error {
	// Only the commands that manage records act as operators. The context of
	// the root command is not marked, since `clavis serve` derives the
	// contexts of its requests from it.
	ctx := app.AsOperator(cmd.Context())
	cfg, logger, err := setup(ctx, load, configPath, environ, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	st, err := openStore(ctx, cfg.Database, cfg.Database.AutoMigrate)
	if err != nil {
		return err
	}
	defer st.close()

	d := app.Deps{Store: st, Logger: logger, Now: time.Now, NewID: uuid.NewV7}
	var t store.Tenant
	switch {
	case slug == app.DefaultTenantSlug && createDefault:
		t, err = app.EnsureDefaultTenant(ctx, d)
	case slug == app.DefaultTenantSlug:
		t, err = app.FindTenant(ctx, d, slug)
		if errors.Is(err, app.ErrTenantNotFound) {
			err = fmt.Errorf("%w; it is created when the server first starts or when the first "+
				"record is created", err)
		}
	default:
		t, err = app.FindTenant(ctx, d, slug)
	}
	if err != nil {
		return err
	}
	return fn(ctx, cfg, d, t)
}
