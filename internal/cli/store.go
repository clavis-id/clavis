package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"

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

// openDatabase loads the database and log configuration and opens the store,
// for commands that need no other configuration.
func openDatabase(ctx context.Context, configPath string, environ []string, logOutput io.Writer,
) (*slog.Logger, openedStore, error) {
	cfg, logger, err := setup(ctx, config.LoadDatabase, configPath, environ, logOutput)
	if err != nil {
		return nil, openedStore{}, err
	}
	st, err := openStore(ctx, cfg.Database, cfg.Database.AutoMigrate)
	if err != nil {
		return nil, openedStore{}, err
	}
	return logger, st, nil
}
