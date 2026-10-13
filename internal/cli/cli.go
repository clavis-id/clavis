// Package cli implements the clavis command-line interface.
package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clavis-id/clavis"
	"github.com/clavis-id/clavis/internal/config"
	"github.com/clavis-id/clavis/internal/logging"
	"github.com/clavis-id/clavis/internal/server"
	"github.com/clavis-id/clavis/internal/version"
	"github.com/clavis-id/clavis/kek"
)

// Execute runs the command described by args and returns the process exit
// code. environ holds the environment in os.Environ format.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer, environ []string) int {
	root := newRootCommand(environ) //nolint:contextcheck // Commands receive ctx through ExecuteContext and cmd.Context().
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func newRootCommand(environ []string) *cobra.Command {
	root := &cobra.Command{
		Use:           "clavis",
		Short:         "Clavis is an OpenID Connect provider and OAuth 2.1 authorization server",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newServeCommand(environ), newMigrateCommand(environ), newKeysCommand(), newVersionCommand())
	return root
}

// configHelp describes where commands read their configuration from.
const configHelp = "Configuration is read from the file given by --config (or " + config.EnvConfigFile + ")\n" +
	"and overridden by " + config.EnvPrefix + "* environment variables."

func newServeCommand(environ []string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Clavis HTTP server",
		Long:  "Run the Clavis HTTP server until it receives an interrupt or termination signal.\n\n" + configHelp,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), configPathOrEnv(configPath, environ), environ, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	return cmd
}

func newMigrateCommand(environ []string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending database migrations and exit",
		Long: "Apply pending database migrations and exit. Use it as a deployment step when\n" +
			"database.auto_migrate is false.\n\n" + configHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return migrate(cmd.Context(), configPathOrEnv(configPath, environ), environ, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	return cmd
}

// setup loads the configuration and builds the logger shared by commands.
func setup(ctx context.Context, configPath string, environ []string, logOutput io.Writer) (config.Config, *slog.Logger, error) {
	res, err := config.Load(configPath, environ)
	if err != nil {
		return config.Config{}, nil, err
	}
	logger, err := logging.New(logOutput, res.Config.Log.Level, res.Config.Log.Format)
	if err != nil {
		return config.Config{}, nil, err
	}
	for _, name := range res.IgnoredEnv {
		logger.LogAttrs(ctx, slog.LevelWarn, "ignoring environment variable that matches no configuration key",
			slog.String("name", name))
	}
	return res.Config, logger, nil
}

func serve(ctx context.Context, configPath string, environ []string, logOutput io.Writer) error {
	cfg, logger, err := setup(ctx, configPath, environ, logOutput)
	if err != nil {
		return err
	}

	st, err := openStore(ctx, cfg.Database, cfg.Database.AutoMigrate)
	if err != nil {
		return err
	}
	defer st.close()

	enc, err := newEncrypter(cfg.Keys)
	if err != nil {
		return err
	}

	srv, err := clavis.New(ctx, clavis.Config{
		Issuer:       cfg.Issuer,
		Store:        st,
		KeyEncrypter: enc,
		SigningKeys: clavis.SigningKeyPolicy{
			Algorithms:     cfg.Keys.Algorithms,
			RotationPeriod: cfg.Keys.RotationPeriod,
			PublishAhead:   cfg.Keys.PublishAhead,
			Retention:      cfg.Keys.Retention,
			CheckInterval:  cfg.Keys.CheckInterval,
		},
		Logger: logger,
	})
	if err != nil {
		return err
	}

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", cfg.Server.Address)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.Server.Address, err)
	}

	info := version.Get()
	logger.LogAttrs(ctx, slog.LevelInfo, "starting clavis",
		slog.String("version", info.Version),
		slog.String("issuer", srv.Issuer()),
		slog.String("database_driver", cfg.Database.Driver))

	return server.Serve(ctx, ln, server.Options{
		Handler:           srv.Handler(),
		Logger:            logger,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ShutdownTimeout:   cfg.Server.ShutdownTimeout,
	})
}

func migrate(ctx context.Context, configPath string, environ []string, logOutput io.Writer) error {
	cfg, logger, err := setup(ctx, configPath, environ, logOutput)
	if err != nil {
		return err
	}
	st, err := openStore(ctx, cfg.Database, false)
	if err != nil {
		return err
	}
	defer st.close()

	if err := st.Migrate(ctx); err != nil {
		return err
	}
	logger.LogAttrs(ctx, slog.LevelInfo, "database migrations applied",
		slog.String("database_driver", cfg.Database.Driver))
	return nil
}

func newKeysCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage key material",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "new-encryption-key",
		Short: "Print a new random encryption key for keys.encryption_key",
		Long: "Print a new random 32-byte encryption key, base64 encoded, for the\n" +
			"keys.encryption_key setting (" + config.EnvPrefix + "KEYS_ENCRYPTION_KEY). Store it in a\n" +
			"secrets manager: losing it makes every stored signing key unreadable.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret := kek.GenerateSecret()
			defer clear(secret)
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(secret)); err != nil {
				return fmt.Errorf("writing key: %w", err)
			}
			return nil
		},
	})
	return cmd
}

// newEncrypter builds the key encrypter from the keys configuration, which
// Load has already validated.
func newEncrypter(cfg config.Keys) (*kek.Local, error) {
	primary, err := kek.ParseSecret(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("keys.encryption_key: %w", err)
	}
	previous := make([][]byte, 0, len(cfg.PreviousEncryptionKeys))
	for i, encoded := range cfg.PreviousEncryptionKeys {
		secret, err := kek.ParseSecret(encoded)
		if err != nil {
			return nil, fmt.Errorf("keys.previous_encryption_keys[%d]: %w", i, err)
		}
		previous = append(previous, secret)
	}
	enc, err := kek.NewLocal(primary, previous...)
	if err != nil {
		return nil, fmt.Errorf("building key encrypter: %w", err)
	}
	return enc, nil
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "clavis %s\n", info.Version)
			if info.Commit != "" {
				modified := ""
				if info.Modified {
					modified = " (modified)"
				}
				_, _ = fmt.Fprintf(out, "commit: %s%s\n", info.Commit, modified)
			}
			if _, err := fmt.Fprintf(out, "go: %s\n", info.GoVersion); err != nil {
				return fmt.Errorf("writing version: %w", err)
			}
			return nil
		},
	}
}

// configPathOrEnv returns flagValue, or the configuration file named by the
// environment when the flag is not set.
func configPathOrEnv(flagValue string, environ []string) string {
	if flagValue != "" {
		return flagValue
	}
	return lookupEnv(environ, config.EnvConfigFile)
}

// lookupEnv returns the value of name in environ, or "" when it is unset.
func lookupEnv(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}
