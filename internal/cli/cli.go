// Package cli implements the clavis command-line interface.
package cli

import (
	"context"
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
	root.AddCommand(newServeCommand(environ), newVersionCommand())
	return root
}

func newServeCommand(environ []string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Clavis HTTP server",
		Long: "Run the Clavis HTTP server until it receives an interrupt or termination signal.\n\n" +
			"Configuration is read from the file given by --config (or " + config.EnvConfigFile + ")\n" +
			"and overridden by " + config.EnvPrefix + "* environment variables.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath == "" {
				configPath = lookupEnv(environ, config.EnvConfigFile)
			}
			return serve(cmd.Context(), configPath, environ, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	return cmd
}

func serve(ctx context.Context, configPath string, environ []string, logOutput io.Writer) error {
	res, err := config.Load(configPath, environ)
	if err != nil {
		return err
	}
	cfg := res.Config

	logger, err := logging.New(logOutput, cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return err
	}
	for _, name := range res.IgnoredEnv {
		logger.LogAttrs(ctx, slog.LevelWarn, "ignoring environment variable that matches no configuration key",
			slog.String("name", name))
	}

	srv, err := clavis.New(ctx, clavis.Config{Issuer: cfg.Issuer, Logger: logger})
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
		slog.String("issuer", srv.Issuer()))

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

// lookupEnv returns the value of name in environ, or "" when it is unset.
func lookupEnv(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}
