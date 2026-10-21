package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"
	"uuid"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/internal/keys"
)

func newTenantsCommand(environ []string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "tenants",
		Short: "Manage tenants",
		Long: "Manage tenants directly in the configured database. The default tenant is served\n" +
			"at the issuer and every other tenant at <issuer>/t/<slug>.\n\n" + configHelp,
		Args: cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	path := func() string { return configPathOrEnv(configPath, environ) }

	var name string
	create := &cobra.Command{
		Use:   "create SLUG",
		Short: "Create a tenant and its signing keys",
		Long: "Create a tenant and its signing keys. The slug becomes part of the tenant's issuer:\n" +
			"1 to 63 lowercase letters, digits and hyphens, starting with a letter. The slugs\n" +
			"default and admin are reserved. Needs the full configuration, including\n" +
			"keys.encryption_key, to encrypt the new keys.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return createTenant(cmd.Context(), path(), environ, args[0], name, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	create.Flags().StringVar(&name, "name", "", "display name (defaults to the slug)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List tenants",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listTenants(cmd.Context(), path(), environ, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	var confirmed bool
	remove := &cobra.Command{
		Use:   "delete SLUG",
		Short: "Delete a tenant and everything it owns",
		Long: "Delete a tenant together with its signing keys and every other record it owns.\n" +
			"Tokens it issued can no longer be verified. The default tenant cannot be deleted.\n" +
			"Pass --yes to confirm.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmed {
				return fmt.Errorf("deleting tenant %q removes its keys and every record it owns; "+
					"run the command again with --yes to confirm", args[0])
			}
			return deleteTenant(cmd.Context(), path(), environ, args[0], cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	remove.Flags().BoolVar(&confirmed, "yes", false, "confirm the deletion")

	cmd.AddCommand(create, list, remove, newThemeCommand(environ, &configPath))
	return cmd
}

func createTenant(ctx context.Context, configPath string, environ []string, slug, name string,
	out, logOutput io.Writer,
) error {
	// The full configuration is needed: new signing keys are encrypted with
	// the key encryption key.
	cfg, logger, err := setup(ctx, config.Load, configPath, environ, logOutput)
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

	deps := app.Deps{Store: st, Logger: logger, Now: time.Now, NewID: uuid.NewV7}
	manager, err := keys.NewManager(keys.Config{
		Store:     st,
		Encrypter: enc,
		Policy:    cfg.Keys.Policy(),
		Logger:    logger,
		Now:       deps.Now,
		NewID:     deps.NewID,
	})
	if err != nil {
		return err
	}
	t, err := app.CreateTenant(ctx, deps, manager.Rotate, slug, name)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Created tenant %s (%s).\nIssuer: %s/t/%s\n", t.Slug, t.ID, cfg.Issuer, t.Slug)
	if err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func listTenants(ctx context.Context, configPath string, environ []string, out, logOutput io.Writer) error {
	cfg, logger, err := setup(ctx, config.LoadDatabase, configPath, environ, logOutput)
	if err != nil {
		return err
	}
	st, err := openStore(ctx, cfg.Database, cfg.Database.AutoMigrate)
	if err != nil {
		return err
	}
	defer st.close()

	tenants, err := app.ListTenants(ctx, app.Deps{Store: st, Logger: logger})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SLUG\tNAME\tID\tCREATED")
	for _, t := range tenants {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Slug, t.Name, t.ID, t.CreatedAt.Format(time.RFC3339))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func deleteTenant(ctx context.Context, configPath string, environ []string, slug string,
	out, logOutput io.Writer,
) error {
	cfg, logger, err := setup(ctx, config.LoadDatabase, configPath, environ, logOutput)
	if err != nil {
		return err
	}
	st, err := openStore(ctx, cfg.Database, cfg.Database.AutoMigrate)
	if err != nil {
		return err
	}
	defer st.close()

	if err := app.DeleteTenant(ctx, app.Deps{Store: st, Logger: logger}, slug); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Deleted tenant %s.\n", slug); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
