package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/store"
)

func newGrantsCommand(environ []string) *cobra.Command {
	var configPath, tenant, email string
	cmd := &cobra.Command{
		Use:   "grants",
		Short: "Manage the grants of users",
		Long: "Manage the grants of a user directly in the configured database. A grant records the\n" +
			"scopes a user allowed a client on the consent page.\n\n" + configHelp,
		Args: cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	cmd.PersistentFlags().StringVar(&tenant, "tenant", app.DefaultTenantSlug, "slug of the tenant of the user")
	cmd.PersistentFlags().StringVar(&email, "user", "", "email address of the user (required)")
	run := func(cmd *cobra.Command, fn func(context.Context, app.Deps, store.Tenant, io.Writer) error) error {
		if email == "" {
			return errors.New("--user is required")
		}
		return withTenant(cmd, config.LoadDatabase, configPathOrEnv(configPath, environ), environ, tenant, false,
			func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant) error {
				return fn(ctx, d, t, cmd.OutOrStdout())
			})
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List the grants of a user",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				grants, err := app.ListGrants(ctx, d, t.ID, email)
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "CLIENT ID\tSCOPES\tGRANTED\tUPDATED")
				for _, g := range grants {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.Client.ClientID, strings.Join(g.Scopes, " "),
						g.CreatedAt.Format(time.RFC3339), g.UpdatedAt.Format(time.RFC3339))
				}
				return flush(tw)
			})
		},
	}

	var confirmed bool
	revoke := &cobra.Command{
		Use:   "revoke CLIENT_ID",
		Short: "Revoke the grant of a user for a client",
		Long: "Revoke the grant of a user for a client, and the access tokens issued to the client for\n" +
			"the user. The next sign-in to the client asks the user for consent again. Pass --yes to\n" +
			"confirm.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmed {
				return fmt.Errorf("revoking the grant of %s for %q also revokes the client's access tokens for "+
					"the user; run the command again with --yes to confirm", email, args[0])
			}
			return run(cmd, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				if err := app.RevokeGrant(ctx, d, t.ID, email, args[0]); err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Revoked the grant of %s for %s in tenant %s.\n", email, args[0], t.Slug))
			})
		},
	}
	revoke.Flags().BoolVar(&confirmed, "yes", false, "confirm the revocation")

	cmd.AddCommand(list, revoke)
	return cmd
}
