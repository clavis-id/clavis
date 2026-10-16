package cli

import (
	"context"
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

func newResourcesCommand(environ []string) *cobra.Command {
	var configPath, tenant string
	cmd := &cobra.Command{
		Use:   "resources",
		Short: "Manage API resources",
		Long: "Manage the API resources of a tenant directly in the configured database. An API\n" +
			"resource defines scopes; access tokens that grant them carry its identifier in aud.\n\n" + configHelp,
		Args: cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	cmd.PersistentFlags().StringVar(&tenant, "tenant", app.DefaultTenantSlug, "slug of the tenant that owns the resources")
	run := func(cmd *cobra.Command, createDefault bool,
		fn func(context.Context, app.Deps, store.Tenant, io.Writer) error,
	) error {
		return withTenant(cmd, config.LoadDatabase, configPathOrEnv(configPath, environ), environ, tenant, createDefault,
			func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant) error {
				return fn(ctx, d, t, cmd.OutOrStdout())
			})
	}

	var spec app.APIResourceSpec
	create := &cobra.Command{
		Use:   "create IDENTIFIER",
		Short: "Register an API resource",
		Long: "Register an API resource. IDENTIFIER is an absolute URI, such as\n" +
			"https://api.example.com/orders, which becomes the aud of its access tokens. Each scope\n" +
			"belongs to one resource of the tenant, and OpenID Connect scopes belong to none.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec.Identifier = args[0]
			return run(cmd, true, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				r, err := app.CreateAPIResource(ctx, d, t.ID, spec)
				if err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Created API resource %s in tenant %s with scopes %s.\n",
					r.Identifier, t.Slug, strings.Join(r.Scopes, " ")))
			})
		},
	}
	create.Flags().StringVar(&spec.Name, "name", "", "display name (defaults to the identifier)")
	create.Flags().StringArrayVar(&spec.Scopes, "scope", nil, "scope the resource defines; repeat for several")

	list := &cobra.Command{
		Use:   "list",
		Short: "List API resources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, false, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				resources, err := app.ListAPIResources(ctx, d, t.ID)
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "IDENTIFIER\tNAME\tSCOPES\tCREATED")
				for _, r := range resources {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Identifier, r.Name, strings.Join(r.Scopes, " "),
						r.CreatedAt.Format(time.RFC3339))
				}
				return flush(tw)
			})
		},
	}

	var confirmed bool
	remove := &cobra.Command{
		Use:   "delete IDENTIFIER",
		Short: "Delete an API resource",
		Long: "Delete an API resource. Clients can no longer obtain tokens for its scopes; tokens\n" +
			"issued earlier stay valid until they expire. Pass --yes to confirm.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmed {
				return fmt.Errorf("deleting API resource %q stops clients from obtaining tokens for it; run "+
					"the command again with --yes to confirm", args[0])
			}
			return run(cmd, false, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				if err := app.DeleteAPIResource(ctx, d, t.ID, args[0]); err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Deleted API resource %s from tenant %s.\n", args[0], t.Slug))
			})
		},
	}
	remove.Flags().BoolVar(&confirmed, "yes", false, "confirm the deletion")

	cmd.AddCommand(create, list, remove)
	return cmd
}
