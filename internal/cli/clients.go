package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"uuid"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/store"
)

func newClientsCommand(environ []string) *cobra.Command {
	var configPath, tenant string
	cmd := &cobra.Command{
		Use:   "clients",
		Short: "Manage OAuth clients",
		Long:  "Manage the OAuth clients of a tenant directly in the configured database.\n\n" + configHelp,
		Args:  cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	cmd.PersistentFlags().StringVar(&tenant, "tenant", app.DefaultTenantSlug, "slug of the tenant that owns the clients")
	// run opens the database, resolves the tenant and calls fn. Only create
	// passes createDefault: the server creates the default tenant when it
	// first starts, and its signing keys on every start, so clients can be
	// registered before that. The other commands report a missing default
	// tenant, which also reveals a mistyped database location.
	run := func(cmd *cobra.Command, createDefault bool,
		fn func(context.Context, app.Deps, store.Tenant, io.Writer) error,
	) error {
		ctx := cmd.Context()
		logger, st, err := openDatabase(ctx, configPathOrEnv(configPath, environ), environ, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		defer st.close()
		d := app.Deps{Store: st, Logger: logger, Now: time.Now, NewID: uuid.NewV7}
		var t store.Tenant
		switch {
		case tenant == app.DefaultTenantSlug && createDefault:
			t, err = app.EnsureDefaultTenant(ctx, d)
		case tenant == app.DefaultTenantSlug:
			t, err = app.FindTenant(ctx, d, tenant)
			if errors.Is(err, app.ErrTenantNotFound) {
				err = fmt.Errorf("%w; it is created when the server first starts or when the first "+
					"client is created", err)
			}
		default:
			t, err = app.FindTenant(ctx, d, tenant)
		}
		if err != nil {
			return err
		}
		return fn(ctx, d, t, cmd.OutOrStdout())
	}

	var (
		spec       app.ClientSpec
		clientType string
	)
	create := &cobra.Command{
		Use:   "create",
		Short: "Register a client",
		Long: "Register a client. Clavis generates the secret of a confidential client and prints it\n" +
			"once; store it right away, because only its hash is kept.\n\n" +
			"Without --grant-type, the client may use the authorization_code and refresh_token\n" +
			"grants. Without --scope, a client that signs users in may request openid, profile\n" +
			"and email, and offline_access when it may use refresh tokens. Lifetimes of 0 use the\n" +
			"defaults.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec.Type = store.ClientType(clientType)
			return run(cmd, true, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				c, secret, err := app.CreateClient(ctx, d, t.ID, spec)
				if err != nil {
					return err
				}
				if c.PKCEExempt {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: client %s may send authorization requests "+
						"without PKCE. Use this only for a confidential client that validates the OpenID "+
						"Connect nonce.\n", c.ClientID)
				}
				var b strings.Builder
				fmt.Fprintf(&b, "Created client %s in tenant %s.\nClient ID: %s\n", c.ClientID, t.Slug, c.ClientID)
				if secret != "" {
					b.WriteString("Client secret: " + secret + "\n\n" + storeSecretNow)
				}
				return write(out, b.String())
			})
		},
	}
	f := create.Flags()
	f.StringVar(&spec.ClientID, "client-id", "", "client identifier (generated when empty)")
	f.StringVar(&spec.Name, "name", "", "display name (defaults to the client ID)")
	f.StringVar(&clientType, "type", string(store.ClientConfidential), "client type: confidential or public")
	f.StringArrayVar(&spec.RedirectURIs, "redirect-uri", nil, "redirect URI; repeat for several")
	f.StringArrayVar(&spec.PostLogoutRedirectURIs, "post-logout-redirect-uri", nil,
		"post-logout redirect URI; repeat for several")
	f.StringArrayVar(&spec.GrantTypes, "grant-type", nil,
		"grant type: authorization_code, refresh_token or client_credentials; repeat for several")
	f.StringArrayVar(&spec.Scopes, "scope", nil, "scope the client may request; repeat for several")
	f.DurationVar(&spec.Lifetimes.AccessToken, "access-token-lifetime", 0, "access token lifetime")
	f.DurationVar(&spec.Lifetimes.IDToken, "id-token-lifetime", 0, "ID token lifetime")
	f.DurationVar(&spec.Lifetimes.RefreshTokenIdle, "refresh-token-idle-lifetime", 0,
		"how long an unused refresh token stays valid")
	f.DurationVar(&spec.Lifetimes.RefreshTokenAbsolute, "refresh-token-absolute-lifetime", 0,
		"how long a chain of refresh tokens stays valid in total")
	f.BoolVar(&spec.SkipConsent, "skip-consent", false, "do not ask users for consent (first-party clients)")
	f.BoolVar(&spec.PKCEExempt, "pkce-exempt", false,
		"accept authorization requests without PKCE (confidential clients that validate the nonce)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List clients",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, false, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				clients, err := app.ListClients(ctx, d, t.ID)
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "CLIENT ID\tNAME\tTYPE\tGRANT TYPES\tPKCE\tCREATED")
				for _, c := range clients {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.ClientID, c.Name, c.Type,
						strings.Join(c.GrantTypes, ","), pkcePolicy(c), c.CreatedAt.Format(time.RFC3339))
				}
				return flush(tw)
			})
		},
	}

	show := &cobra.Command{
		Use:   "show CLIENT_ID",
		Short: "Show the settings of a client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, false, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				c, err := app.GetClient(ctx, d, t.ID, args[0])
				if err != nil {
					return err
				}
				return showClient(out, t, c)
			})
		},
	}

	var confirmedRotate bool
	rotate := &cobra.Command{
		Use:   "rotate-secret CLIENT_ID",
		Short: "Replace the secret of a confidential client",
		Long: "Replace the secret of a confidential client and print the new one once. The previous\n" +
			"secret stops working immediately. Pass --yes to confirm.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmedRotate {
				return fmt.Errorf("rotating the secret of client %q makes the current secret stop working "+
					"immediately; run the command again with --yes to confirm", args[0])
			}
			return run(cmd, false, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				secret, err := app.RotateClientSecret(ctx, d, t.ID, args[0])
				if err != nil {
					return err
				}
				return write(out, "New client secret: "+secret+"\n\n"+storeSecretNow)
			})
		},
	}
	rotate.Flags().BoolVar(&confirmedRotate, "yes", false, "confirm the rotation")

	var confirmedDelete bool
	remove := &cobra.Command{
		Use:   "delete CLIENT_ID",
		Short: "Delete a client",
		Long:  "Delete a client. It can no longer obtain tokens. Pass --yes to confirm.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmedDelete {
				return fmt.Errorf("deleting client %q stops it from obtaining tokens; run the command "+
					"again with --yes to confirm", args[0])
			}
			return run(cmd, false, func(ctx context.Context, d app.Deps, t store.Tenant, out io.Writer) error {
				if err := app.DeleteClient(ctx, d, t.ID, args[0]); err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Deleted client %s from tenant %s.\n", args[0], t.Slug))
			})
		},
	}
	remove.Flags().BoolVar(&confirmedDelete, "yes", false, "confirm the deletion")

	cmd.AddCommand(create, list, show, rotate, remove)
	return cmd
}

// storeSecretNow follows every printed client secret.
const storeSecretNow = "Store the client secret now: it cannot be shown again.\n"

// pkcePolicy describes whether a client must use PKCE (ADR 0018).
func pkcePolicy(c store.Client) string {
	if c.PKCEExempt {
		return "exempt"
	}
	return "required"
}

// hasSecret says whether a client has a secret, which is never shown again.
func hasSecret(c store.Client) string {
	if len(c.SecretHash) == 0 {
		return "none"
	}
	return "set (shown only when created or rotated)"
}

func showClient(out io.Writer, t store.Tenant, c store.Client) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	row := func(name string, values ...string) {
		if len(values) == 0 {
			values = []string{"(none)"}
		}
		_, _ = fmt.Fprintf(tw, "%s:\t%s\n", name, values[0])
		for _, v := range values[1:] {
			_, _ = fmt.Fprintf(tw, "\t%s\n", v)
		}
	}
	consent := "required"
	if c.SkipConsent {
		consent = "skipped"
	}
	pkce := pkcePolicy(c)
	if c.PKCEExempt {
		pkce = "not required (exempt)"
	}
	lifetime := func(d time.Duration) string {
		if d == 0 {
			return "default"
		}
		return d.String()
	}
	row("Client ID", c.ClientID)
	row("Name", c.Name)
	row("Tenant", t.Slug)
	row("Type", string(c.Type))
	row("Client secret", hasSecret(c))
	row("Grant types", c.GrantTypes...)
	row("Redirect URIs", c.RedirectURIs...)
	row("Post-logout redirect URIs", c.PostLogoutRedirectURIs...)
	row("Scopes", c.Scopes...)
	row("PKCE", pkce)
	row("Consent", consent)
	row("Access token lifetime", lifetime(c.Lifetimes.AccessToken))
	row("ID token lifetime", lifetime(c.Lifetimes.IDToken))
	row("Refresh token idle lifetime", lifetime(c.Lifetimes.RefreshTokenIdle))
	row("Refresh token absolute lifetime", lifetime(c.Lifetimes.RefreshTokenAbsolute))
	row("Created", c.CreatedAt.Format(time.RFC3339))
	row("Updated", c.UpdatedAt.Format(time.RFC3339))
	return flush(tw)
}

func write(out io.Writer, s string) error {
	if _, err := io.WriteString(out, s); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func flush(tw *tabwriter.Writer) error {
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
