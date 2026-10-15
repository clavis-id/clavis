package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/store"
)

// passwordInputHelp explains where commands read passwords from.
const passwordInputHelp = "The password is read from the terminal without echo, twice, or from the first\n" +
	"line of standard input when it is not a terminal. It is never taken from arguments, which\n" +
	"other users of the machine can see."

func newUsersCommand(environ []string) *cobra.Command {
	var configPath, tenant string
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
		Long:  "Manage the users of a tenant directly in the configured database.\n\n" + configHelp,
		Args:  cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	cmd.PersistentFlags().StringVar(&tenant, "tenant", app.DefaultTenantSlug, "slug of the tenant that owns the users")
	run := func(cmd *cobra.Command, createDefault bool,
		fn func(context.Context, config.Config, app.Deps, store.Tenant) error,
	) error {
		return withTenant(cmd, config.LoadPasswords, configPathOrEnv(configPath, environ), environ, tenant,
			createDefault, fn)
	}

	var (
		spec         app.UserSpec
		withPassword bool
	)
	create := &cobra.Command{
		Use:   "create EMAIL",
		Short: "Create a user",
		Long:  "Create an active user. With --with-password, also set a password.\n\n" + passwordInputHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec.Email = args[0]
			return run(cmd, true, func(ctx context.Context, cfg config.Config, d app.Deps, t store.Tenant) error {
				var h *password.Hasher
				var pw string
				if withPassword {
					// Read the password first, so a rejected one leaves no user
					// behind.
					var err error
					if h, err = password.New(cfg.Passwords.Policy()); err != nil {
						return err
					}
					if pw, err = readNewPassword(cmd, h); err != nil {
						return err
					}
				}
				u, err := app.CreateUser(ctx, d, t.ID, spec)
				if err != nil {
					return err
				}
				msg := fmt.Sprintf("Created user %s in tenant %s (ID %s).\n", u.Email, t.Slug, u.ID)
				if withPassword {
					if err := app.SetPassword(ctx, d, h, u, pw); err != nil {
						return fmt.Errorf("user %s was created, but setting the password failed: %w", u.Email, err)
					}
					msg += "Password set.\n"
				}
				return write(cmd.OutOrStdout(), msg)
			})
		},
	}
	f := create.Flags()
	f.StringVar(&spec.Name, "name", "", "full name (the name claim)")
	f.StringVar(&spec.GivenName, "given-name", "", "given name")
	f.StringVar(&spec.FamilyName, "family-name", "", "family name")
	f.BoolVar(&spec.EmailVerified, "email-verified", false, "mark the email address as verified")
	f.BoolVar(&withPassword, "with-password", false, "also set a password")

	setPassword := &cobra.Command{
		Use:   "set-password EMAIL",
		Short: "Set the password of a user",
		Long:  "Set the password of a user, replacing the current one.\n\n" + passwordInputHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, false, func(ctx context.Context, cfg config.Config, d app.Deps, t store.Tenant) error {
				u, err := app.FindUser(ctx, d, t.ID, args[0])
				if err != nil {
					return err
				}
				h, err := password.New(cfg.Passwords.Policy())
				if err != nil {
					return err
				}
				pw, err := readNewPassword(cmd, h)
				if err != nil {
					return err
				}
				if err := app.SetPassword(ctx, d, h, u, pw); err != nil {
					return err
				}
				return write(cmd.OutOrStdout(), fmt.Sprintf("Set the password of %s.\n", u.Email))
			})
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, false, func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant) error {
				users, err := app.ListUsers(ctx, d, t.ID)
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(tw, "EMAIL\tNAME\tSTATUS\tEMAIL VERIFIED\tID\tCREATED")
				for _, u := range users {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", u.Email, u.Profile.Name, u.Status,
						strconv.FormatBool(u.EmailVerified), u.ID, u.CreatedAt.Format(time.RFC3339))
				}
				return flush(tw)
			})
		},
	}

	var confirmed bool
	remove := &cobra.Command{
		Use:   "delete EMAIL",
		Short: "Delete a user and the user's credentials",
		Long:  "Delete a user together with the user's credentials. Pass --yes to confirm.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmed {
				return fmt.Errorf("deleting user %q removes the account and its credentials; run the command "+
					"again with --yes to confirm", args[0])
			}
			return run(cmd, false, func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant) error {
				if err := app.DeleteUser(ctx, d, t.ID, args[0]); err != nil {
					return err
				}
				return write(cmd.OutOrStdout(), fmt.Sprintf("Deleted user %s from tenant %s.\n", args[0], t.Slug))
			})
		},
	}
	remove.Flags().BoolVar(&confirmed, "yes", false, "confirm the deletion")

	cmd.AddCommand(create, setPassword, list, remove)
	return cmd
}

// readNewPassword reads a password as passwordInputHelp describes and checks
// it against the policy of h.
func readNewPassword(cmd *cobra.Command, h *password.Hasher) (string, error) {
	pw, err := readPassword(cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	if err := h.CheckNew(pw); err != nil {
		return "", err
	}
	return pw, nil
}

// readPassword reads a password from in, which is a terminal or a pipe.
// Prompts go to prompts.
func readPassword(in io.Reader, prompts io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		_, _ = fmt.Fprint(prompts, "Password: ")
		first, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(prompts)
		if err != nil {
			return "", fmt.Errorf("reading the password: %w", err)
		}
		_, _ = fmt.Fprint(prompts, "Repeat the password: ")
		second, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(prompts)
		if err != nil {
			return "", fmt.Errorf("reading the password: %w", err)
		}
		if !bytes.Equal(first, second) {
			return "", errors.New("the passwords do not match")
		}
		return string(first), nil
	}

	// One line, bounded so that a stream that never ends cannot exhaust
	// memory; a longer line fails the policy check.
	line, err := bufio.NewReader(io.LimitReader(in, 64*1024)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading the password from standard input: %w", err)
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line == "" {
		return "", errors.New("no password on standard input; pipe one line, or run the command in a terminal")
	}
	return line, nil
}
