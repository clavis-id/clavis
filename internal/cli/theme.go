package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/store"
)

// colorNames lists the names that --color and --dark-color accept.
func colorNames() string {
	var names []string
	for _, c := range (store.ThemeColors{}).List() {
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

func newThemeCommand(environ []string, configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "theme",
		Short: "Manage how the hosted pages of a tenant look",
		Long: "Manage the branding of a tenant's hosted pages (ADR 0025): colors for the light and dark\n" +
			"color schemes, the corner radius and a logo. Values left unset keep the defaults.",
		Args: cobra.NoArgs,
	}
	run := func(cmd *cobra.Command, slug string, createDefault bool,
		fn func(context.Context, config.Config, app.Deps, store.Tenant, io.Writer) error,
	) error {
		return withTenant(cmd, config.LoadDatabase, configPathOrEnv(*configPath, environ), environ, slug, createDefault,
			func(ctx context.Context, cfg config.Config, d app.Deps, t store.Tenant) error {
				return fn(ctx, cfg, d, t, cmd.OutOrStdout())
			})
	}

	show := &cobra.Command{
		Use:   "show SLUG",
		Short: "Show the theme and the logo of a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args[0], false, showTheme)
		},
	}

	var colors, darkColors []string
	var radius int
	set := &cobra.Command{
		Use:   "set SLUG",
		Short: "Set colors and the corner radius of a tenant's pages",
		Long: "Set colors and the corner radius of a tenant's pages; other values stay as they are.\n" +
			"Colors are #rrggbb. An empty color, as in --color accent=, returns it to the default.\n" +
			"Color names: " + colorNames() + ".",
		Example: "  clavis tenants theme set acme --color accent=#0b5cad --dark-color accent=#4493f8 --radius 6",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(colors) == 0 && len(darkColors) == 0 && !cmd.Flags().Changed("radius") {
				return errors.New("nothing to set: pass --color, --dark-color or --radius")
			}
			return run(cmd, args[0], true, func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant,
				out io.Writer,
			) error {
				b, err := app.TenantBranding(ctx, d, t.ID)
				if err != nil {
					return err
				}
				theme := b.Theme
				if err := setColors(&theme.Light, "--color", colors); err != nil {
					return err
				}
				if err := setColors(&theme.Dark, "--dark-color", darkColors); err != nil {
					return err
				}
				if cmd.Flags().Changed("radius") {
					theme.Radius = &radius
				}
				if err := app.SetTheme(ctx, d, t.ID, theme); err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Set the theme of tenant %s.\n", t.Slug))
			})
		},
	}
	set.Flags().StringArrayVar(&colors, "color", nil, "a color of the light color scheme, as NAME=#rrggbb (repeatable)")
	set.Flags().StringArrayVar(&darkColors, "dark-color", nil,
		"a color of the dark color scheme, as NAME=#rrggbb (repeatable)")
	set.Flags().IntVar(&radius, "radius", 0,
		fmt.Sprintf("corner radius in pixels, from 0 to %d", app.MaxThemeRadius))

	var remove bool
	logo := &cobra.Command{
		Use:   "logo SLUG [FILE]",
		Short: "Set or remove the logo of a tenant's pages",
		Long: fmt.Sprintf("Set the logo of a tenant's pages from a PNG, JPEG or WebP file of at most %d KiB\n"+
			"and %d by %d pixels, or remove it with --remove.", app.MaxLogoBytes>>10, app.MaxLogoPixels,
			app.MaxLogoPixels),
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case remove && len(args) == 2:
				return errors.New("pass either FILE or --remove")
			case remove:
				return run(cmd, args[0], false, func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant,
					out io.Writer,
				) error {
					if err := app.RemoveLogo(ctx, d, t.ID); err != nil {
						return err
					}
					return write(out, fmt.Sprintf("Removed the logo of tenant %s.\n", t.Slug))
				})
			case len(args) == 1:
				return errors.New("FILE is required, or --remove")
			}
			data, err := readLogo(args[1])
			if err != nil {
				return err
			}
			return run(cmd, args[0], true, func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant,
				out io.Writer,
			) error {
				logo, err := app.SetLogo(ctx, d, t.ID, data)
				if err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Set the logo of tenant %s (%s, %d bytes).\n", t.Slug,
					logo.ContentType, len(logo.Data)))
			})
		},
	}
	logo.Flags().BoolVar(&remove, "remove", false, "remove the logo")

	var confirmed bool
	reset := &cobra.Command{
		Use:   "reset SLUG",
		Short: "Return a tenant's pages to the default look",
		Long:  "Remove the theme and the logo of a tenant, whose pages then look like the defaults. Pass --yes\nto confirm.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmed {
				return fmt.Errorf("resetting tenant %q removes its theme and its logo; run the command again "+
					"with --yes to confirm", args[0])
			}
			return run(cmd, args[0], false, func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant,
				out io.Writer,
			) error {
				if err := app.ResetBranding(ctx, d, t.ID); err != nil {
					return err
				}
				return write(out, fmt.Sprintf("Reset the theme and the logo of tenant %s.\n", t.Slug))
			})
		},
	}
	reset.Flags().BoolVar(&confirmed, "yes", false, "confirm the reset")

	cmd.AddCommand(show, set, logo, reset)
	return cmd
}

// setColors applies values, each NAME=#rrggbb from the flag named flag, to
// colors.
func setColors(colors *store.ThemeColors, flag string, values []string) error {
	for _, v := range values {
		name, value, ok := strings.Cut(v, "=")
		if !ok || !colors.Set(name, value) {
			return fmt.Errorf("%s %q: want NAME=#rrggbb, with NAME one of %s", flag, v, colorNames())
		}
	}
	return nil
}

// readLogo reads a logo file, reading no more than one byte past the limit
// so that a large file fails validation without being read whole.
func readLogo(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file to read.
	if err != nil {
		return nil, fmt.Errorf("reading the logo: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, app.MaxLogoBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the logo: %w", err)
	}
	return data, nil
}

func showTheme(ctx context.Context, cfg config.Config, d app.Deps, t store.Tenant, out io.Writer) error {
	b, err := app.TenantBranding(ctx, d, t.ID)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Tenant:\t%s\n", t.Slug)
	_, _ = fmt.Fprintf(tw, "Light colors:\t%s\n", describeColors(b.Theme.Light))
	_, _ = fmt.Fprintf(tw, "Dark colors:\t%s\n", describeColors(b.Theme.Dark))
	radius := "default"
	if b.Theme.Radius != nil {
		radius = strconv.Itoa(*b.Theme.Radius) + "px"
	}
	_, _ = fmt.Fprintf(tw, "Radius:\t%s\n", radius)
	logo := "none"
	if b.LogoType != "" {
		issuer := strings.TrimSuffix(cfg.Issuer, "/")
		if t.Slug != app.DefaultTenantSlug {
			issuer += "/t/" + t.Slug
		}
		name, _ := app.LogoName(b.LogoType, b.LogoHash)
		logo = fmt.Sprintf("%s, %s/branding/%s", b.LogoType, issuer, name)
	}
	_, _ = fmt.Fprintf(tw, "Logo:\t%s\n", logo)
	return flush(tw)
}

// describeColors lists the colors that c sets, or says that it keeps the
// defaults.
func describeColors(c store.ThemeColors) string {
	var set []string
	for _, color := range c.List() {
		if color.Value != "" {
			set = append(set, color.Name+" "+color.Value)
		}
	}
	if len(set) == 0 {
		return "default"
	}
	return strings.Join(set, ", ")
}
