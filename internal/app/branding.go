package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"log/slog"
	"strings"
	"uuid"

	"golang.org/x/image/webp"

	"clavisid.org/clavis/store"
)

// Bounds of a tenant's branding (ADR 0025).
const (
	// MaxLogoBytes bounds the size of a logo file.
	MaxLogoBytes = 128 << 10
	// MaxLogoPixels bounds the width and the height of a logo.
	MaxLogoPixels = 1024
	// MaxThemeRadius bounds the corner radius, in CSS pixels.
	MaxThemeRadius = 32
)

// Errors returned by the branding use cases.
var (
	ErrInvalidTheme     = errors.New("invalid theme")
	ErrInvalidLogo      = errors.New("invalid logo")
	ErrLogoNotFound     = errors.New("logo not found")
	ErrNoTenantBranding = errors.New("the tenant has no branding")
)

// logoFormats are the image formats a logo can have, by the signature its
// file starts with. SVG is not among them: an SVG image is a document that
// can hold scripts and links.
var logoFormats = []struct {
	contentType string
	matches     func([]byte) bool
	decode      func(*bytes.Reader) (image.Image, error)
	config      func(*bytes.Reader) (image.Config, error)
}{
	{
		"image/png",
		func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) },
		func(r *bytes.Reader) (image.Image, error) { return png.Decode(r) },
		func(r *bytes.Reader) (image.Config, error) { return png.DecodeConfig(r) },
	},
	{
		"image/jpeg",
		func(b []byte) bool { return bytes.HasPrefix(b, []byte("\xff\xd8\xff")) },
		func(r *bytes.Reader) (image.Image, error) { return jpeg.Decode(r) },
		func(r *bytes.Reader) (image.Config, error) { return jpeg.DecodeConfig(r) },
	},
	{
		"image/webp",
		func(b []byte) bool { return len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP" },
		func(r *bytes.Reader) (image.Image, error) { return webp.Decode(r) },
		func(r *bytes.Reader) (image.Config, error) { return webp.DecodeConfig(r) },
	},
}

// LogoName returns the name under which a logo with the given media type
// and content hash is published. The name changes with the content, so
// browsers can cache the logo for good. ok is false for a media type that a
// logo cannot have.
func LogoName(contentType, hash string) (name string, ok bool) {
	ext, ok := map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp"}[contentType]
	if !ok || hash == "" {
		return "", false
	}
	return "logo-" + hash + ext, true
}

// TenantBranding returns the branding of a tenant, or the zero Branding,
// which keeps every default, when the tenant has none. The Cache of d keeps
// it for TenantCacheTTL.
func TenantBranding(ctx context.Context, d Deps, tenantID uuid.UUID) (store.Branding, error) {
	return cached(d.Cache.brandingMap(), tenantID, d.Now(), func() (store.Branding, error) {
		b, err := d.Store.Brandings().Get(ctx, tenantID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return store.Branding{TenantID: tenantID}, nil
		case err != nil:
			return store.Branding{}, fmt.Errorf("getting the branding: %w", err)
		}
		return b, nil
	})
}

// TenantLogo returns the logo of a tenant, or ErrLogoNotFound. The Cache of
// d keeps the answer for TenantCacheTTL.
func TenantLogo(ctx context.Context, d Deps, tenantID uuid.UUID) (store.Logo, error) {
	found, err := cached(d.Cache.logoMap(), tenantID, d.Now(), func() (cachedLogo, error) {
		logo, err := d.Store.Brandings().GetLogo(ctx, tenantID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return cachedLogo{}, nil
		case err != nil:
			return cachedLogo{}, fmt.Errorf("getting the logo: %w", err)
		}
		return cachedLogo{logo: logo, found: true}, nil
	})
	switch {
	case err != nil:
		return store.Logo{}, err
	case !found.found:
		return store.Logo{}, ErrLogoNotFound
	}
	return found.logo, nil
}

// ValidateTheme reports whether a theme can be stored: every color is
// #rrggbb, in any case, and the radius is between 0 and MaxThemeRadius.
// Errors wrap ErrInvalidTheme.
func ValidateTheme(theme store.Theme) error {
	var errs []error
	for _, scheme := range []struct {
		name   string
		colors store.ThemeColors
	}{{"light", theme.Light}, {"dark", theme.Dark}} {
		for _, c := range scheme.colors.List() {
			if c.Value != "" && !hexColor(c.Value) {
				errs = append(errs, fmt.Errorf("%s.%s: must be a color as #rrggbb, got %q", scheme.name, c.Name, c.Value))
			}
		}
	}
	if theme.Radius != nil && (*theme.Radius < 0 || *theme.Radius > MaxThemeRadius) {
		errs = append(errs, fmt.Errorf("radius: must be between 0 and %d pixels, got %d", MaxThemeRadius, *theme.Radius))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTheme, err)
	}
	return nil
}

// hexColor reports whether s is a color as #rrggbb.
func hexColor(s string) bool {
	return len(s) == 7 && s[0] == '#' && strings.Trim(s[1:], "0123456789abcdefABCDEF") == ""
}

// SetTheme validates a theme and makes it the theme of a tenant, which
// keeps its logo. Colors are stored in lowercase.
func SetTheme(ctx context.Context, d Deps, tenantID uuid.UUID, theme store.Theme) error {
	if err := ValidateTheme(theme); err != nil {
		return err
	}
	for _, colors := range []*store.ThemeColors{&theme.Light, &theme.Dark} {
		for _, c := range colors.List() {
			colors.Set(c.Name, strings.ToLower(c.Value))
		}
	}
	err := d.Store.Brandings().PutTheme(ctx, tenantID, theme, d.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrTenantNotFound
	case err != nil:
		return fmt.Errorf("storing the theme: %w", err)
	}
	d.Cache.forgetBranding(tenantID)
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "set tenant theme", slog.String("tenant_id", tenantID.String()))
	return nil
}

// ValidateLogo checks that data is a PNG, JPEG or WebP image of at most
// MaxLogoBytes and MaxLogoPixels in each direction, and returns its media
// type. Errors wrap ErrInvalidLogo.
func ValidateLogo(data []byte) (string, error) {
	if len(data) == 0 || len(data) > MaxLogoBytes {
		return "", fmt.Errorf("%w: the file must have 1 to %d bytes", ErrInvalidLogo, MaxLogoBytes)
	}
	for _, f := range logoFormats {
		if !f.matches(data) {
			continue
		}
		// The dimensions are checked before the image is decoded, which
		// bounds the memory that decoding takes.
		cfg, err := f.config(bytes.NewReader(data))
		switch {
		case err != nil:
			return "", fmt.Errorf("%w: reading the %s image: %w", ErrInvalidLogo, f.contentType, err)
		case cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxLogoPixels || cfg.Height > MaxLogoPixels:
			return "", fmt.Errorf("%w: the image must be at most %d by %d pixels, got %d by %d", ErrInvalidLogo,
				MaxLogoPixels, MaxLogoPixels, cfg.Width, cfg.Height)
		}
		if _, err := f.decode(bytes.NewReader(data)); err != nil {
			return "", fmt.Errorf("%w: decoding the %s image: %w", ErrInvalidLogo, f.contentType, err)
		}
		return f.contentType, nil
	}
	return "", fmt.Errorf("%w: the file must be a PNG, JPEG or WebP image", ErrInvalidLogo)
}

// SetLogo validates an image and makes it the logo of a tenant, which keeps
// its theme.
func SetLogo(ctx context.Context, d Deps, tenantID uuid.UUID, data []byte) (store.Logo, error) {
	contentType, err := ValidateLogo(data)
	if err != nil {
		return store.Logo{}, err
	}
	sum := sha256.Sum256(data)
	logo := store.Logo{ContentType: contentType, Data: bytes.Clone(data), Hash: hex.EncodeToString(sum[:6])}
	err = d.Store.Brandings().PutLogo(ctx, tenantID, logo, d.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Logo{}, ErrTenantNotFound
	case err != nil:
		return store.Logo{}, fmt.Errorf("storing the logo: %w", err)
	}
	d.Cache.forgetBranding(tenantID)
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "set tenant logo", slog.String("tenant_id", tenantID.String()),
		slog.String("content_type", contentType), slog.Int("bytes", len(data)))
	return logo, nil
}

// RemoveLogo removes the logo of a tenant, which keeps its theme. It
// returns ErrLogoNotFound when the tenant has no logo.
func RemoveLogo(ctx context.Context, d Deps, tenantID uuid.UUID) error {
	err := d.Store.Brandings().DeleteLogo(ctx, tenantID, d.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrLogoNotFound
	case err != nil:
		return fmt.Errorf("removing the logo: %w", err)
	}
	d.Cache.forgetBranding(tenantID)
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "removed tenant logo", slog.String("tenant_id", tenantID.String()))
	return nil
}

// ResetBranding removes the theme and the logo of a tenant, whose pages then
// use the defaults. It returns ErrNoTenantBranding when there is nothing to
// remove.
func ResetBranding(ctx context.Context, d Deps, tenantID uuid.UUID) error {
	err := d.Store.Brandings().Delete(ctx, tenantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNoTenantBranding
	case err != nil:
		return fmt.Errorf("removing the branding: %w", err)
	}
	d.Cache.forgetBranding(tenantID)
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "reset tenant branding", slog.String("tenant_id", tenantID.String()))
	return nil
}
