package app

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
	"uuid"

	"github.com/google/go-cmp/cmp"

	"clavisid.org/clavis/store"
)

// testWebP is a lossless WebP image of one pixel.
const testWebP = "UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA=="

func encodedImage(t testing.TB, format string, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 11, G: 92, B: 173, A: 255})
	var b bytes.Buffer
	var err error
	switch format {
	case "png":
		err = png.Encode(&b, img)
	case "jpeg":
		err = jpeg.Encode(&b, img, nil)
	case "webp":
		var data []byte
		data, err = base64.StdEncoding.DecodeString(testWebP)
		b.Write(data)
	}
	if err != nil {
		t.Fatalf("encoding a %s image: %v", format, err)
	}
	return b.Bytes()
}

func TestBranding(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)

	got, err := TenantBranding(t.Context(), d, tn.ID)
	if err != nil || !cmp.Equal(got, store.Branding{TenantID: tn.ID}) {
		t.Fatalf("TenantBranding() without a branding = %+v, %v; want the defaults", got, err)
	}

	radius := 4
	theme := store.Theme{Light: store.ThemeColors{Accent: "#0B5CAD"}, Dark: store.ThemeColors{Accent: "#4493f8"},
		Radius: &radius}
	if err := SetTheme(t.Context(), d, tn.ID, theme); err != nil {
		t.Fatalf("SetTheme() unexpected error: %v", err)
	}
	logo, err := SetLogo(t.Context(), d, tn.ID, encodedImage(t, "png", 64, 32))
	if err != nil {
		t.Fatalf("SetLogo() unexpected error: %v", err)
	}
	if logo.ContentType != "image/png" || len(logo.Hash) != 12 {
		t.Errorf("SetLogo() = %s, %q", logo.ContentType, logo.Hash)
	}
	got, err = TenantBranding(t.Context(), d, tn.ID)
	want := store.Branding{
		TenantID: tn.ID,
		Theme: store.Theme{Light: store.ThemeColors{Accent: "#0b5cad"}, Dark: store.ThemeColors{Accent: "#4493f8"},
			Radius: &radius},
		LogoType:  "image/png",
		LogoHash:  logo.Hash,
		UpdatedAt: d.Now(),
	}
	if err != nil || !cmp.Equal(want, got) {
		t.Errorf("TenantBranding() = %+v, %v; want %+v", got, err, want)
	}
	if stored, err := TenantLogo(t.Context(), d, tn.ID); err != nil || !cmp.Equal(logo, stored) {
		t.Errorf("TenantLogo() = %+v, %v", stored, err)
	}

	if err := RemoveLogo(t.Context(), d, tn.ID); err != nil {
		t.Fatalf("RemoveLogo() unexpected error: %v", err)
	}
	if err := RemoveLogo(t.Context(), d, tn.ID); !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("a second RemoveLogo() = %v, want ErrLogoNotFound", err)
	}
	if _, err := TenantLogo(t.Context(), d, tn.ID); !errors.Is(err, ErrLogoNotFound) {
		t.Errorf("TenantLogo() after RemoveLogo() = %v, want ErrLogoNotFound", err)
	}
	if err := ResetBranding(t.Context(), d, tn.ID); err != nil {
		t.Fatalf("ResetBranding() unexpected error: %v", err)
	}
	if err := ResetBranding(t.Context(), d, tn.ID); !errors.Is(err, ErrNoTenantBranding) {
		t.Errorf("a second ResetBranding() = %v, want ErrNoTenantBranding", err)
	}

	unknown := uuid.NewV7()
	if err := SetTheme(t.Context(), d, unknown, theme); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("SetTheme() for an unknown tenant = %v, want ErrTenantNotFound", err)
	}
	if _, err := SetLogo(t.Context(), d, unknown, encodedImage(t, "png", 1, 1)); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("SetLogo() for an unknown tenant = %v, want ErrTenantNotFound", err)
	}
	if err := SetTheme(t.Context(), d, tn.ID, store.Theme{Light: store.ThemeColors{Text: "red"}}); !errors.Is(err, ErrInvalidTheme) {
		t.Errorf("SetTheme() with an invalid color = %v, want ErrInvalidTheme", err)
	}
	if _, err := SetLogo(t.Context(), d, tn.ID, []byte("<svg/>")); !errors.Is(err, ErrInvalidLogo) {
		t.Errorf("SetLogo() with an SVG = %v, want ErrInvalidLogo", err)
	}
}

func TestValidateTheme(t *testing.T) {
	t.Parallel()
	zero, largest, tooLarge, negative := 0, MaxThemeRadius, MaxThemeRadius+1, -1
	valid := []store.Theme{
		{},
		{Light: store.ThemeColors{Accent: "#0b5cad", AccentText: "#FFFFFF", Error: "#b42318"}, Radius: &zero},
		{Dark: store.ThemeColors{Background: "#0d1117", Border: "#30363d"}, Radius: &largest},
	}
	for _, theme := range valid {
		if err := ValidateTheme(theme); err != nil {
			t.Errorf("ValidateTheme(%+v) = %v", theme, err)
		}
	}
	for name, theme := range map[string]store.Theme{
		"named color":      {Light: store.ThemeColors{Accent: "blue"}},
		"short color":      {Light: store.ThemeColors{Accent: "#fff"}},
		"color with alpha": {Dark: store.ThemeColors{Surface: "#ffffff80"}},
		"CSS injection":    {Dark: store.ThemeColors{Text: "#fff;}body{display:none"}},
		"not hexadecimal":  {Light: store.ThemeColors{Muted: "#gggggg"}},
		"radius too large": {Radius: &tooLarge},
		"negative radius":  {Radius: &negative},
		"several problems": {Light: store.ThemeColors{Accent: "x"}, Dark: store.ThemeColors{Accent: "y"}},
		"missing hash":     {Light: store.ThemeColors{Border: "0b5cadd"}},
	} {
		err := ValidateTheme(theme)
		if !errors.Is(err, ErrInvalidTheme) {
			t.Errorf("%s: ValidateTheme() = %v, want ErrInvalidTheme", name, err)
		}
	}
	err := ValidateTheme(store.Theme{Light: store.ThemeColors{Accent: "x"}, Dark: store.ThemeColors{Error: "y"}})
	if err == nil || !strings.Contains(err.Error(), "light.accent") || !strings.Contains(err.Error(), "dark.error") {
		t.Errorf("ValidateTheme() = %v, want every problem named", err)
	}
}

func TestValidateLogo(t *testing.T) {
	t.Parallel()
	for format, want := range map[string]string{"png": "image/png", "jpeg": "image/jpeg", "webp": "image/webp"} {
		if got, err := ValidateLogo(encodedImage(t, format, 16, 16)); err != nil || got != want {
			t.Errorf("ValidateLogo(%s) = %q, %v; want %q", format, got, err, want)
		}
	}
	if _, err := ValidateLogo(encodedImage(t, "png", MaxLogoPixels, 1)); err != nil {
		t.Errorf("ValidateLogo() of the widest image: %v", err)
	}
	valid := encodedImage(t, "png", 8, 8)
	for name, data := range map[string][]byte{
		"empty":         nil,
		"too large":     append(bytes.Clone(valid), make([]byte, MaxLogoBytes)...),
		"too wide":      encodedImage(t, "png", MaxLogoPixels+1, 1),
		"too high":      encodedImage(t, "png", 1, MaxLogoPixels+1),
		"SVG":           []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"GIF":           []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00;"),
		"HTML":          []byte("<!DOCTYPE html><title>x</title>"),
		"truncated PNG": valid[:len(valid)/2],
		"PNG header":    valid[:8],
		"WebP header":   []byte("RIFF\x00\x00\x00\x00WEBP"),
	} {
		if _, err := ValidateLogo(data); !errors.Is(err, ErrInvalidLogo) {
			t.Errorf("%s: ValidateLogo() = %v, want ErrInvalidLogo", name, err)
		}
	}
}

func FuzzValidateLogo(f *testing.F) {
	for _, format := range []string{"png", "jpeg", "webp"} {
		f.Add(encodedImage(f, format, 2, 2))
	}
	f.Add([]byte("RIFF\x10\x00\x00\x00WEBPVP8X"))
	f.Fuzz(func(t *testing.T, data []byte) {
		contentType, err := ValidateLogo(data)
		if err == nil && contentType != "image/png" && contentType != "image/jpeg" && contentType != "image/webp" {
			t.Fatalf("ValidateLogo() = %q", contentType)
		}
	})
}
