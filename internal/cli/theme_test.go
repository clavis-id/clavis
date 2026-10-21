package cli

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThemeCommands(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	environ := []string{"CLAVIS_ISSUER=https://auth.example.com", "CLAVIS_DATABASE_DSN=" + filepath.Join(dir, "clavis.db")}
	run := func(args ...string) (stdout, stderr string, code int) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), append([]string{"tenants", "theme"}, args...), nil, &out, &errOut, environ)
		return out.String(), errOut.String(), code
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, testImage(48, 16)); err != nil {
		t.Fatalf("encoding the logo: %v", err)
	}
	logo, text := filepath.Join(dir, "logo.png"), filepath.Join(dir, "logo.svg")
	if err := os.WriteFile(logo, encoded.Bytes(), 0o600); err != nil {
		t.Fatalf("writing the logo: %v", err)
	}
	if err := os.WriteFile(text, []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0o600); err != nil {
		t.Fatalf("writing the logo: %v", err)
	}

	// The default tenant can be branded before the server first starts.
	out, errOut, code := run("set", "default", "--color", "accent=#0B5CAD", "--dark-color", "accent=#4493f8",
		"--radius", "6")
	if code != 0 || !strings.Contains(out, "Set the theme of tenant default") {
		t.Fatalf("theme set = %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, errOut, code = run("set", "default", "--color", "text=#1b1f24"); code != 0 {
		t.Fatalf("a second theme set = %d, stderr %q", code, errOut)
	}
	if out, errOut, code = run("logo", "default", logo); code != 0 || !strings.Contains(out, "image/png") {
		t.Fatalf("theme logo = %d, stdout %q, stderr %q", code, out, errOut)
	}
	out, errOut, code = run("show", "default")
	for _, want := range []string{"accent #0b5cad, text #1b1f24", "accent #4493f8", "6px",
		"image/png, https://auth.example.com/branding/logo-"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("theme show = %d, stdout %q, stderr %q; want %q", code, out, errOut, want)
		}
	}
	// An empty value returns a color to the default.
	if _, errOut, code = run("set", "default", "--color", "text="); code != 0 {
		t.Fatalf("theme set with an empty color = %d, stderr %q", code, errOut)
	}
	if out, _, _ = run("show", "default"); strings.Contains(out, "text #") {
		t.Errorf("theme show after clearing a color: %q", out)
	}

	for name, tt := range map[string]struct {
		args []string
		want string
	}{
		"nothing to set":    {[]string{"set", "default"}, "nothing to set"},
		"unknown color":     {[]string{"set", "default", "--color", "link=#000000"}, "NAME one of accent"},
		"no value":          {[]string{"set", "default", "--color", "accent"}, "want NAME=#rrggbb"},
		"invalid color":     {[]string{"set", "default", "--color", "accent=blue"}, "light.accent"},
		"radius too large":  {[]string{"set", "default", "--radius", "40"}, "radius"},
		"unknown tenant":    {[]string{"set", "acme", "--radius", "4"}, "tenant not found"},
		"missing logo file": {[]string{"logo", "default", filepath.Join(dir, "missing.png")}, "reading the logo"},
		"not an image":      {[]string{"logo", "default", text}, "PNG, JPEG or WebP"},
		"no file":           {[]string{"logo", "default"}, "FILE is required"},
		"file and --remove": {[]string{"logo", "default", logo, "--remove"}, "either FILE or --remove"},
		"reset without yes": {[]string{"reset", "default"}, "--yes"},
		"show unknown":      {[]string{"show", "acme"}, "tenant not found"},
	} {
		if _, errOut, code := run(tt.args...); code != 1 || !strings.Contains(errOut, tt.want) {
			t.Errorf("%s: theme %v = %d, stderr %q; want %q", name, tt.args, code, errOut, tt.want)
		}
	}

	if out, errOut, code = run("logo", "default", "--remove"); code != 0 || !strings.Contains(out, "Removed the logo") {
		t.Errorf("theme logo --remove = %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, errOut, code = run("logo", "default", "--remove"); code != 1 || !strings.Contains(errOut, "logo not found") {
		t.Errorf("a second theme logo --remove = %d, stderr %q", code, errOut)
	}
	if out, errOut, code = run("reset", "default", "--yes"); code != 0 || !strings.Contains(out, "Reset the theme") {
		t.Errorf("theme reset = %d, stdout %q, stderr %q", code, out, errOut)
	}
	out, _, _ = run("show", "default")
	for _, want := range []string{"Light colors:  default", "Radius:        default", "Logo:          none"} {
		if !strings.Contains(out, want) {
			t.Errorf("theme show after the reset = %q, want %q", out, want)
		}
	}
	if _, errOut, code = run("reset", "default", "--yes"); code != 1 || !strings.Contains(errOut, "no branding") {
		t.Errorf("a second theme reset = %d, stderr %q", code, errOut)
	}
}

func testImage(width, height int) image.Image {
	return image.NewRGBA(image.Rect(0, 0, width, height))
}
