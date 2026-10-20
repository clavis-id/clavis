package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

func mustLoad(t testing.TB) *Catalogs {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	return c
}

// declaredKeys returns the values of the Key constants in keys.go.
func declaredKeys(t *testing.T) []Key {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "keys.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing keys.go: %v", err)
	}
	var keys []Key
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			for _, value := range spec.(*ast.ValueSpec).Values {
				lit, ok := value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("keys.go: a key is not a string literal")
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("keys.go: %v", err)
				}
				keys = append(keys, Key(s))
			}
		}
	}
	slices.Sort(keys)
	return keys
}

// The embedded catalogs load, which means every locale has every English
// message with the same placeholders, and the English catalog defines
// exactly the keys that keys.go declares.
func TestCatalogsDefineEveryKey(t *testing.T) {
	t.Parallel()
	c := mustLoad(t)
	declared := declaredKeys(t)
	if len(declared) == 0 {
		t.Fatal("keys.go declares no keys")
	}
	for _, l := range Supported() {
		if diff := cmp.Diff(declared, slices.Sorted(maps.Keys(c.messages[l]))); diff != "" {
			t.Errorf("keys of the %s catalog (-declared +catalog):\n%s", l, diff)
		}
	}
}

func TestLoadReportsCatalogProblems(t *testing.T) {
	t.Parallel()
	catalogs := func(en, es string) fstest.MapFS {
		return fstest.MapFS{
			"locales/en.json": {Data: []byte(en)},
			"locales/es.json": {Data: []byte(es)},
		}
	}
	for name, tt := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"missing message": {catalogs(`{"a": "A", "b": "B"}`, `{"a": "A"}`), "es: b: missing"},
		"extra message":   {catalogs(`{"a": "A"}`, `{"a": "A", "b": "B"}`), "es: b: not in the English catalog"},
		"other placeholders": {catalogs(`{"a": "Hi {name}"}`, `{"a": "Hola {nombre}"}`),
			"es: a: placeholders [nombre], want [name]"},
		"malformed placeholder": {catalogs(`{"a": "Hi {Name}"}`, `{"a": "Hola {Name}"}`), "en: a: a placeholder"},
		"stray brace":           {catalogs(`{"a": "A}"}`, `{"a": "A"}`), "en: a: unmatched }"},
		"empty message":         {catalogs(`{"a": ""}`, `{"a": "A"}`), "en: a: empty message"},
		"duplicate key":         {catalogs(`{"a": "A", "a": "B"}`, `{"a": "A"}`), "parsing the en catalog"},
		"missing catalog":       {fstest.MapFS{"locales/en.json": {Data: []byte(`{}`)}}, "reading the es catalog"},
	} {
		_, err := load(tt.fsys)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: load() = %v, want an error with %q", name, err, tt.want)
		}
	}
	if _, err := load(catalogs(`{"a": "{x} and {y}, {x}"}`, `{"a": "{y} y {x}"}`)); err != nil {
		t.Errorf("load() with reordered and repeated placeholders: %v", err)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	got, err := parse("{client} wants {account}.")
	want := []Part{{Placeholder: "client"}, {Text: " wants "}, {Placeholder: "account"}, {Text: "."}}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("parse() = %v, %v; want %v", got, err, want)
	}
	for _, message := range []string{"{", "a {b", "{}", "{a-b}", "{A}", "a } b", "{a {b}}"} {
		if _, err := parse(message); err == nil {
			t.Errorf("parse(%q) succeeded, want an error", message)
		}
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()
	c := mustLoad(t)
	for _, tt := range []struct {
		chosen, uiLocales, acceptLanguage string
		want                              Locale
	}{
		{"", "", "", English},
		{"", "", "es-CL,es;q=0.9,en;q=0.8", Spanish},
		{"", "", "en-US,en;q=0.9,es;q=0.8", English},
		{"", "", "de-DE,de;q=0.9", English},
		{"", "", "de,es;q=0.5", Spanish},
		{"", "", "not a header", English},
		{"", "es-419 en", "en", Spanish},
		{"", "fr es", "en", Spanish},
		{"", "fr", "es", Spanish},
		{"", "!!! es", "", Spanish},
		{"", strings.Repeat("x ", 600) + "es", "", English},
		{"es", "en", "en", Spanish},
		{"en", "es", "es", English},
		{"fr", "", "es", Spanish},
		{"ES", "", "", English},
		{"", "", strings.Repeat("a,", 600) + "es", English},
	} {
		if got := c.Match(tt.chosen, tt.uiLocales, tt.acceptLanguage); got != tt.want {
			t.Errorf("Match(%q, %q, %q) = %s, want %s", tt.chosen, tt.uiLocales, tt.acceptLanguage, got, tt.want)
		}
	}
}

func TestPrinter(t *testing.T) {
	t.Parallel()
	c := mustLoad(t)
	en, es := c.Printer(English), c.Printer(Spanish)
	if got := en.T(ConsentLead, "client", "Shop", "account", "ada@example.com"); got !=
		"Shop wants to access the account ada@example.com." {
		t.Errorf("T() = %q", got)
	}
	if got := es.T(ScopeResource, "scope", "orders:read", "resource", "Orders"); got != "Usar Orders (orders:read)" {
		t.Errorf("T() = %q", got)
	}
	if got := en.T(LoginLead); got != "to continue to {client}" {
		t.Errorf("T() without a value = %q, want the placeholder", got)
	}
	if got := en.T("no.such.key"); got != "no.such.key" {
		t.Errorf("T() of an unknown key = %q", got)
	}
	if got := c.Printer("fr"); got.Locale() != English || got.T(LoginTitle) != "Sign in" {
		t.Errorf("Printer(fr) = %s, %q; want English", got.Locale(), got.T(LoginTitle))
	}
	var zero Printer
	if zero.Locale() != English || zero.T(LoginTitle) != string(LoginTitle) {
		t.Errorf("zero Printer = %s, %q", zero.Locale(), zero.T(LoginTitle))
	}

	parts := es.Parts(LoginLead)
	if want := []Part{{Text: "para continuar en "}, {Placeholder: "client"}}; !slices.Equal(parts, want) {
		t.Errorf("Parts() = %v, want %v", parts, want)
	}
	parts[0].Text = "changed"
	if es.T(LoginLead) != "para continuar en {client}" {
		t.Error("changing the result of Parts() changed the catalog")
	}
	if got := en.Parts("no.such.key"); !slices.Equal(got, []Part{{Text: "no.such.key"}}) {
		t.Errorf("Parts() of an unknown key = %v", got)
	}
}

func TestLocales(t *testing.T) {
	t.Parallel()
	if got := Supported(); got[0] != Default {
		t.Errorf("Supported() = %v, want %s first", got, Default)
	}
	for s, want := range map[string]bool{"en": true, "es": true, "fr": false, "": false, "EN": false, "es-ES": false} {
		if _, ok := ParseLocale(s); ok != want {
			t.Errorf("ParseLocale(%q) = %v, want %v", s, ok, want)
		}
	}
	if English.Name() != "English" || Spanish.Name() != "Español" {
		t.Errorf("names: %s, %s", English.Name(), Spanish.Name())
	}
}

func FuzzMatch(f *testing.F) {
	c := mustLoad(f)
	f.Add("", "es-419 en", "en-US,en;q=0.9")
	f.Add("es", "", "da, en-gb;q=0.8, en;q=0.7")
	f.Add("", "zh-Hant-TW x-private", "*;q=0.5")
	f.Fuzz(func(t *testing.T, chosen, uiLocales, acceptLanguage string) {
		if l := c.Match(chosen, uiLocales, acceptLanguage); !slices.Contains(Supported(), l) {
			t.Fatalf("Match() = %q, not a supported locale", l)
		}
	})
}
