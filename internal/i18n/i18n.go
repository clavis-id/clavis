// Package i18n translates the text of the hosted pages and of the email
// messages (ADR 0025). The catalogs are JSON files embedded in the binary,
// one per locale, that map each Key to a message. Messages name their
// placeholders, such as {client}, so that each language can place them
// where its grammar needs them.
package i18n

import (
	"cmp"
	"embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"golang.org/x/text/language"
)

// Locale is a language that Clavis is translated into.
type Locale string

// Supported locales.
const (
	English Locale = "en"
	Spanish Locale = "es"
)

// Default is the locale of a request whose preferences match no supported
// locale.
const Default = English

// Supported returns the supported locales, Default first.
func Supported() []Locale { return []Locale{English, Spanish} }

// Name returns the name of l in its own language, for a language selector.
func (l Locale) Name() string {
	if l == Spanish {
		return "Español"
	}
	return "English"
}

// ParseLocale returns the supported locale named exactly s, such as "es".
func ParseLocale(s string) (Locale, bool) {
	l := Locale(s)
	return l, slices.Contains(Supported(), l)
}

// maxPreferenceBytes bounds the ui_locales and Accept-Language values that
// Match parses; longer ones are ignored.
const maxPreferenceBytes = 1024

//go:embed locales/*.json
var catalogFiles embed.FS

// Catalogs holds the messages of every supported locale. It is safe for
// concurrent use.
type Catalogs struct {
	messages map[Locale]map[Key][]Part
	matcher  language.Matcher
}

// Part is a piece of a message: literal Text, or, when Placeholder is set,
// the place of a value.
type Part struct {
	Text        string
	Placeholder string
}

// Load parses the embedded catalogs. It fails when a message is malformed
// or when a locale lacks a message of the English catalog, has one that it
// lacks, or uses other placeholders.
func Load() (*Catalogs, error) {
	return load(catalogFiles)
}

// load parses the catalogs in fsys, at locales/<locale>.json.
func load(fsys fs.FS) (*Catalogs, error) {
	c := &Catalogs{messages: make(map[Locale]map[Key][]Part)}
	tags := make([]language.Tag, 0, len(Supported()))
	var errs []error
	for _, l := range Supported() {
		data, err := fs.ReadFile(fsys, "locales/"+string(l)+".json")
		if err != nil {
			return nil, fmt.Errorf("i18n: reading the %s catalog: %w", l, err)
		}
		var raw map[string]string
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("i18n: parsing the %s catalog: %w", l, err)
		}
		messages := make(map[Key][]Part, len(raw))
		for _, key := range slices.Sorted(maps.Keys(raw)) {
			parts, err := parse(raw[key])
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %s: %w", l, key, err))
				continue
			}
			messages[Key(key)] = parts
		}
		c.messages[l] = messages
		tags = append(tags, language.Make(string(l)))
	}
	english := c.messages[English]
	for _, l := range Supported()[1:] {
		for _, key := range slices.Sorted(maps.Keys(english)) {
			parts, ok := c.messages[l][key]
			switch {
			case !ok:
				errs = append(errs, fmt.Errorf("%s: %s: missing", l, key))
			case !slices.Equal(placeholders(parts), placeholders(english[key])):
				errs = append(errs, fmt.Errorf("%s: %s: placeholders %v, want %v", l, key,
					placeholders(parts), placeholders(english[key])))
			}
		}
		for _, key := range slices.Sorted(maps.Keys(c.messages[l])) {
			if _, ok := english[key]; !ok {
				errs = append(errs, fmt.Errorf("%s: %s: not in the English catalog", l, key))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("i18n: invalid catalogs: %w", err)
	}
	c.matcher = language.NewMatcher(tags)
	return c, nil
}

// parse splits a message into literal text and placeholders. A placeholder
// is a name of lowercase letters and underscores in braces; other braces
// are not allowed.
func parse(message string) ([]Part, error) {
	if message == "" {
		return nil, errors.New("empty message")
	}
	var parts []Part
	for rest := message; rest != ""; {
		open := strings.IndexAny(rest, "{}")
		if open < 0 {
			parts = append(parts, Part{Text: rest})
			break
		}
		if rest[open] == '}' {
			return nil, errors.New("unmatched }")
		}
		if open > 0 {
			parts = append(parts, Part{Text: rest[:open]})
		}
		name, after, ok := strings.Cut(rest[open+1:], "}")
		if !ok || name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz_") != "" {
			return nil, errors.New("a placeholder must be a name of lowercase letters and underscores in braces")
		}
		parts = append(parts, Part{Placeholder: name})
		rest = after
	}
	return parts, nil
}

// placeholders returns the sorted, distinct placeholder names of a message.
func placeholders(parts []Part) []string {
	var names []string
	for _, p := range parts {
		if p.Placeholder != "" {
			names = append(names, p.Placeholder)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// Match returns the locale of a request: chosen, the locale that the user
// picked with the language selector, when it is supported; otherwise the
// first supported match of uiLocales, the space-separated BCP 47 tags of the
// OpenID Connect ui_locales parameter; otherwise of acceptLanguage, the
// Accept-Language header; otherwise Default.
func (c *Catalogs) Match(chosen, uiLocales, acceptLanguage string) Locale {
	if l, ok := ParseLocale(chosen); ok {
		return l
	}
	if l, ok := c.match(parseUILocales(uiLocales)); ok {
		return l
	}
	if len(acceptLanguage) <= maxPreferenceBytes {
		if tags, _, err := language.ParseAcceptLanguage(acceptLanguage); err == nil {
			if l, ok := c.match(tags); ok {
				return l
			}
		}
	}
	return Default
}

func (c *Catalogs) match(tags []language.Tag) (Locale, bool) {
	if len(tags) == 0 {
		return "", false
	}
	_, i, confidence := c.matcher.Match(tags...)
	if confidence == language.No {
		return "", false
	}
	return Supported()[i], true
}

// parseUILocales returns the valid tags of a ui_locales value, in order of
// preference (OpenID Connect Core 1.0, section 3.1.2.1). Invalid tags are
// skipped: the parameter only expresses a preference.
func parseUILocales(s string) []language.Tag {
	if len(s) > maxPreferenceBytes {
		return nil
	}
	var tags []language.Tag
	for f := range strings.FieldsSeq(s) {
		if tag, err := language.Parse(f); err == nil {
			tags = append(tags, tag)
		}
	}
	return tags
}

// Printer returns the messages of locale l, or of Default when l is not
// supported.
func (c *Catalogs) Printer(l Locale) Printer {
	messages, ok := c.messages[l]
	if !ok {
		l, messages = Default, c.messages[Default]
	}
	return Printer{locale: l, messages: messages}
}

// Printer writes the messages of one locale. The zero Printer has no
// messages and writes keys instead.
type Printer struct {
	locale   Locale
	messages map[Key][]Part
}

// Locale returns the locale of p.
func (p Printer) Locale() Locale { return cmp.Or(p.locale, Default) }

// T returns the message of key with its placeholders replaced by args,
// which are pairs of a placeholder name and its value. An unknown key
// returns the key, and a placeholder without a value stays in braces, so a
// mistake shows on the page instead of failing the request; tests look for
// both.
func (p Printer) T(key Key, args ...string) string {
	parts, ok := p.messages[key]
	if !ok {
		return string(key)
	}
	var b strings.Builder
	for _, part := range parts {
		if part.Placeholder == "" {
			b.WriteString(part.Text)
			continue
		}
		value, found := "{"+part.Placeholder+"}", false
		for i := 0; i+1 < len(args) && !found; i += 2 {
			if args[i] == part.Placeholder {
				value, found = args[i+1], true
			}
		}
		b.WriteString(value)
	}
	return b.String()
}

// Parts returns the pieces of the message of key, for a page that renders
// its placeholders with markup. An unknown key returns the key as text.
func (p Printer) Parts(key Key) []Part {
	parts, ok := p.messages[key]
	if !ok {
		return []Part{{Text: string(key)}}
	}
	return slices.Clone(parts)
}
