package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/language"

	"clavisid.org/clavis/store"
)

// ErrInvalidProfile reports a profile that cannot be stored. Errors that wrap
// it are a *ProfileError, which names the claim.
var ErrInvalidProfile = errors.New("invalid profile")

// ProfileKind is the kind of value that a profile claim holds.
type ProfileKind string

// Kinds of profile values (OpenID Connect Core 1.0, section 5.1).
const (
	// ProfileText is one line of up to MaxNameLength characters.
	ProfileText ProfileKind = "text"
	// ProfileLines is up to MaxProfileLinesLength characters, on several lines.
	ProfileLines ProfileKind = "lines"
	// ProfileURL is an absolute https or http URL.
	ProfileURL ProfileKind = "url"
	// ProfileDate is a date as YYYY-MM-DD, where the year may be 0000, or a
	// year alone as YYYY.
	ProfileDate ProfileKind = "date"
	// ProfileTimeZone is the name of a zone of the IANA time zone database,
	// such as America/Santiago.
	ProfileTimeZone ProfileKind = "time_zone"
	// ProfileLanguage is a BCP 47 language tag, such as es-CL.
	ProfileLanguage ProfileKind = "language"
	// ProfilePhone is a phone number in E.164 form, such as +56912345678,
	// with an optional extension.
	ProfilePhone ProfileKind = "phone"
)

// ProfileError names an invalid claim of a profile and the kind of value it
// needs.
type ProfileError struct {
	// Claim is the name of the claim, such as website or
	// address.postal_code.
	Claim string
	Kind  ProfileKind
}

func (e *ProfileError) Error() string {
	return fmt.Sprintf("invalid profile: %s must be a value of kind %s", e.Claim, e.Kind)
}

func (e *ProfileError) Unwrap() error { return ErrInvalidProfile }

// MaxProfileLinesLength bounds a profile value of kind ProfileLines, in
// characters.
const MaxProfileLinesLength = 500

// Bounds of the other profile values, in bytes.
const (
	maxURLLength      = 2048
	maxTimeZoneLength = 64
	maxLanguageLength = 35
)

var (
	timeZonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9][A-Za-z0-9_+-]*){0,2}$`)
	phonePattern    = regexp.MustCompile(`^\+[1-9]\d{1,14}(;ext=\d{1,10})?$`)
	yearPattern     = regexp.MustCompile(`^\d{4}$`)
)

// NormalizeProfile checks a profile that a user edits and returns it as it
// is stored: surrounding spaces removed, line breaks as \n, the language tag
// in its canonical form and the phone number without the spaces, hyphens,
// dots and parentheses that people use to group digits. Empty values are
// unset. Every value is bounded and holds no control characters other than
// line breaks where lines are allowed, which also keeps U+0000 out of the
// store. phone_number_verified passes through; UpdateProfile decides it.
func NormalizeProfile(p store.Profile) (store.Profile, error) {
	var errs []error
	for _, c := range profileClaims(&p) {
		normalized, ok := normalizeClaim(*c.value, c.kind)
		if !ok {
			errs = append(errs, &ProfileError{Claim: c.name, Kind: c.kind})
			continue
		}
		*c.value = normalized
	}
	if err := errors.Join(errs...); err != nil {
		return store.Profile{}, err
	}
	return p, nil
}

// profileClaim is a text claim of a profile: its name, where p keeps its
// value, and the kind of value it takes.
type profileClaim struct {
	name  string
	value *string
	kind  ProfileKind
}

// profileClaims returns the text claims of p, in the order of OpenID Connect
// Core 1.0, section 5.1, with the parts of the address last.
func profileClaims(p *store.Profile) []profileClaim {
	return []profileClaim{
		{"name", &p.Name, ProfileText},
		{"given_name", &p.GivenName, ProfileText},
		{"family_name", &p.FamilyName, ProfileText},
		{"middle_name", &p.MiddleName, ProfileText},
		{"nickname", &p.Nickname, ProfileText},
		{"preferred_username", &p.PreferredUsername, ProfileText},
		{"profile", &p.ProfileURL, ProfileURL},
		{"picture", &p.Picture, ProfileURL},
		{"website", &p.Website, ProfileURL},
		{"gender", &p.Gender, ProfileText},
		{"birthdate", &p.Birthdate, ProfileDate},
		{"zoneinfo", &p.Zoneinfo, ProfileTimeZone},
		{"locale", &p.Locale, ProfileLanguage},
		{"phone_number", &p.PhoneNumber, ProfilePhone},
		{"address.formatted", &p.Address.Formatted, ProfileLines},
		{"address.street_address", &p.Address.StreetAddress, ProfileLines},
		{"address.locality", &p.Address.Locality, ProfileText},
		{"address.region", &p.Address.Region, ProfileText},
		{"address.postal_code", &p.Address.PostalCode, ProfileText},
		{"address.country", &p.Address.Country, ProfileText},
	}
}

// NormalizeProfileValue returns value as NormalizeProfile stores it for a
// claim of the given kind, and whether it is valid. An empty value is valid.
func NormalizeProfileValue(value string, kind ProfileKind) (string, bool) {
	return normalizeClaim(value, kind)
}

// normalizeClaim is NormalizeProfileValue.
func normalizeClaim(value string, kind ProfileKind) (string, bool) {
	if kind == ProfileLines {
		value = strings.ReplaceAll(value, "\r\n", "\n")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", true
	}
	if !utf8.ValidString(value) {
		return "", false
	}
	for _, r := range value {
		if r == '\n' && kind == ProfileLines {
			continue
		}
		if unicode.In(r, unicode.Cc, unicode.Bidi_Control, unicode.Zl, unicode.Zp) {
			return "", false
		}
	}
	switch kind {
	case ProfileText:
		return value, utf8.RuneCountInString(value) <= MaxNameLength
	case ProfileLines:
		return value, utf8.RuneCountInString(value) <= MaxProfileLinesLength
	case ProfileURL:
		u, err := url.Parse(value)
		return value, len(value) <= maxURLLength && err == nil && (u.Scheme == "https" || u.Scheme == "http") &&
			u.Host != ""
	case ProfileDate:
		if yearPattern.MatchString(value) {
			return value, value != "0000"
		}
		_, err := time.Parse(time.DateOnly, value)
		return value, err == nil
	case ProfileTimeZone:
		return value, len(value) <= maxTimeZoneLength && timeZonePattern.MatchString(value)
	case ProfileLanguage:
		tag, err := language.Parse(value)
		return tag.String(), err == nil && len(value) <= maxLanguageLength
	case ProfilePhone:
		value = strings.Map(func(r rune) rune {
			if strings.ContainsRune(" -.()", r) {
				return -1
			}
			return r
		}, value)
		return value, phonePattern.MatchString(value)
	}
	return "", false
}

// UpdateProfile replaces the profile of user u with p after NormalizeProfile
// and returns the updated user. The phone number stays verified only while
// it does not change; the email address is not part of the profile.
func UpdateProfile(ctx context.Context, d Deps, u store.User, p store.Profile) (store.User, error) {
	normalized, err := NormalizeProfile(p)
	if err != nil {
		return store.User{}, err
	}
	normalized.PhoneNumberVerified = u.Profile.PhoneNumberVerified && normalized.PhoneNumber == u.Profile.PhoneNumber
	changed := changedClaims(u.Profile, normalized)
	u.Profile, u.UpdatedAt = normalized, d.Now()
	switch err := d.Store.Users().Update(ctx, u); {
	case errors.Is(err, store.ErrNotFound):
		return store.User{}, fmt.Errorf("%w: %s", ErrUserNotFound, u.Email)
	case err != nil:
		return store.User{}, fmt.Errorf("updating the profile: %w", err)
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user updated the profile",
		slog.String("tenant_id", u.TenantID.String()), slog.String("user_id", u.ID.String()))
	if changed != "" {
		audit(ctx, d, store.AuditEvent{TenantID: u.TenantID, Type: EventProfileUpdated, Actor: store.ActorUser,
			UserID: u.ID, Details: map[string]string{"claims": changed}})
	}
	return u, nil
}
