package clavis

import (
	"errors"
	"net/url"
	"strconv"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ui"
	"clavisid.org/clavis/store"
)

// profileField is a field of the profile form: its form name, which is the
// claim name without the address. prefix, the key of its label, how to
// show it, and where its value lives in a profile. Fields come in pairs on
// a wide page unless full is set.
type profileField struct {
	name         string
	claim        string
	label        i18n.Key
	hint         i18n.Key
	typ          string
	lines        bool
	full         bool
	autocomplete string
	value        func(*store.Profile) *string
}

// profileForm lists the sections of the profile form and their fields
// (OpenID Connect Core 1.0, section 5.1). The address is edited by its
// parts; its formatted form is kept as it is.
var profileForm = []struct {
	title  i18n.Key
	fields []profileField
}{
	{i18n.AccountSectionName, []profileField{
		{name: "name", label: i18n.ProfileName, typ: "text", autocomplete: "name", full: true,
			value: func(p *store.Profile) *string { return &p.Name }},
		{name: "given_name", label: i18n.ProfileGivenName, typ: "text", autocomplete: "given-name",
			value: func(p *store.Profile) *string { return &p.GivenName }},
		{name: "family_name", label: i18n.ProfileFamilyName, typ: "text", autocomplete: "family-name",
			value: func(p *store.Profile) *string { return &p.FamilyName }},
		{name: "middle_name", label: i18n.ProfileMiddleName, typ: "text", autocomplete: "additional-name",
			value: func(p *store.Profile) *string { return &p.MiddleName }},
		{name: "nickname", label: i18n.ProfileNickname, typ: "text", autocomplete: "nickname",
			value: func(p *store.Profile) *string { return &p.Nickname }},
		{name: "preferred_username", label: i18n.ProfilePreferredUsername, typ: "text", autocomplete: "off",
			full: true, value: func(p *store.Profile) *string { return &p.PreferredUsername }},
	}},
	{i18n.AccountSectionPersonal, []profileField{
		{name: "gender", label: i18n.ProfileGender, typ: "text", autocomplete: "sex",
			value: func(p *store.Profile) *string { return &p.Gender }},
		{name: "birthdate", label: i18n.ProfileBirthdate, hint: i18n.ProfileBirthdateHint, typ: "text",
			autocomplete: "bday", value: func(p *store.Profile) *string { return &p.Birthdate }},
		{name: "zoneinfo", label: i18n.ProfileZoneinfo, hint: i18n.ProfileZoneinfoHint, typ: "text",
			autocomplete: "off", value: func(p *store.Profile) *string { return &p.Zoneinfo }},
		{name: "locale", label: i18n.ProfileLocale, hint: i18n.ProfileLocaleHint, typ: "text",
			autocomplete: "language", value: func(p *store.Profile) *string { return &p.Locale }},
	}},
	{i18n.AccountSectionContact, []profileField{
		{name: "phone_number", label: i18n.ProfilePhoneNumber, hint: i18n.ProfilePhoneNumberHint, typ: "tel",
			autocomplete: "tel", full: true, value: func(p *store.Profile) *string { return &p.PhoneNumber }},
		{name: "street_address", claim: "address.street_address", label: i18n.ProfileStreetAddress, lines: true,
			autocomplete: "street-address", full: true,
			value: func(p *store.Profile) *string { return &p.Address.StreetAddress }},
		{name: "locality", claim: "address.locality", label: i18n.ProfileLocality, typ: "text",
			autocomplete: "address-level2", value: func(p *store.Profile) *string { return &p.Address.Locality }},
		{name: "region", claim: "address.region", label: i18n.ProfileRegion, typ: "text",
			autocomplete: "address-level1", value: func(p *store.Profile) *string { return &p.Address.Region }},
		{name: "postal_code", claim: "address.postal_code", label: i18n.ProfilePostalCode, typ: "text",
			autocomplete: "postal-code", value: func(p *store.Profile) *string { return &p.Address.PostalCode }},
		{name: "country", claim: "address.country", label: i18n.ProfileCountry, typ: "text",
			autocomplete: "country-name", value: func(p *store.Profile) *string { return &p.Address.Country }},
	}},
	{i18n.AccountSectionLinks, []profileField{
		{name: "profile", label: i18n.ProfileProfileURL, typ: "url", autocomplete: "url", full: true,
			value: func(p *store.Profile) *string { return &p.ProfileURL }},
		{name: "picture", label: i18n.ProfilePicture, typ: "url", autocomplete: "photo", full: true,
			value: func(p *store.Profile) *string { return &p.Picture }},
		{name: "website", label: i18n.ProfileWebsite, typ: "url", autocomplete: "url", full: true,
			value: func(p *store.Profile) *string { return &p.Website }},
	}},
}

// profileSections returns the profile form in the locale of text, filled
// with profile.
func profileSections(text i18n.Printer, profile store.Profile) []ui.ProfileSection {
	sections := make([]ui.ProfileSection, 0, len(profileForm))
	for _, section := range profileForm {
		fields := make([]ui.ProfileField, 0, len(section.fields))
		for _, f := range section.fields {
			field := ui.ProfileField{Name: f.name, Label: text.T(f.label), Value: *f.value(&profile), Type: f.typ,
				Lines: f.lines, Full: f.full, Autocomplete: f.autocomplete}
			if f.hint != "" {
				field.Hint = text.T(f.hint)
			}
			fields = append(fields, field)
		}
		sections = append(sections, ui.ProfileSection{Title: text.T(section.title), Fields: fields})
	}
	return sections
}

// profileFromForm returns current with the values of the posted profile
// form. What the form does not show, such as the formatted address or
// whether the phone number is verified, stays.
func profileFromForm(form url.Values, current store.Profile) store.Profile {
	profile := current
	for _, section := range profileForm {
		for _, f := range section.fields {
			*f.value(&profile) = form.Get(f.name)
		}
	}
	return profile
}

// profileErrors explains, in the locale of text, every claim that err, from
// app.UpdateProfile, refuses.
func profileErrors(text i18n.Printer, err error) []string {
	var problems []error
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		problems = joined.Unwrap()
	} else {
		problems = []error{err}
	}
	labels := make(map[string]i18n.Key)
	for _, section := range profileForm {
		for _, f := range section.fields {
			claim := f.claim
			if claim == "" {
				claim = f.name
			}
			labels[claim] = f.label
		}
	}
	messages := make([]string, 0, len(problems))
	for _, problem := range problems {
		var pe *app.ProfileError
		if !errors.As(problem, &pe) {
			continue
		}
		field := pe.Claim
		if label, ok := labels[pe.Claim]; ok {
			field = text.T(label)
		}
		switch pe.Kind {
		case app.ProfileText:
			messages = append(messages, text.T(i18n.AccountInvalidText, "field", field, "max", strconv.Itoa(app.MaxNameLength)))
		case app.ProfileLines:
			messages = append(messages, text.T(i18n.AccountInvalidLines, "field", field,
				"max", strconv.Itoa(app.MaxProfileLinesLength)))
		case app.ProfileURL:
			messages = append(messages, text.T(i18n.AccountInvalidURL, "field", field))
		case app.ProfileDate:
			messages = append(messages, text.T(i18n.AccountInvalidDate, "field", field))
		case app.ProfileTimeZone:
			messages = append(messages, text.T(i18n.AccountInvalidTimeZone, "field", field))
		case app.ProfileLanguage:
			messages = append(messages, text.T(i18n.AccountInvalidLanguage, "field", field))
		case app.ProfilePhone:
			messages = append(messages, text.T(i18n.AccountInvalidPhone, "field", field))
		}
	}
	return messages
}
