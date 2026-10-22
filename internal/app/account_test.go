package app

import (
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"

	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

func TestNormalizeProfile(t *testing.T) {
	t.Parallel()
	got, err := NormalizeProfile(store.Profile{
		Name:        "  Ada Lovelace ",
		GivenName:   "Ada",
		Website:     "https://ada.example.com/",
		Birthdate:   "0000-12-10",
		Zoneinfo:    "Europe/London",
		Locale:      "en_gb",
		PhoneNumber: "+44 (20) 7946-0958;ext=12",
		Address: store.Address{
			StreetAddress: "12 St James's Square\r\nFlat 3",
			Locality:      "London",
			Country:       "United Kingdom",
		},
		PhoneNumberVerified: true,
	})
	want := store.Profile{
		Name:        "Ada Lovelace",
		GivenName:   "Ada",
		Website:     "https://ada.example.com/",
		Birthdate:   "0000-12-10",
		Zoneinfo:    "Europe/London",
		Locale:      "en-GB",
		PhoneNumber: "+442079460958;ext=12",
		Address: store.Address{
			StreetAddress: "12 St James's Square\nFlat 3",
			Locality:      "London",
			Country:       "United Kingdom",
		},
		PhoneNumberVerified: true,
	}
	if err != nil {
		t.Fatalf("NormalizeProfile() unexpected error: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("NormalizeProfile() mismatch (-want +got):\n%s", diff)
	}
	if again, err := NormalizeProfile(got); err != nil || !cmp.Equal(again, got) {
		t.Errorf("NormalizeProfile() of a normalized profile = %+v, %v; want it unchanged", again, err)
	}
	for _, year := range []string{"1815", "1815-12-10"} {
		if _, err := NormalizeProfile(store.Profile{Birthdate: year}); err != nil {
			t.Errorf("NormalizeProfile() with the birthdate %q = %v, want nil", year, err)
		}
	}
}

func TestNormalizeProfileRefuses(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", MaxNameLength+1)
	for _, tt := range []struct {
		claim string
		kind  ProfileKind
		set   func(*store.Profile)
	}{
		{"name", ProfileText, func(p *store.Profile) { p.Name = long }},
		{"nickname", ProfileText, func(p *store.Profile) { p.Nickname = "ada\x00" }},
		{"family_name", ProfileText, func(p *store.Profile) { p.FamilyName = "Love\nlace" }},
		{"gender", ProfileText, func(p *store.Profile) { p.Gender = "\u202eelamef" }},
		{"preferred_username", ProfileText, func(p *store.Profile) { p.PreferredUsername = "ada\xff" }},
		{"profile", ProfileURL, func(p *store.Profile) { p.ProfileURL = "javascript:alert(1)" }},
		{"picture", ProfileURL, func(p *store.Profile) { p.Picture = "/ada.png" }},
		{"website", ProfileURL, func(p *store.Profile) { p.Website = "https://" + strings.Repeat("a", maxURLLength) }},
		{"birthdate", ProfileDate, func(p *store.Profile) { p.Birthdate = "1815-02-30" }},
		{"birthdate", ProfileDate, func(p *store.Profile) { p.Birthdate = "0000" }},
		{"birthdate", ProfileDate, func(p *store.Profile) { p.Birthdate = "10 December 1815" }},
		{"zoneinfo", ProfileTimeZone, func(p *store.Profile) { p.Zoneinfo = "Europe/../London" }},
		{"locale", ProfileLanguage, func(p *store.Profile) { p.Locale = "english" }},
		{"phone_number", ProfilePhone, func(p *store.Profile) { p.PhoneNumber = "020 7946 0958" }},
		{"phone_number", ProfilePhone, func(p *store.Profile) { p.PhoneNumber = "+44 20 7946 0958 x12" }},
		{"address.street_address", ProfileLines, func(p *store.Profile) {
			p.Address.StreetAddress = strings.Repeat("a", MaxProfileLinesLength+1)
		}},
		{"address.locality", ProfileText, func(p *store.Profile) { p.Address.Locality = "London\nUK" }},
		{"address.formatted", ProfileLines, func(p *store.Profile) { p.Address.Formatted = "Flat 3\tLondon" }},
	} {
		var p store.Profile
		tt.set(&p)
		_, err := NormalizeProfile(p)
		var pe *ProfileError
		if !errors.Is(err, ErrInvalidProfile) || !errors.As(err, &pe) || pe.Claim != tt.claim || pe.Kind != tt.kind {
			t.Errorf("NormalizeProfile() with an invalid %s = %v, want a %s error", tt.claim, err, tt.kind)
		}
	}

	// Every invalid claim is reported.
	_, err := NormalizeProfile(store.Profile{Name: long, Website: "ftp://ada.example.com"})
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Errorf("NormalizeProfile() with two invalid claims = %v, want both", err)
	}
}

func FuzzNormalizeProfile(f *testing.F) {
	f.Add("Ada Lovelace", "https://ada.example.com", "1815-12-10", "Europe/London", "en_GB", "+44 20 7946 0958",
		"12 St James's Square\r\nFlat 3")
	f.Add("", "javascript:x", "0000", "../etc", "zz", "123", "\x00")
	f.Fuzz(func(t *testing.T, name, website, birthdate, zoneinfo, locale, phone, street string) {
		p, err := NormalizeProfile(store.Profile{Name: name, Website: website, Birthdate: birthdate, Zoneinfo: zoneinfo,
			Locale: locale, PhoneNumber: phone, Address: store.Address{StreetAddress: street}})
		if err != nil {
			if !errors.Is(err, ErrInvalidProfile) {
				t.Errorf("NormalizeProfile() error %v does not wrap ErrInvalidProfile", err)
			}
			return
		}
		for _, v := range []string{p.Name, p.Website, p.Birthdate, p.Zoneinfo, p.Locale, p.PhoneNumber, p.Address.StreetAddress} {
			if strings.ContainsAny(v, "\x00\r\t") || strings.TrimSpace(v) != v {
				t.Errorf("NormalizeProfile() kept %q", v)
			}
		}
		if again, err := NormalizeProfile(p); err != nil || !cmp.Equal(again, p) {
			t.Errorf("NormalizeProfile(%+v) = %+v, %v; want it unchanged", p, again, err)
		}
	})
}

func TestUpdateProfile(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	u := f.user
	u.Profile = store.Profile{Name: "Ada", PhoneNumber: "+442079460958", PhoneNumberVerified: true}
	if err := f.d.Store.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Update() unexpected error: %v", err)
	}
	*f.now = f.now.Add(time.Hour)

	// The same phone number stays verified, even when users ask otherwise.
	got, err := UpdateProfile(t.Context(), f.d, u, store.Profile{Name: " Ada King ", PhoneNumber: "+44 20 7946 0958"})
	if err != nil || got.Profile.Name != "Ada King" || !got.Profile.PhoneNumberVerified || !got.UpdatedAt.Equal(*f.now) {
		t.Fatalf("UpdateProfile() = %+v, %v; want the new name with the phone number still verified", got, err)
	}
	stored, err := FindUser(t.Context(), f.d, f.tenant.ID, u.Email)
	if err != nil || !cmp.Equal(stored.Profile, got.Profile) {
		t.Errorf("stored profile = %+v, %v; want %+v", stored.Profile, err, got.Profile)
	}
	// Another number is not verified.
	got, err = UpdateProfile(t.Context(), f.d, got, store.Profile{PhoneNumber: "+56912345678", PhoneNumberVerified: true})
	if err != nil || got.Profile.PhoneNumberVerified {
		t.Errorf("UpdateProfile() with another phone number = %+v, %v; want it unverified", got.Profile, err)
	}
	if _, err := UpdateProfile(t.Context(), f.d, got, store.Profile{Website: "ftp://x"}); !errors.Is(err, ErrInvalidProfile) {
		t.Errorf("UpdateProfile() with an invalid website = %v, want ErrInvalidProfile", err)
	}
}

func TestFindAccount(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, err := FindAccount(t.Context(), f.d, f.tenant.ID, nil); !errors.Is(err, ErrNoAccountSession) {
		t.Errorf("FindAccount() without a session = %v, want ErrNoAccountSession", err)
	}
	login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "Ada@Example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	hash := oauth.HashToken(login.SessionToken)
	*f.now = f.now.Add(time.Hour)
	a, err := FindAccount(t.Context(), f.d, f.tenant.ID, hash)
	if err != nil || a.User.ID != f.user.ID || !a.Session.LastSeenAt.Equal(*f.now) ||
		!a.Session.IdleExpiresAt.Equal(f.now.Add(SessionIdleTimeout)) {
		t.Fatalf("FindAccount() = %+v, %v; want ada's session, just used", a, err)
	}
	if _, err := FindAccount(t.Context(), f.d, uuid.NewV7(), hash); !errors.Is(err, ErrNoAccountSession) {
		t.Errorf("FindAccount() in another tenant = %v, want ErrNoAccountSession", err)
	}
	disabled := f.user
	disabled.Status = store.UserDisabled
	if err := f.d.Store.Users().Update(t.Context(), disabled); err != nil {
		t.Fatalf("disabling the user: %v", err)
	}
	if _, err := FindAccount(t.Context(), f.d, f.tenant.ID, hash); !errors.Is(err, ErrNoAccountSession) {
		t.Errorf("FindAccount() of a disabled user = %v, want ErrNoAccountSession", err)
	}
	disabled.Status = store.UserActive
	if err := f.d.Store.Users().Update(t.Context(), disabled); err != nil {
		t.Fatalf("enabling the user: %v", err)
	}
	*f.now = f.now.Add(SessionIdleTimeout)
	if _, err := FindAccount(t.Context(), f.d, f.tenant.ID, hash); !errors.Is(err, ErrNoAccountSession) {
		t.Errorf("FindAccount() of an idle session = %v, want ErrNoAccountSession", err)
	}
}

func TestSignInToAccount(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	if _, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "wrong horse",
		nil); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("SignInToAccount() with a wrong password = %v, want ErrInvalidCredentials", err)
	}
	previous, _ := f.signIn(t, webRequest())
	login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", previous)
	if err != nil || login.SessionToken == "" || login.Response.RedirectURI != "" {
		t.Fatalf("SignInToAccount() = %+v, %v; want only a session", login, err)
	}
	// The new session replaces the browser's previous one.
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, previous); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the previous session = %v, want ErrNotFound", err)
	}
	a, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken))
	if err != nil {
		t.Fatalf("FindAccount() unexpected error: %v", err)
	}
	if err := SignOutOfAccount(t.Context(), f.d, a); err != nil {
		t.Fatalf("SignOutOfAccount() unexpected error: %v", err)
	}
	if _, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken)); !errors.Is(err, ErrNoAccountSession) {
		t.Errorf("FindAccount() after signing out = %v, want ErrNoAccountSession", err)
	}
}

func TestChangePassword(t *testing.T) {
	t.Parallel()
	f := newAuthzFixture(t)
	f.h.minimumChars = 8
	other, _ := f.signIn(t, webRequest())
	resp, client := f.refreshTokenFor(t, with(webRequest(), "scope", "openid offline_access"))
	login, err := SignInToAccount(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "correct horse", nil)
	if err != nil {
		t.Fatalf("SignInToAccount() unexpected error: %v", err)
	}
	a, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken))
	if err != nil {
		t.Fatalf("FindAccount() unexpected error: %v", err)
	}

	if err := ChangePassword(t.Context(), f.d, f.h, a, "wrong horse", "new horse battery"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("ChangePassword() with a wrong current password = %v, want ErrInvalidCredentials", err)
	}
	if err := ChangePassword(t.Context(), f.d, f.h, a, "correct horse", "short"); !errors.Is(err, password.ErrPolicy) {
		t.Errorf("ChangePassword() with a short password = %v, want ErrPolicy", err)
	}
	*f.now = f.now.Add(time.Minute)
	if err := ChangePassword(t.Context(), f.d, f.h, a, "correct horse", "new horse battery"); err != nil {
		t.Fatalf("ChangePassword() unexpected error: %v", err)
	}
	if _, err := AuthenticatePassword(t.Context(), f.d, f.h, f.tenant.ID, "ada@example.com", "new horse battery"); err != nil {
		t.Errorf("the new password = %v, want nil", err)
	}
	// The session of the account pages stays; every other one ends, and the
	// user's tokens are revoked.
	if _, err := FindAccount(t.Context(), f.d, f.tenant.ID, oauth.HashToken(login.SessionToken)); err != nil {
		t.Errorf("the session that changed the password = %v, want it kept", err)
	}
	if _, err := f.d.Store.Sessions().GetByTokenHash(t.Context(), f.tenant.ID, other); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another session = %v, want ErrNotFound", err)
	}
	if _, err := f.refresh(t, client, resp.RefreshToken); err == nil {
		t.Error("the refresh token still works")
	}
	f.wantRevoked(t, "after the password change", resp.AccessToken)
}

// The account pages reset a password without an authorization request; the
// message then names no application.
func TestStartPasswordResetForTheAccountPages(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	id, err := StartPasswordReset(t.Context(), f.d, f.tenant, nil, "ada@example.com", testBinding, f.text, testVerifyURL)
	if err != nil {
		t.Fatalf("StartPasswordReset() unexpected error: %v", err)
	}
	v, err := FindEmailVerification(t.Context(), f.d, f.tenant.ID, id, testBinding, store.VerifyPasswordReset)
	if err != nil || v.AuthorizationRequestID != "" {
		t.Fatalf("verification = %+v, %v; want one without an authorization request", v, err)
	}
	if msg := f.mail.last(t); !strings.Contains(msg.Text, "the password of your account.") ||
		strings.Contains(msg.Text, "Web app") {
		t.Errorf("message = %+v; want one that names no application", msg)
	}
}
