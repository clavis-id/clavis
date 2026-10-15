package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/store"
)

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()
	valid := map[string]string{
		"ada@example.com":                   "ada@example.com",
		"Ada.Lovelace@Example.COM":          "ada.lovelace@example.com",
		"ada+tag@mail.example.co.uk":        "ada+tag@mail.example.co.uk",
		"o'brien@example.com":               "o'brien@example.com",
		"a@b.co":                            "a@b.co",
		"x@xn--bcher-kva.example":           "x@xn--bcher-kva.example",
		strings.Repeat("a", 64) + "@ex.com": strings.Repeat("a", 64) + "@ex.com",
	}
	for in, want := range valid {
		got, err := NormalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	invalid := []string{
		"", "ada", "ada@", "@example.com", "ada@example", "ada@@example.com", "ada@b@example.com",
		"ada @example.com", " ada@example.com", "ada@example.com\n", "Ada <ada@example.com>",
		`"ada"@example.com`, `"a@b"@example.com`, `ada\@example.com`, "ada(comment)@example.com",
		"ada@[127.0.0.1]", "ada@127.0.0.1", "ada@-example.com", "ada@example-.com", "ada@exa_mple.com",
		"ada@example..com", "ada@.example.com", ".ada@example.com", "ada.@example.com", "a..da@example.com",
		"adá@example.com", "ada@exämple.com", strings.Repeat("a", 65) + "@example.com",
		"ada@" + strings.Repeat("a", 64) + ".com", "ada@" + strings.Repeat("a.", 126) + "com",
	}
	for _, in := range invalid {
		if got, err := NormalizeEmail(in); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want ErrInvalidEmail", in, got, err)
		}
	}
}

// FuzzNormalizeEmail checks that accepted addresses are printable ASCII
// with exactly one @, lowercase, and stable under normalization.
func FuzzNormalizeEmail(f *testing.F) {
	for _, seed := range []string{"ada@example.com", "Ada.Lovelace+x@Example.COM", `"a b"@example.com`,
		"ada@[127.0.0.1]", "a(b)@example.com", "ada@example..com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, email string) {
		got, err := NormalizeEmail(email)
		if err != nil {
			return
		}
		if strings.ToLower(got) != got || !strings.EqualFold(got, email) || strings.Count(got, "@") != 1 ||
			len(got) > maxEmailLength {
			t.Errorf("NormalizeEmail(%q) = %q", email, got)
		}
		for _, c := range []byte(got) {
			if c < 0x21 || c > 0x7e {
				t.Errorf("NormalizeEmail(%q) = %q, which has byte %#x", email, got, c)
			}
		}
		if again, err := NormalizeEmail(got); err != nil || again != got {
			t.Errorf("NormalizeEmail(%q) = %q, %v; normalization is not stable", got, again, err)
		}
	})
}

func TestCreateUser(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	d := newDeps(t, st)
	tn := newTenantForClients(t, d)

	got, err := CreateUser(t.Context(), d, tn.ID, UserSpec{
		Email: "Ada@Example.com", EmailVerified: true, Name: "Ada Lovelace", GivenName: "Ada", FamilyName: "Lovelace",
	})
	if err != nil {
		t.Fatalf("CreateUser() unexpected error: %v", err)
	}
	if got.Email != "ada@example.com" || !got.EmailVerified || got.Status != store.UserActive ||
		got.Profile.Name != "Ada Lovelace" || got.Profile.GivenName != "Ada" || got.Profile.FamilyName != "Lovelace" ||
		!got.CreatedAt.Equal(d.Now()) {
		t.Errorf("CreateUser() = %+v", got)
	}
	if stored, err := st.Users().GetByEmail(t.Context(), tn.ID, "ada@example.com"); err != nil || stored.ID != got.ID {
		t.Errorf("stored user = %v, %v; want %v", stored.ID, err, got.ID)
	}

	tests := []struct {
		name string
		spec UserSpec
		want error
	}{
		{"same email in another case", UserSpec{Email: "ADA@example.com"}, ErrUserExists},
		{"invalid email", UserSpec{Email: "ada"}, ErrInvalidEmail},
		{"control character in name", UserSpec{Email: "grace@example.com", Name: "Grace\nHopper"}, ErrInvalidUser},
		{"long given name", UserSpec{Email: "grace@example.com", GivenName: strings.Repeat("g", MaxNameLength+1)}, ErrInvalidUser},
		{"bidirectional override in family name", UserSpec{Email: "grace@example.com", FamilyName: "Hop\u202Eper"}, ErrInvalidUser},
	}
	for _, tt := range tests {
		if _, err := CreateUser(t.Context(), d, tn.ID, tt.spec); !errors.Is(err, tt.want) {
			t.Errorf("%s: CreateUser() = %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, err := CreateUser(t.Context(), d, uuid.NewV7(), UserSpec{Email: "grace@example.com"}); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("CreateUser() in an unknown tenant = %v, want ErrTenantNotFound", err)
	}
}

func TestFindListAndDeleteUsers(t *testing.T) {
	t.Parallel()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)
	for _, email := range []string{"one@example.com", "two@example.com", "three@example.com"} {
		if _, err := CreateUser(t.Context(), d, tn.ID, UserSpec{Email: email}); err != nil {
			t.Fatalf("CreateUser(%q) unexpected error: %v", email, err)
		}
	}
	if u, err := FindUser(t.Context(), d, tn.ID, "TWO@example.com"); err != nil || u.Email != "two@example.com" {
		t.Errorf("FindUser(TWO@example.com) = %v, %v", u.Email, err)
	}
	for _, email := range []string{"missing@example.com", "not an email"} {
		if _, err := FindUser(t.Context(), d, tn.ID, email); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("FindUser(%q) = %v, want ErrUserNotFound", email, err)
		}
	}
	users, err := ListUsers(t.Context(), d, tn.ID)
	if err != nil {
		t.Fatalf("ListUsers() unexpected error: %v", err)
	}
	var emails []string
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	if strings.Join(emails, ",") != "one@example.com,two@example.com,three@example.com" {
		t.Errorf("ListUsers() = %v, want creation order", emails)
	}
	if err := DeleteUser(t.Context(), d, tn.ID, "two@example.com"); err != nil {
		t.Fatalf("DeleteUser() unexpected error: %v", err)
	}
	if err := DeleteUser(t.Context(), d, tn.ID, "two@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("second DeleteUser() = %v, want ErrUserNotFound", err)
	}
}

// fakeHasher "hashes" a password by prefixing it and records its calls.
type fakeHasher struct {
	mu           sync.Mutex
	verifies     int
	dummies      int
	rehash       bool
	verifyErr    error
	fips         bool
	minimumChars int
}

func (f *fakeHasher) CheckNew(pw string) error {
	if len(pw) < f.minimumChars {
		return password.ErrPolicy
	}
	return nil
}

func (f *fakeHasher) Hash(_ context.Context, pw string) (string, error) { return "fake$" + pw, nil }

func (f *fakeHasher) Verify(_ context.Context, encoded, pw string) (password.Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies++
	if f.verifyErr != nil {
		return password.Verification{}, f.verifyErr
	}
	match := encoded == "fake$"+pw
	return password.Verification{Match: match, Rehash: match && f.rehash, Algorithm: password.Argon2id}, nil
}

func (f *fakeHasher) VerifyDummy(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dummies++
	return nil
}

func (f *fakeHasher) FIPS() bool { return f.fips }

func (f *fakeHasher) calls() (verifies, dummies int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifies, f.dummies
}

// newLoginFixture returns a tenant with ada@example.com, whose password is
// "correct horse", and grace@example.com, who has no password.
func newLoginFixture(t *testing.T, h PasswordHasher) (Deps, store.Tenant, store.User) {
	t.Helper()
	d := newDeps(t, openStore(t))
	tn := newTenantForClients(t, d)
	ada, err := CreateUser(t.Context(), d, tn.ID, UserSpec{Email: "ada@example.com"})
	if err != nil {
		t.Fatalf("CreateUser(ada) unexpected error: %v", err)
	}
	if err := SetPassword(t.Context(), d, h, ada, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	if _, err := CreateUser(t.Context(), d, tn.ID, UserSpec{Email: "grace@example.com"}); err != nil {
		t.Fatalf("CreateUser(grace) unexpected error: %v", err)
	}
	return d, tn, ada
}

func TestAuthenticatePassword(t *testing.T) {
	t.Parallel()
	h := &fakeHasher{}
	d, tn, ada := newLoginFixture(t, h)

	got, err := AuthenticatePassword(t.Context(), d, h, tn.ID, "Ada@Example.com", "correct horse")
	if err != nil || got.ID != ada.ID {
		t.Fatalf("AuthenticatePassword() = %v, %v; want %v", got.ID, err, ada.ID)
	}
	if v, dummies := h.calls(); v != 1 || dummies != 0 {
		t.Errorf("a successful login made %d verifications and %d dummy ones, want 1 and 0", v, dummies)
	}
}

// TestAuthenticatePasswordEqualizesFailures checks that every failure that
// could reveal whether an account exists costs exactly one verification,
// real or dummy, and returns the same error.
func TestAuthenticatePasswordEqualizesFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, email         string
		wantReal, wantDummy int
	}{
		{"wrong password", "ada@example.com", 1, 0},
		{"unknown email", "nobody@example.com", 0, 1},
		{"user without a password", "grace@example.com", 0, 1},
		{"invalid email", "not an email", 0, 1},
	}
	for _, tt := range tests {
		h := &fakeHasher{}
		d, tn, _ := newLoginFixture(t, h)
		if _, err := AuthenticatePassword(t.Context(), d, h, tn.ID, tt.email, "wrong horse"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: AuthenticatePassword() = %v, want ErrInvalidCredentials", tt.name, err)
		}
		if v, dummies := h.calls(); v != tt.wantReal || dummies != tt.wantDummy {
			t.Errorf("%s: %d verifications and %d dummy ones, want %d and %d", tt.name, v, dummies, tt.wantReal, tt.wantDummy)
		}
	}
}

func TestAuthenticatePasswordRefusesDisabledUsers(t *testing.T) {
	t.Parallel()
	h := &fakeHasher{}
	d, tn, _ := newLoginFixture(t, h)
	off := store.User{ID: uuid.NewV7(), TenantID: tn.ID, Email: "off@example.com", Status: store.UserDisabled,
		CreatedAt: d.Now(), UpdatedAt: d.Now()}
	if err := d.Store.Users().Create(t.Context(), off); err != nil {
		t.Fatalf("creating a disabled user: %v", err)
	}
	if err := SetPassword(t.Context(), d, h, off, "correct horse"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	if _, err := AuthenticatePassword(t.Context(), d, h, tn.ID, "off@example.com", "correct horse"); !errors.Is(err, ErrUserDisabled) {
		t.Errorf("right password = %v, want ErrUserDisabled", err)
	}
	// A wrong password does not reveal that the user is disabled.
	if _, err := AuthenticatePassword(t.Context(), d, h, tn.ID, "off@example.com", "wrong horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthenticatePasswordWithUnusableHash(t *testing.T) {
	t.Parallel()
	for _, hashErr := range []error{password.ErrMalformedHash, password.ErrUnsupportedHash} {
		h := &fakeHasher{}
		d, tn, _ := newLoginFixture(t, h)
		var logs bytes.Buffer
		d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		h.verifyErr = hashErr
		if _, err := AuthenticatePassword(t.Context(), d, h, tn.ID, "ada@example.com", "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%v: AuthenticatePassword() = %v, want ErrInvalidCredentials", hashErr, err)
		}
		if !strings.Contains(logs.String(), "cannot verify the password hash") || strings.Contains(logs.String(), "correct horse") {
			t.Errorf("%v: logs do not report the unusable hash, or leak the password:\n%s", hashErr, logs.String())
		}
	}
}

func TestSetPassword(t *testing.T) {
	t.Parallel()
	h := &fakeHasher{minimumChars: 8}
	d, tn, ada := newLoginFixture(t, h)

	later := d.Now().Add(time.Hour)
	d.Now = func() time.Time { return later }
	if err := SetPassword(t.Context(), d, h, ada, "battery staple"); err != nil {
		t.Fatalf("SetPassword() unexpected error: %v", err)
	}
	stored, err := d.Store.Passwords().Get(t.Context(), tn.ID, ada.ID)
	if err != nil || stored.Hash != "fake$battery staple" || !stored.SetAt.Equal(later) {
		t.Errorf("stored password = %+v, %v", stored, err)
	}
	if err := SetPassword(t.Context(), d, h, ada, "short"); !errors.Is(err, password.ErrPolicy) {
		t.Errorf("SetPassword(short) = %v, want ErrPolicy", err)
	}
	ghost := ada
	ghost.ID = uuid.NewV7()
	if err := SetPassword(t.Context(), d, h, ghost, "battery staple"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("SetPassword() for a deleted user = %v, want ErrUserNotFound", err)
	}
}

// TestAuthenticatePasswordRehashes uses the real hasher: a hash made under a
// weaker policy is replaced after a successful login.
func TestAuthenticatePasswordRehashes(t *testing.T) {
	t.Parallel()
	weak, err := password.New(password.DefaultConfig())
	if err != nil {
		t.Fatalf("password.New() unexpected error: %v", err)
	}
	strongCfg := password.DefaultConfig()
	strongCfg.Argon2id.Iterations = 3
	strongCfg.PBKDF2Iterations = 700_000
	strong, err := password.New(strongCfg)
	if err != nil {
		t.Fatalf("password.New() unexpected error: %v", err)
	}

	d, tn, ada := newLoginFixture(t, weak)
	var logs bytes.Buffer
	d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	before, err := d.Store.Passwords().Get(t.Context(), tn.ID, ada.ID)
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}

	if _, err := AuthenticatePassword(t.Context(), d, strong, tn.ID, "ada@example.com", "correct horse"); err != nil {
		t.Fatalf("AuthenticatePassword() unexpected error: %v", err)
	}
	after, err := d.Store.Passwords().Get(t.Context(), tn.ID, ada.ID)
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if after.Hash == before.Hash || !after.SetAt.Equal(before.SetAt) {
		t.Errorf("after the login the hash is %q (before %q) and SetAt %v (before %v); want a new hash and the same SetAt",
			after.Hash, before.Hash, after.SetAt, before.SetAt)
	}
	if !strings.Contains(after.Hash, "t=3") && !strings.Contains(after.Hash, "i=700000") {
		t.Errorf("new hash %q does not use the current policy", after.Hash)
	}
	if !strings.Contains(logs.String(), "rehashed password") {
		t.Errorf("logs do not report the rehash:\n%s", logs.String())
	}
	if _, err := AuthenticatePassword(t.Context(), d, strong, tn.ID, "ada@example.com", "correct horse"); err != nil {
		t.Errorf("login with the rehashed password = %v", err)
	}
}

// conflictingPasswords makes every rehash lose a race with a password change.
type conflictingPasswords struct{ store.Passwords }

func (conflictingPasswords) Rehash(context.Context, uuid.UUID, uuid.UUID, string, string) error {
	return store.ErrConflict
}

type conflictingStore struct{ store.Store }

func (c conflictingStore) Passwords() store.Passwords {
	return conflictingPasswords{c.Store.Passwords()}
}

func TestAuthenticatePasswordToleratesConcurrentPasswordChanges(t *testing.T) {
	t.Parallel()
	h := &fakeHasher{rehash: true, fips: true}
	d, tn, ada := newLoginFixture(t, h)
	var logs bytes.Buffer
	d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	d.Store = conflictingStore{d.Store}
	if u, err := AuthenticatePassword(t.Context(), d, h, tn.ID, "ada@example.com", "correct horse"); err != nil || u.ID != ada.ID {
		t.Errorf("AuthenticatePassword() = %v, %v; want the user despite the lost rehash", u.ID, err)
	}
	if strings.Contains(logs.String(), "level=ERROR") || strings.Contains(logs.String(), "replaced") {
		t.Errorf("a lost rehash race was logged:\n%s", logs.String())
	}
}

func TestAuthenticatePasswordLogsTheFIPSMigration(t *testing.T) {
	t.Parallel()
	h := &fakeHasher{rehash: true, fips: true}
	d, tn, _ := newLoginFixture(t, h)
	var logs bytes.Buffer
	d.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := AuthenticatePassword(t.Context(), d, h, tn.ID, "ada@example.com", "correct horse"); err != nil {
		t.Fatalf("AuthenticatePassword() unexpected error: %v", err)
	}
	if !strings.Contains(logs.String(), `level=WARN msg="replaced an argon2id password hash in FIPS mode"`) {
		t.Errorf("logs do not report the FIPS migration:\n%s", logs.String())
	}
}
