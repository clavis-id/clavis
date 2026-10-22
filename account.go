package clavis

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ui"
	"clavisid.org/clavis/store"
)

// Paths of the account pages, relative to a tenant's issuer (ADR 0028).
const (
	accountPath             = "/account"
	accountLoginPath        = "/account/login"
	accountLogoutPath       = "/account/logout"
	accountPasswordPath     = "/account/password"
	accountApplicationsPath = "/account/applications"
)

// handleRoot sends a browser at the root of an issuer to the account pages,
// which sign the user in first when there is no session.
func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request, t tenant) {
	seeOther(w, t.issuer+accountPath)
}

// handleAccountLoginPage asks for the credentials of the account pages, or
// sends a browser that has a session on to them.
func (s *Server) handleAccountLoginPage(w http.ResponseWriter, r *http.Request, t tenant) {
	switch _, err := app.FindAccount(r.Context(), s.deps, t.ID, sessionHash(r, t.ID)); {
	case err == nil:
		seeOther(w, t.issuer+accountPath)
	case errors.Is(err, app.ErrNoAccountSession):
		s.accountLoginPage(w, r, t, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), ""), "", "", "")
	default:
		s.internalError(w, r, "finding the account", err)
	}
}

// handleAccountLogin signs the user in to the account pages with the posted
// credentials.
func (s *Server) handleAccountLogin(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.accountForm(w, r, t)
	if !ok {
		return
	}
	email := form.Get("email")
	login, err := app.SignInToAccount(r.Context(), s.deps, s.passwords, t.ID, email, form.Get("password"),
		sessionHash(r, t.ID))
	switch {
	case errors.Is(err, app.ErrInvalidCredentials):
		s.accountLoginPage(w, r, t, s.locale(w, r, "", ""), email, i18n.LoginInvalidCredentials, "")
		return
	case errors.Is(err, app.ErrUserDisabled):
		s.accountLoginPage(w, r, t, s.locale(w, r, "", ""), email, i18n.LoginDisabled, "")
		return
	case err != nil:
		s.internalError(w, r, "signing in to the account", err)
		return
	}
	s.setSessionCookie(w, t, login)
	seeOther(w, t.issuer+accountPath)
}

// handleAccountLogout ends the session of the account pages.
func (s *Server) handleAccountLogout(w http.ResponseWriter, r *http.Request, t tenant) {
	if _, ok := s.accountForm(w, r, t); !ok {
		return
	}
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	if err := app.SignOutOfAccount(r.Context(), s.deps, a); err != nil {
		s.internalError(w, r, "signing out of the account", err)
		return
	}
	s.clearSessionCookie(w, r, t)
	s.accountLoginPage(w, r, t, s.locale(w, r, "", ""), a.User.Email, "", i18n.AccountSignedOut)
}

// handleAccountPage shows the profile of the signed-in user.
func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request, t tenant) {
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	s.accountPage(w, r, t, a, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), ""), a.User.Profile, nil, "")
}

// handleAccount saves the posted profile.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.accountForm(w, r, t)
	if !ok {
		return
	}
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	l := s.locale(w, r, "", "")
	profile := profileFromForm(form, a.User.Profile)
	u, err := app.UpdateProfile(r.Context(), s.deps, a.User, profile)
	switch {
	case errors.Is(err, app.ErrInvalidProfile):
		s.accountPage(w, r, t, a, l, profile, profileErrors(s.catalogs.Printer(l), err), "")
		return
	case err != nil:
		s.internalError(w, r, "updating the profile", err)
		return
	}
	a.User = u
	s.accountPage(w, r, t, a, l, u.Profile, nil, i18n.AccountProfileSaved)
}

// handleAccountPasswordPage asks for the current and the new password.
func (s *Server) handleAccountPasswordPage(w http.ResponseWriter, r *http.Request, t tenant) {
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	s.accountPasswordPage(w, r, t, a, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), ""), "", "")
}

// handleAccountPassword changes the password of the signed-in user, which
// ends every other session of the user.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.accountForm(w, r, t)
	if !ok {
		return
	}
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	l := s.locale(w, r, "", "")
	err := app.ChangePassword(r.Context(), s.deps, s.passwords, a, form.Get("current_password"), form.Get("new_password"))
	switch {
	case errors.Is(err, app.ErrInvalidCredentials):
		s.accountPasswordPage(w, r, t, a, l, i18n.AccountWrongPassword, "")
	case errors.Is(err, password.ErrPolicy):
		s.accountPasswordPage(w, r, t, a, l, i18n.PasswordPolicy, "")
	case err != nil:
		s.internalError(w, r, "changing the password", err)
	default:
		s.accountPasswordPage(w, r, t, a, l, "", i18n.AccountPasswordChanged)
	}
}

// handleAccountApplicationsPage lists the applications that the signed-in
// user allowed.
func (s *Server) handleAccountApplicationsPage(w http.ResponseWriter, r *http.Request, t tenant) {
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	s.accountApplicationsPage(w, r, t, a, s.locale(w, r, r.URL.Query().Get(ui.LocaleParam), ""), "")
}

// handleAccountApplications removes the access of the posted application
// (ADR 0020).
func (s *Server) handleAccountApplications(w http.ResponseWriter, r *http.Request, t tenant) {
	form, ok := s.accountForm(w, r, t)
	if !ok {
		return
	}
	a, ok := s.account(w, r, t)
	if !ok {
		return
	}
	grants, err := app.ListGrants(r.Context(), s.deps, t.ID, a.User.Email)
	if err != nil {
		s.internalError(w, r, "listing the grants", err)
		return
	}
	var removed string
	for _, g := range grants {
		if g.Client.ClientID != form.Get("client_id") {
			continue
		}
		switch err := app.RevokeGrant(r.Context(), s.deps, t.ID, a.User.Email, g.Client.ClientID); {
		case errors.Is(err, app.ErrGrantNotFound):
			// Removed in the meantime.
		case err != nil:
			s.internalError(w, r, "revoking a grant", err)
			return
		default:
			removed = g.Client.Name
		}
	}
	l := s.locale(w, r, "", "")
	var notice string
	if removed != "" {
		notice = s.catalogs.Printer(l).T(i18n.AccountApplicationRemoved, "client", removed)
	}
	s.accountApplicationsPage(w, r, t, a, l, notice)
}

// accountForm checks that a form of the account pages comes from Clavis's
// own pages, and parses it. On failure it answers the request and returns
// false.
func (s *Server) accountForm(w http.ResponseWriter, r *http.Request, t tenant) (url.Values, bool) {
	if err := s.crossOrigin.Check(r); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusForbidden, i18n.ErrorBlockedTitle,
			i18n.ErrorCrossSiteAccountForm)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusBadRequest, i18n.ErrorInvalidAccountTitle,
			i18n.ErrorMalformedAccountForm)
		return nil, false
	}
	return r.PostForm, true
}

// account returns the signed-in user of the account pages, or sends the
// browser to their sign-in page and returns false.
func (s *Server) account(w http.ResponseWriter, r *http.Request, t tenant) (app.Account, bool) {
	a, err := app.FindAccount(r.Context(), s.deps, t.ID, sessionHash(r, t.ID))
	switch {
	case errors.Is(err, app.ErrNoAccountSession):
		seeOther(w, t.issuer+accountLoginPath)
		return app.Account{}, false
	case err != nil:
		s.internalError(w, r, "finding the account", err)
		return app.Account{}, false
	}
	return a, true
}

// accountNav returns the links of the account pages of tenant t, for the
// page at path.
func accountNav(t tenant, path string) ui.AccountNav {
	return ui.AccountNav{
		ProfileURL:      t.path + accountPath,
		PasswordURL:     t.path + accountPasswordPath,
		ApplicationsURL: t.path + accountApplicationsPath,
		LogoutURL:       t.path + accountLogoutPath,
		Current:         t.path + path,
	}
}

// accountLayout returns the layout of an account page at path in locale l,
// with a language selector that loads the page again.
func (s *Server) accountLayout(r *http.Request, t tenant, l i18n.Locale, path string) ui.Layout {
	layout := s.layout(r, t, l)
	layout.Languages = &ui.LanguageSelector{Method: http.MethodGet, Action: t.path + path}
	layout.Wide = true
	return layout
}

// accountLoginPage renders the sign-in form of the account pages in locale
// l, with the email address to fill in, and the message of problem and the
// message of notice unless they are empty.
func (s *Server) accountLoginPage(w http.ResponseWriter, r *http.Request, t tenant, l i18n.Locale, email string,
	problem, notice i18n.Key,
) {
	layout := s.accountLayout(r, t, l, accountLoginPath)
	layout.Wide = false
	var message, info, resetURL string
	if problem != "" {
		message = layout.T(problem)
	}
	if notice != "" {
		info = layout.T(notice)
	}
	if t.reset {
		resetURL = t.issuer + resetPath
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.Login(ui.LoginPage{
		Layout:   layout,
		Action:   t.path + accountLoginPath,
		Email:    email,
		Error:    message,
		Notice:   info,
		ResetURL: resetURL,
	}))
}

// accountPage renders the profile form of a in locale l with the values of
// profile, the errors that refused it and the message of notice, unless it
// is empty.
func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, t tenant, a app.Account, l i18n.Locale,
	profile store.Profile, problems []string, notice i18n.Key,
) {
	layout := s.accountLayout(r, t, l, accountPath)
	var info string
	if notice != "" {
		info = layout.T(notice)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.Account(ui.AccountPage{
		Layout:   layout,
		Nav:      accountNav(t, accountPath),
		Email:    a.User.Email,
		Action:   t.path + accountPath,
		Sections: profileSections(layout.Text, profile),
		Notice:   info,
		Errors:   problems,
	}))
}

// accountPasswordPage renders the password form of a in locale l, with the
// message of problem and the message of notice unless they are empty.
func (s *Server) accountPasswordPage(w http.ResponseWriter, r *http.Request, t tenant, a app.Account,
	l i18n.Locale, problem, notice i18n.Key,
) {
	layout := s.accountLayout(r, t, l, accountPasswordPath)
	minLength, maxLength := s.passwords.MinLength(), password.MaxLength
	var problems []string
	if problem != "" {
		problems = []string{layout.T(problem, "min", strconv.Itoa(minLength), "max", strconv.Itoa(maxLength))}
	}
	var info string
	if notice != "" {
		info = layout.T(notice)
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.AccountPassword(ui.AccountPasswordPage{
		Layout:    layout,
		Nav:       accountNav(t, accountPasswordPath),
		Email:     a.User.Email,
		Action:    t.path + accountPasswordPath,
		MinLength: minLength,
		MaxLength: maxLength,
		Notice:    info,
		Errors:    problems,
	}))
}

// accountApplicationsPage renders the applications that the user of a
// allowed, in locale l, with notice unless it is empty.
func (s *Server) accountApplicationsPage(w http.ResponseWriter, r *http.Request, t tenant, a app.Account,
	l i18n.Locale, notice string,
) {
	grants, err := app.ListGrants(r.Context(), s.deps, t.ID, a.User.Email)
	if err != nil {
		s.internalError(w, r, "listing the grants", err)
		return
	}
	layout := s.accountLayout(r, t, l, accountApplicationsPath)
	applications := make([]ui.AccountApplication, 0, len(grants))
	for _, g := range grants {
		scopes := make([]string, len(g.Scopes))
		for i, scope := range g.Scopes {
			scopes[i] = ui.ScopeDescription(layout.Text, scope, "")
		}
		applications = append(applications, ui.AccountApplication{Name: g.Client.Name, ClientID: g.Client.ClientID,
			Scopes: scopes})
	}
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(true))
	s.render(w, r, http.StatusOK, ui.AccountApplications(ui.AccountApplicationsPage{
		Layout:       layout,
		Nav:          accountNav(t, accountApplicationsPath),
		Action:       t.path + accountApplicationsPath,
		Applications: applications,
		Notice:       notice,
	}))
}
