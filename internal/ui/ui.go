// Package ui renders the hosted pages of Clavis: HTML generated on the
// server with templ, styled by embedded assets (ADR 0007). Run make generate
// after editing a .templ file.
package ui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/store"
)

//go:embed assets
var assetFiles embed.FS

// Assets serves the embedded static files. Each file is published under a
// name that includes a hash of its content, so browsers can cache it
// forever and a new release changes the name.
type Assets struct {
	files      map[string]asset
	stylesheet string
}

type asset struct {
	content     []byte
	contentType string
}

// assetTypes maps the extensions of embedded files to their media types.
var assetTypes = map[string]string{
	".css": "text/css; charset=utf-8",
}

// NewAssets indexes the embedded assets.
func NewAssets() (*Assets, error) {
	a := &Assets{files: make(map[string]asset)}
	err := fs.WalkDir(assetFiles, "assets", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := assetFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("reading %s: %w", name, err)
		}
		ext := path.Ext(name)
		contentType, ok := assetTypes[ext]
		if !ok {
			return fmt.Errorf("asset %s has no known media type", name)
		}
		sum := sha256.Sum256(content)
		published := strings.TrimSuffix(path.Base(name), ext) + "-" + hex.EncodeToString(sum[:6]) + ext
		a.files[published] = asset{content: content, contentType: contentType}
		if path.Base(name) == "clavis.css" {
			a.stylesheet = published
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ui: indexing assets: %w", err)
	}
	if a.stylesheet == "" {
		return nil, errors.New("ui: the stylesheet is missing from the embedded assets")
	}
	return a, nil
}

// Stylesheet returns the published name of the main stylesheet.
func (a *Assets) Stylesheet() string { return a.stylesheet }

// ServeAsset writes the asset with the given published name, or a 404
// response.
func (a *Assets) ServeAsset(w http.ResponseWriter, r *http.Request, name string) {
	f, ok := a.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.contentType)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(f.content))
}

// SetPageHeaders sets the headers of a hosted page: no caching, no framing,
// no referrer, and the Content Security Policy csp, built with
// Layout.ContentSecurityPolicy.
func SetPageHeaders(h http.Header, csp string) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// LocaleParam is the parameter with which the language selector sends the
// chosen locale.
const LocaleParam = "clavis_locale"

// Layout holds what every page needs.
type Layout struct {
	// Stylesheet is the URL of the main stylesheet.
	Stylesheet string
	// Text writes the page's text in its locale.
	Text i18n.Printer
	// theme is the tenant's style sheet, which SetTheme sets, and
	// themeSource its hash as a Content Security Policy source.
	theme       string
	themeSource string
	// LogoURL is the URL of the tenant's logo, or empty, and TenantName
	// is its text alternative.
	LogoURL    string
	TenantName string
	// Languages sets up the language selector, or is nil for a page
	// without one.
	Languages *LanguageSelector
}

// T returns the message of key in the page's locale; see i18n.Printer.T.
func (l Layout) T(key i18n.Key, args ...string) string { return l.Text.T(key, args...) }

// LanguageSelector sends the request of the page again, with the chosen
// locale in LocaleParam: a form with Method and Action that carries Fields.
type LanguageSelector struct {
	Method string
	Action string
	Fields []Field
}

// ContentSecurityPolicy returns the policy of a page with layout l. Pages
// load only stylesheets and images from their own origin, plus the
// tenant's theme element by its hash, run no scripts, cannot be framed, and
// submit forms only to their own origin and to formTargets. Browsers also
// apply form-action to the redirects that follow a form submission, so a
// login page must allow the redirect URI it sends the user to; FormTarget
// converts one. Without any form target and without allowSelf, the page
// cannot submit forms at all.
func (l Layout) ContentSecurityPolicy(allowSelf bool, formTargets ...string) string {
	return contentSecurityPolicy("", l.styleSources(), allowSelf, formTargets)
}

// FormPostContentSecurityPolicy returns the policy of the page that FormPost
// renders with layout l: the policy of ContentSecurityPolicy for a form
// that submits only to formTarget, which FormTarget returns for the
// redirect URI, plus the one script that submits the form, allowed by its
// hash.
func (l Layout) FormPostContentSecurityPolicy(formTarget string) string {
	var targets []string
	if formTarget != "" {
		targets = append(targets, formTarget)
	}
	return contentSecurityPolicy("script-src '"+formPostScriptHash+"'; ", l.styleSources(), false, targets)
}

// SetTheme makes css, which ThemeStyle returns, the tenant's style sheet of
// the page, and records its hash for the page's Content Security Policy.
func (l *Layout) SetTheme(css string) {
	l.theme, l.themeSource = css, ""
	if css != "" {
		sum := sha256.Sum256([]byte(css))
		l.themeSource = "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
}

// Theme returns the tenant's style sheet of the page, or empty.
func (l Layout) Theme() string { return l.theme }

// styleSources returns the style-src sources of a page: its own origin, and
// the hash of the theme element when there is one.
func (l Layout) styleSources() string {
	if l.themeSource == "" {
		return "'self'"
	}
	return "'self' " + l.themeSource
}

func contentSecurityPolicy(scripts, styles string, allowSelf bool, formTargets []string) string {
	var sources []string
	if allowSelf {
		sources = append(sources, "'self'")
	}
	sources = append(sources, formTargets...)
	if len(sources) == 0 {
		sources = []string{"'none'"}
	}
	return "default-src 'none'; " + scripts + "style-src " + styles + "; img-src 'self'; form-action " +
		strings.Join(sources, " ") + "; frame-ancestors 'none'; base-uri 'none'"
}

// formPostScript submits the form of the FormPost page as soon as the page
// loads, and formPostScriptHash is its hash as a Content Security Policy
// hash source.
const formPostScript = `document.getElementById("response").submit();`

var formPostScriptHash = func() string {
	sum := sha256.Sum256([]byte(formPostScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}()

// FormTarget returns the Content Security Policy source expression that
// allows a form submission to redirect to redirectURI: its origin for an
// http or https URI with a host name, otherwise its scheme. The result never
// contains characters that could end the source list, whatever the URI
// holds.
func FormTarget(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || !isSchemeName(u.Scheme) {
		return ""
	}
	if (u.Scheme == "https" || u.Scheme == "http") && isPlainHost(u.Host) {
		return u.Scheme + "://" + u.Host
	}
	// CSP host sources cannot express IP version 6 literals, and private-use
	// schemes have no origin.
	return u.Scheme + ":"
}

// isSchemeName reports whether s is a URI scheme (RFC 3986, section 3.1).
func isSchemeName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789+-.") == ""
}

// isPlainHost reports whether host is a lowercase host name or IPv4 address
// with an optional port, which a CSP host source can express as is.
func isPlainHost(host string) bool {
	name, port, hasPort := strings.Cut(host, ":")
	if name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		return false
	}
	return !hasPort || (port != "" && strings.Trim(port, "0123456789") == "")
}

// ThemeStyle returns the style sheet that applies a tenant's theme over the
// default one, or empty for a theme without values. Values that are not
// #rrggbb colors or a radius between 0 and 64 pixels are left out, whatever
// the store holds, so the style sheet holds nothing else. The light colors
// apply outside the dark color scheme only, so a tenant that sets only them
// keeps the default dark colors.
func ThemeStyle(theme store.Theme) string {
	var b strings.Builder
	light, dark := declarations(theme.Light), declarations(theme.Dark)
	if theme.Radius != nil && *theme.Radius >= 0 && *theme.Radius <= maxRadius {
		b.WriteString(":root{--clavis-radius:" + strconv.Itoa(*theme.Radius) + "px}")
	}
	if light != "" {
		b.WriteString("@media not all and (prefers-color-scheme: dark){:root{" + light + "}}")
	}
	if dark != "" {
		b.WriteString("@media (prefers-color-scheme: dark){:root{" + dark + "}}")
	}
	return b.String()
}

// maxRadius bounds the radius that ThemeStyle writes.
const maxRadius = 64

// declarations returns the custom property declarations of the valid colors
// in c.
func declarations(c store.ThemeColors) string {
	var b strings.Builder
	for _, color := range c.List() {
		if len(color.Value) == 7 && color.Value[0] == '#' &&
			strings.Trim(color.Value[1:], "0123456789abcdefABCDEF") == "" {
			b.WriteString("--clavis-" + strings.ReplaceAll(color.Name, "_", "-") + ":" + color.Value + ";")
		}
	}
	return b.String()
}

// LoginPage is the password sign-in form.
type LoginPage struct {
	Layout
	// ClientName names the application the user signs in to.
	ClientName string
	// Action is the URL the form posts to.
	Action string
	// RequestID identifies the stored authorization request.
	RequestID string
	// Email fills the email field: with the login hint of the request, or
	// again after a failed attempt.
	Email string
	// Error explains why the previous attempt failed.
	Error string
	// Notice is news for the user, such as a password that has just
	// changed, or empty.
	Notice string
	// SignupURL is the URL of the signup page, or empty when the tenant
	// offers none.
	SignupURL string
	// ResetURL is the URL of the password reset page, or empty when the
	// server cannot reset passwords.
	ResetURL string
}

// SignupPage asks for the email address of a new account (ADR 0026).
type SignupPage struct {
	Layout
	// ClientName names the application the user signs up for.
	ClientName string
	// Action is the URL the form posts to.
	Action string
	// RequestID identifies the stored authorization request.
	RequestID string
	// Email fills the email field again after a malformed address.
	Email string
	// Error explains why the previous attempt failed.
	Error string
	// LoginURL is the URL of the sign-in page.
	LoginURL string
}

// VerifyPage asks for the code sent to Email or, when Token is set,
// confirms the link that the user followed. Reset tells a password reset
// from a signup.
type VerifyPage struct {
	Layout
	Reset bool
	// Email is the address the message went to.
	Email string
	// Action is the URL the form posts to.
	Action string
	// VerificationID identifies the stored email verification.
	VerificationID string
	// Token is the token of the link, or empty for the code form.
	Token string
	// Error explains why the previous code failed.
	Error string
	// RestartURL is the URL of the signup page, to start again.
	RestartURL string
}

// PasswordPage asks for the password of a new account or, when Reset is
// set, for the new password of an account.
type PasswordPage struct {
	Layout
	Reset bool
	// Email is the address of the new account.
	Email string
	// Action is the URL the form posts to.
	Action string
	// VerificationID identifies the stored email verification.
	VerificationID string
	// MinLength and MaxLength bound the length of the password, in
	// characters.
	MinLength int
	MaxLength int
	// Error explains why the previous password was refused.
	Error string
}

// SignedUpPage says that the new account is ready.
type SignedUpPage struct {
	Layout
}

// ResetPage asks for the email address of the account whose password the
// user resets (ADR 0027).
type ResetPage struct {
	Layout
	// Action is the URL the form posts to.
	Action string
	// RequestID identifies the stored authorization request.
	RequestID string
	// Email fills the email field: with the login hint of the request, or
	// again after a malformed address.
	Email string
	// Error explains why the previous attempt failed.
	Error string
	// LoginURL is the URL of the sign-in page.
	LoginURL string
}

// AccountNav holds the URLs of the account pages, and the URL of the page
// that shows it in Current.
type AccountNav struct {
	ProfileURL      string
	PasswordURL     string
	ApplicationsURL string
	LogoutURL       string
	Current         string
}

// ProfileField is an input of the profile form.
type ProfileField struct {
	// Name is the name of the form field and the ID of the input.
	Name  string
	Label string
	Value string
	// Type is the type of the input, such as text or url, unless Lines is
	// set, which asks for a text area.
	Type  string
	Lines bool
	// Autocomplete is the autofill token of the input (HTML, section
	// 4.10.18.7).
	Autocomplete string
	// Hint explains the format, or is empty.
	Hint string
}

// ProfileSection is a group of profile fields.
type ProfileSection struct {
	Title  string
	Fields []ProfileField
}

// AccountPage shows the profile of the signed-in user (ADR 0028).
type AccountPage struct {
	Layout
	Nav AccountNav
	// Email is the address of the account, which the profile cannot
	// change.
	Email    string
	Action   string
	Sections []ProfileSection
	// Notice says what the last change did, or is empty, and Errors
	// explain why it was refused.
	Notice string
	Errors []string
}

// AccountPasswordPage changes the password of the signed-in user.
type AccountPasswordPage struct {
	Layout
	Nav AccountNav
	// Email is the address of the account, for password managers.
	Email     string
	Action    string
	MinLength int
	MaxLength int
	Notice    string
	Errors    []string
}

// AccountApplication is an application that the user allowed.
type AccountApplication struct {
	Name     string
	ClientID string
	// Scopes describes what the application may do, one line each.
	Scopes []string
}

// AccountApplicationsPage lists the applications that the signed-in user
// allowed.
type AccountApplicationsPage struct {
	Layout
	Nav          AccountNav
	Action       string
	Applications []AccountApplication
	Notice       string
}

// PasswordChangedPage says that the password has changed, after a reset
// whose authorization request was gone.
type PasswordChangedPage struct {
	Layout
}

// ConsentPage asks the user to allow or deny a client.
type ConsentPage struct {
	Layout
	// ClientName names the application that asks for access.
	ClientName string
	// Account is the email address of the signed-in user.
	Account string
	// Scopes describes what the application asks for, one line each.
	Scopes []string
	// Action is the URL the form posts to.
	Action string
	// RequestID identifies the stored authorization request.
	RequestID string
}

// FormPostPage posts an authorization response to the client (OAuth 2.0
// Form Post Response Mode, section 2).
type FormPostPage struct {
	Layout
	// Action is the client's redirect URI.
	Action string
	// Fields are the parameters of the response.
	Fields []Field
}

// LogoutPage asks the user to confirm signing out (OpenID Connect
// RP-Initiated Logout 1.0, section 2).
type LogoutPage struct {
	Layout
	// Account is the email address of the signed-in user, or empty.
	Account string
	// ClientName names the application that asks for the logout, or is
	// empty when the request does not show which one.
	ClientName string
	// Problem explains why the browser will stay at Clavis after signing
	// out instead of returning to the application, or is empty.
	Problem string
	// Action is the URL the form posts to, and Fields carry the logout
	// request to it.
	Action string
	Fields []Field
}

// SignedOutPage tells the user that the session ended.
type SignedOutPage struct {
	Layout
	// Problem explains why the browser did not return to the application,
	// or is empty.
	Problem string
}

// Field is a hidden form field.
type Field struct {
	Name  string
	Value string
}

// ScopeDescription describes, for the consent page in the locale of t, what
// a scope lets an application do. resource is the name of the API resource
// that defines the scope, or empty for an OpenID Connect scope.
func ScopeDescription(t i18n.Printer, scope, resource string) string {
	if resource != "" {
		return t.T(i18n.ScopeResource, "resource", resource, "scope", scope)
	}
	key, ok := map[string]i18n.Key{
		"openid":         i18n.ScopeOpenID,
		"profile":        i18n.ScopeProfile,
		"email":          i18n.ScopeEmail,
		"address":        i18n.ScopeAddress,
		"phone":          i18n.ScopePhone,
		"offline_access": i18n.ScopeOfflineAccess,
	}[scope]
	if !ok {
		return scope
	}
	return t.T(key)
}

// ErrorPage explains a request that cannot continue.
type ErrorPage struct {
	Layout
	Title   string
	Message string
}

// pick returns ifTrue when cond holds, and otherwise ifFalse, for pages that
// two flows share.
func pick(cond bool, ifTrue, ifFalse i18n.Key) i18n.Key {
	if cond {
		return ifTrue
	}
	return ifFalse
}
