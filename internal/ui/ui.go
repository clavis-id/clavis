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
	"strings"
	"time"
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
// ContentSecurityPolicy.
func SetPageHeaders(h http.Header, csp string) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// ContentSecurityPolicy returns the policy of a hosted page. Pages load only
// stylesheets and images from their own origin, run no scripts, cannot be
// framed, and submit forms only to their own origin and to formTargets.
// Browsers also apply form-action to the redirects that follow a form
// submission, so a login page must allow the redirect URI it sends the user
// to; FormTarget converts one. Without any form target and without
// allowSelf, the page cannot submit forms at all.
func ContentSecurityPolicy(allowSelf bool, formTargets ...string) string {
	return contentSecurityPolicy("", allowSelf, formTargets)
}

// FormPostContentSecurityPolicy returns the policy of the page that FormPost
// renders: the policy of ContentSecurityPolicy for a form that submits only
// to formTarget, which FormTarget returns for the redirect URI, plus the one
// script that submits the form, allowed by its hash.
func FormPostContentSecurityPolicy(formTarget string) string {
	var targets []string
	if formTarget != "" {
		targets = append(targets, formTarget)
	}
	return contentSecurityPolicy("script-src '"+formPostScriptHash+"'; ", false, targets)
}

func contentSecurityPolicy(scripts string, allowSelf bool, formTargets []string) string {
	var sources []string
	if allowSelf {
		sources = append(sources, "'self'")
	}
	sources = append(sources, formTargets...)
	if len(sources) == 0 {
		sources = []string{"'none'"}
	}
	return "default-src 'none'; " + scripts + "style-src 'self'; img-src 'self'; form-action " +
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

// Layout holds what every page needs.
type Layout struct {
	// Stylesheet is the URL of the main stylesheet.
	Stylesheet string
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

// Field is a hidden form field.
type Field struct {
	Name  string
	Value string
}

// ScopeDescription describes, for the consent page, what a scope lets an
// application do. resource is the name of the API resource that defines the
// scope, or empty for an OpenID Connect scope.
func ScopeDescription(scope, resource string) string {
	switch {
	case resource != "":
		return "Use " + resource + " (" + scope + ")"
	case scope == "openid":
		return "Know who you are"
	case scope == "profile":
		return "See your name and profile"
	case scope == "email":
		return "See your email address"
	case scope == "address":
		return "See your postal address"
	case scope == "phone":
		return "See your phone number"
	case scope == "offline_access":
		return "Keep access while you are signed out"
	default:
		return scope
	}
}

// ErrorPage explains a request that cannot continue.
type ErrorPage struct {
	Layout
	Title   string
	Message string
}
