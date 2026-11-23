package clavis

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/a-h/templ"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ui"
)

// brandingPath is where a tenant's logo is published, relative to its
// issuer.
const brandingPath = "/branding/"

// localeCookie remembers the locale that the user picked with the language
// selector (ADR 0025), for every tenant on the host.
const localeCookie = "__Host-clavis-locale"

// localeCookieMaxAge keeps the user's choice for a year.
const localeCookieMaxAge = 365 * 24 * 60 * 60

// locale returns the language of a hosted page (ADR 0025). chosen is the
// value of ui.LocaleParam in the request, which the language selector sends
// and which a cookie then remembers; without it, the remembered locale
// applies, then uiLocales, the ui_locales parameter of the request that the
// page belongs to, then the Accept-Language header. A choice sent from
// another site applies to its page only, so that a link or a form elsewhere
// cannot change the language of the browser's later pages.
func (s *Server) locale(w http.ResponseWriter, r *http.Request, chosen, uiLocales string) i18n.Locale {
	if l, ok := i18n.ParseLocale(chosen); ok {
		if !sameOrigin(r) {
			return l
		}
		http.SetCookie(w, &http.Cookie{
			Name:     localeCookie,
			Value:    string(l),
			Path:     "/",
			MaxAge:   localeCookieMaxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		return l
	}
	var remembered string
	if c, err := r.Cookie(localeCookie); err == nil {
		remembered = c.Value
	}
	return s.catalogs.Match(remembered, uiLocales, r.Header.Get("Accept-Language"))
}

// sameOrigin reports whether a request comes from a page of the same
// origin, or from the user, by the rules of http.CrossOriginProtection,
// which does not check GET requests: by the Sec-Fetch-Site header, or
// without it by the Origin header. A request with neither header does not
// come from a modern browser and passes.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	default:
		return false
	}
}

// layout returns the frame of a hosted page of tenant t in locale l, with
// the tenant's branding. The branding only changes how the page looks, so
// a failure to load it leaves the defaults.
func (s *Server) layout(r *http.Request, t tenant, l i18n.Locale) ui.Layout {
	layout := ui.Layout{
		Stylesheet: s.issuer.Path + assetsPath + s.assets.Stylesheet(),
		Text:       s.catalogs.Printer(l),
		TenantName: t.Name,
	}
	b, err := app.TenantBranding(r.Context(), s.deps, t.ID)
	if err != nil {
		s.logger.LogAttrs(r.Context(), slog.LevelWarn, "loading the tenant branding failed; using the defaults",
			slog.String("route", r.Pattern), slog.String("error", err.Error()))
		return layout
	}
	layout.SetTheme(ui.ThemeStyle(b.Theme))
	if name, ok := app.LogoName(b.LogoType, b.LogoHash); ok {
		layout.LogoURL = t.path + brandingPath + name
	}
	return layout
}

// handleLogo serves the logo of a tenant under its current published name.
func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request, t tenant) {
	logo, err := app.TenantLogo(r.Context(), s.deps, t.ID)
	switch {
	case errors.Is(err, app.ErrLogoNotFound):
		s.notFound(w)
		return
	case err != nil:
		s.internalError(w, r, "serving the logo", err)
		return
	}
	name, ok := app.LogoName(logo.ContentType, logo.Hash)
	if !ok || r.PathValue("name") != name {
		s.notFound(w)
		return
	}
	h := w.Header()
	h.Set("Content-Type", logo.ContentType)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("X-Content-Type-Options", "nosniff")
	// The image is validated when it is stored; these headers keep a
	// browser from treating it as anything else if it is opened directly.
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(logo.Data))
}

// errorPage renders a page in locale l that explains why a request cannot
// continue: the message of key, with args for its placeholders, under the
// title of titleKey.
func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, t tenant, l i18n.Locale, status int,
	titleKey, key i18n.Key, args ...string,
) {
	layout := s.layout(r, t, l)
	ui.SetPageHeaders(w.Header(), layout.ContentSecurityPolicy(false))
	s.render(w, r, status, ui.Error(ui.ErrorPage{
		Layout:  layout,
		Title:   layout.T(titleKey),
		Message: layout.T(key, args...),
	}))
}

// render writes a page with the given status. Headers must be set already.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page templ.Component) {
	w.WriteHeader(status)
	if err := page.Render(r.Context(), w); err != nil {
		s.logger.LogAttrs(r.Context(), slog.LevelWarn, "rendering a page failed",
			slog.String("route", r.Pattern), slog.String("error", err.Error()))
	}
}
