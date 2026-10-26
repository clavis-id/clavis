package clavis

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"uuid"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/keys"
	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// formContentType is the media type of token requests (RFC 6749, section
// 3.2) and of form-encoded bearer tokens (RFC 6750, section 2.2).
const formContentType = "application/x-www-form-urlencoded"

// handleToken serves the token endpoint (RFC 6749, section 3.2). The client
// authenticates first; only then is the grant examined.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request, t tenant) {
	allowCORS(w)
	s.serveTokenRequest(w, r, func() error {
		client, err := s.authenticateClient(w, r, t)
		if err != nil {
			return err
		}
		at := t.authorizationTenant()
		req, err := oauth.ParseTokenRequest(r.PostForm)
		if err != nil {
			return err
		}
		var resp app.TokenResponse
		switch req.GrantType {
		case oauth.GrantTypeAuthorizationCode:
			resp, err = app.ExchangeCode(r.Context(), s.deps, s.signer, at, client, req)
		case oauth.GrantTypeRefreshToken:
			resp, err = app.RefreshToken(r.Context(), s.deps, s.signer, at, client, req)
		case oauth.GrantTypeClientCredentials:
			resp, err = app.ClientCredentialsToken(r.Context(), s.deps, s.signer, at, client, req)
		default:
			err = &oauth.Error{Code: oauth.ErrorUnsupportedGrantType, Description: "the grant type is not supported"}
		}
		if err != nil {
			return err
		}
		s.writeNoStoreJSON(w, r, http.StatusOK, resp)
		return nil
	})
}

// serveTokenRequest serves a request to the token, revocation or
// introspection endpoint with serve, which writes the response of a success
// and returns the error of a failure. It answers the error, and counts the
// request against the client address when the error counts (ADR 0030).
func (s *Server) serveTokenRequest(w http.ResponseWriter, r *http.Request, serve func() error) {
	res, ok := s.reserveTokenRequest(w, r)
	if !ok {
		return
	}
	err := serve()
	s.settle(res, countsAgainstClient(err))
	if err != nil {
		s.tokenError(w, r, err)
	}
}

// authenticateClient reads the form of a request to the token, revocation
// or introspection endpoint and authenticates the client that sent it (RFC
// 6749, section 2.3).
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request, t tenant) (store.Client, error) {
	if !hasContentType(r, formContentType) {
		return store.Client{}, &oauth.Error{Code: oauth.ErrorInvalidRequest,
			Description: "the request must be application/x-www-form-urlencoded"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		return store.Client{}, &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "the form is malformed"}
	}
	creds, err := oauth.ParseClientCredentials(r.Header.Get("Authorization"), r.PostForm)
	if err != nil {
		return store.Client{}, err
	}
	return app.AuthenticateClient(r.Context(), s.deps, t.ID, creds)
}

// handleRevocation serves the revocation endpoint (RFC 7009, section 2),
// which browser-based clients may call too.
func (s *Server) handleRevocation(w http.ResponseWriter, r *http.Request, t tenant) {
	allowCORS(w)
	s.serveTokenRequest(w, r, func() error {
		client, err := s.authenticateClient(w, r, t)
		if err != nil {
			return err
		}
		token, err := oauth.ParseTokenReference(r.PostForm)
		if err != nil {
			return err
		}
		if err := app.RevokeToken(r.Context(), s.deps, s.signer, t.authorizationTenant(), client, token); err != nil {
			return err
		}
		// Section 2.2: the client ignores the body of a success response.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		return nil
	})
}

// handleIntrospection serves the introspection endpoint (RFC 7662, section
// 2) to confidential clients, which are servers, so it allows no
// cross-origin requests. Inactive tokens do not count against the client
// address: resource servers introspect expired tokens all the time, and
// tokens are too long to be found by scanning (section 4).
func (s *Server) handleIntrospection(w http.ResponseWriter, r *http.Request, t tenant) {
	s.serveTokenRequest(w, r, func() error {
		client, err := s.authenticateClient(w, r, t)
		if err != nil {
			return err
		}
		token, err := oauth.ParseTokenReference(r.PostForm)
		if err != nil {
			return err
		}
		resp, err := app.IntrospectToken(r.Context(), s.deps, s.signer, t.authorizationTenant(), client, token)
		if err != nil {
			return err
		}
		s.writeNoStoreJSON(w, r, http.StatusOK, resp)
		return nil
	})
}

// tokenError answers a request to the token, revocation or introspection
// endpoint with an error response (RFC 6749, section 5.2). A failed client
// authentication answers 401 with the scheme clients can use.
func (s *Server) tokenError(w http.ResponseWriter, r *http.Request, err error) {
	var e *oauth.Error
	if !errors.As(err, &e) {
		s.internalError(w, r, "answering a token request", err)
		return
	}
	status := http.StatusBadRequest
	if e.Code == oauth.ErrorInvalidClient {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="clavis"`)
	}
	s.writeNoStoreJSON(w, r, status, struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitzero"`
	}{e.Code, e.Description})
}

// countsAgainstClient reports whether the error of a request to the token,
// revocation or introspection endpoint counts against the client address
// (ADR 0030): a failed client authentication, or a code or refresh token
// presented again. Other errors are what clients meet in normal use, such as
// an expired refresh token, and the codes, tokens and secrets that requests
// carry are too long to guess.
func countsAgainstClient(err error) bool {
	if errors.Is(err, app.ErrReplayed) {
		return true
	}
	var e *oauth.Error
	return errors.As(err, &e) && e.Code == oauth.ErrorInvalidClient
}

// handleUserInfo serves the userinfo endpoint (OpenID Connect Core 1.0,
// section 5.3) with GET or POST. The access token comes in the
// Authorization header or, for POST, in the form body (RFC 6750, sections
// 2.1 and 2.2).
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request, t tenant) {
	allowCORS(w)
	token, err := bearerToken(w, r)
	if err != nil {
		s.bearerError(w, r, err)
		return
	}
	claims, err := app.UserInfo(r.Context(), s.deps, s.signer, t.authorizationTenant(), token)
	if err != nil {
		s.bearerError(w, r, err)
		return
	}
	s.writeNoStoreJSON(w, r, http.StatusOK, claims)
}

// errNoToken reports a request without an access token. RFC 6750, section
// 3.1, answers it without an error code.
var errNoToken = errors.New("no access token")

// bearerToken returns the access token of a request. A request may use one
// method only.
func bearerToken(w http.ResponseWriter, r *http.Request) (string, error) {
	var fromHeader, fromBody string
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, value, found := strings.Cut(h, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(value) == "" {
			return "", &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "the Authorization header must use the Bearer scheme"}
		}
		fromHeader = strings.TrimSpace(value)
	}
	if r.Method == http.MethodPost && hasContentType(r, formContentType) {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			return "", &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "the form is malformed"}
		}
		values := r.PostForm["access_token"]
		if len(values) > 1 {
			return "", &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "access_token is repeated"}
		}
		if len(values) == 1 {
			fromBody = values[0]
		}
	}
	switch {
	case fromHeader != "" && fromBody != "":
		return "", &oauth.Error{Code: oauth.ErrorInvalidRequest, Description: "the request sends more than one access token"}
	case fromHeader != "":
		return fromHeader, nil
	case fromBody != "":
		return fromBody, nil
	default:
		return "", errNoToken
	}
}

// bearerError answers a protected resource request with the error of RFC
// 6750, section 3.
func (s *Server) bearerError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errNoToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="clavis"`)
		s.writeNoStoreJSON(w, r, http.StatusUnauthorized, struct{}{})
		return
	}
	var e *oauth.Error
	if !errors.As(err, &e) {
		s.internalError(w, r, "answering a userinfo request", err)
		return
	}
	status := http.StatusUnauthorized
	switch e.Code {
	case oauth.ErrorInvalidRequest:
		status = http.StatusBadRequest
	case oauth.ErrorInsufficientScope:
		status = http.StatusForbidden
	}
	// Descriptions are fixed text without quotes, so they fit a quoted
	// string as they are.
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="clavis", error=%q, error_description=%q`,
		e.Code, e.Description))
	s.writeNoStoreJSON(w, r, status, struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitzero"`
	}{e.Code, e.Description})
}

// handlePreflight answers CORS preflight requests to an endpoint that
// browser-based clients call with the given methods. The endpoints that
// allow CORS authenticate with credentials sent explicitly, never with
// cookies, so any origin may call them.
func handlePreflight(methods string) tenantHandler {
	return func(w http.ResponseWriter, _ *http.Request, _ tenant) {
		allowCORS(w)
		h := w.Header()
		h.Set("Access-Control-Allow-Methods", methods)
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
	}
}

// allowCORS lets any origin read the response, without credentials.
func allowCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
}

// hasContentType reports whether the request body has the media type want.
func hasContentType(r *http.Request, want string) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == want
}

// writeNoStoreJSON writes v as a JSON response that no cache may store
// (RFC 6749, section 5.1). The values can come from users, such as a name
// in userinfo, so the encoding escapes the characters that HTML treats
// specially and browsers are told not to guess another media type.
func (s *Server) writeNoStoreJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v, jsontext.EscapeForHTML(true))
	if err != nil {
		s.internalError(w, r, "encoding the response", err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	w.WriteHeader(status)
	//nolint:gosec // G705: the body is JSON with HTML characters escaped, served as application/json with nosniff.
	_, _ = w.Write(body)
}

// tokenSigner signs and verifies tokens with the tenant keys, translating
// failed verifications into app.ErrInvalidToken.
type tokenSigner struct {
	*keys.Manager
}

func (s tokenSigner) Verify(ctx context.Context, tenantID uuid.UUID, token, typ string) ([]byte, error) {
	payload, err := s.Manager.Verify(ctx, tenantID, token, typ)
	if errors.Is(err, keys.ErrInvalidToken) {
		return nil, fmt.Errorf("%w: %w", app.ErrInvalidToken, err)
	}
	return payload, err
}
