package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/store"
)

// Lifetimes of the records of an authorization (ADR 0013, ADR 0014).
const (
	AuthorizationRequestLifetime = 10 * time.Minute
	AuthorizationCodeLifetime    = 60 * time.Second
	// AuthorizationCodeRetention keeps an expired code in the store this
	// long, so a replay soon after expiry is still recognized (RFC 6749,
	// section 4.1.2).
	AuthorizationCodeRetention = time.Hour
	// SessionIdleTimeout ends a session that is not used for this long, and
	// SessionLifetime ends it regardless. Both become tenant settings later.
	SessionIdleTimeout = 24 * time.Hour
	SessionLifetime    = 14 * 24 * time.Hour
)

// amrPassword is the authentication method reference of a password (RFC
// 8176, section 2).
const amrPassword = "pwd"

// ErrAuthorizationRequestNotFound reports a stored authorization request
// that does not exist, has expired, was completed already, or belongs to
// another browser. The cases are not told apart, so a page reveals nothing
// about requests started elsewhere.
var ErrAuthorizationRequestNotFound = errors.New("the sign-in request has expired, was completed already, " +
	"or was started in another browser")

// RedirectError is an authorization error that goes back to the client
// through its redirect URI (RFC 6749, section 4.1.2.1).
type RedirectError struct {
	Err *oauth.Error
	// URI is the redirect URI with the error response.
	URI string
}

func (e *RedirectError) Error() string { return "authorization error: " + e.Err.Error() }

func (e *RedirectError) Unwrap() error { return e.Err }

// AuthorizationTenant is the tenant that receives an authorization request,
// with its issuer identifier, which responses carry (RFC 9207).
type AuthorizationTenant struct {
	ID     uuid.UUID
	Issuer string
}

// StartAuthorization validates an authorization request and stores it for
// the sign-in that follows, bound to the browser whose binding cookie hashes
// to bindingHash (ADR 0013). It returns the ID of the stored request.
//
// A request whose client or redirect URI is unusable returns an error that
// wraps oauth.ErrInvalidAuthorizationTarget, which must be shown to the user;
// any other invalid request returns a *RedirectError.
func StartAuthorization(ctx context.Context, d Deps, t AuthorizationTenant, params url.Values,
	bindingHash []byte,
) (string, error) {
	client, redirectURI, provided, err := authorizationTarget(ctx, d, t.ID, params)
	if err != nil {
		return "", err
	}
	fail := func(e *oauth.Error, state string) error {
		return &RedirectError{Err: e, URI: errorResponseURI(redirectURI, t.Issuer, state, e)}
	}

	r, err := oauth.ParseAuthorizationRequest(params)
	if err != nil {
		var oauthErr *oauth.Error
		if !errors.As(err, &oauthErr) {
			return "", fmt.Errorf("parsing the authorization request: %w", err)
		}
		return "", fail(oauthErr, r.State)
	}
	if !slices.Contains(client.GrantTypes, oauth.GrantTypeAuthorizationCode) {
		return "", fail(&oauth.Error{Code: oauth.ErrorUnauthorizedClient,
			Description: "the client may not use the authorization code grant"}, r.State)
	}
	for _, scope := range r.Scopes {
		if !slices.Contains(client.Scopes, scope) {
			return "", fail(&oauth.Error{Code: oauth.ErrorInvalidScope,
				Description: "the client may not request every scope in the request"}, r.State)
		}
	}
	owners, err := scopeOwners(ctx, d, t.ID)
	if err != nil {
		return "", err
	}
	if undefinedScope(r.Scopes, owners) != "" {
		return "", fail(&oauth.Error{Code: oauth.ErrorInvalidScope,
			Description: "the request includes a scope that no API resource defines"}, r.State)
	}
	// ADR 0018: PKCE is required unless an operator exempted this
	// confidential client.
	if r.CodeChallenge == "" && (client.Type != store.ClientConfidential || !client.PKCEExempt) {
		return "", fail(&oauth.Error{Code: oauth.ErrorInvalidRequest,
			Description: "code_challenge is required"}, r.State)
	}
	// Sessions are not reused until single sign-on arrives, so a request
	// that forbids interaction always needs a login it cannot get (OpenID
	// Connect Core 1.0, section 3.1.2.6).
	if r.HasPrompt(oauth.PromptNone) {
		return "", fail(&oauth.Error{Code: oauth.ErrorLoginRequired,
			Description: "the user must sign in"}, r.State)
	}

	now := d.Now()
	stored := store.AuthorizationRequest{
		ID:                  oauth.NewRequestID(),
		TenantID:            t.ID,
		ClientID:            client.ID,
		BindingHash:         bindingHash,
		RedirectURI:         redirectURI,
		RedirectURIProvided: provided,
		Scopes:              r.Scopes,
		State:               r.State,
		Nonce:               r.Nonce,
		CreatedAt:           now,
		ExpiresAt:           now.Add(AuthorizationRequestLifetime),
	}
	if r.CodeChallenge != "" {
		stored.CodeChallenge = r.CodeChallenge
		stored.CodeChallengeMethod = oauth.CodeChallengeMethodS256
	}
	if err := d.Store.AuthorizationRequests().Create(ctx, stored); err != nil {
		return "", fmt.Errorf("storing the authorization request: %w", err)
	}
	return stored.ID, nil
}

// authorizationTarget finds the client of an authorization request and the
// redirect URI its response goes to. provided says whether the request named
// the redirect URI. Errors wrap oauth.ErrInvalidAuthorizationTarget unless
// the store fails.
func authorizationTarget(ctx context.Context, d Deps, tenantID uuid.UUID, params url.Values,
) (client store.Client, redirectURI string, provided bool, err error) {
	clientID, redirectURI, err := oauth.AuthorizationTarget(params)
	if err != nil {
		return store.Client{}, "", false, err
	}
	client, err = d.Store.Clients().GetByClientID(ctx, tenantID, clientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Client{}, "", false, fmt.Errorf("%w: unknown client", oauth.ErrInvalidAuthorizationTarget)
	case err != nil:
		return store.Client{}, "", false, fmt.Errorf("looking up the client: %w", err)
	}
	if redirectURI != "" {
		if !oauth.MatchRedirectURI(client.RedirectURIs, redirectURI) {
			return store.Client{}, "", false, fmt.Errorf("%w: redirect_uri is not registered for the client",
				oauth.ErrInvalidAuthorizationTarget)
		}
		return client, redirectURI, true, nil
	}
	// OAuth 2.1 lets a request omit the redirect URI when the client has
	// only one; OpenID Connect Core 1.0, section 3.1.2.1, always requires it.
	switch {
	case slices.Contains(strings.Split(params.Get("scope"), " "), oauth.ScopeOpenID):
		return store.Client{}, "", false, fmt.Errorf("%w: redirect_uri is required in OpenID Connect requests",
			oauth.ErrInvalidAuthorizationTarget)
	case len(client.RedirectURIs) != 1:
		return store.Client{}, "", false, fmt.Errorf("%w: redirect_uri is required because the client "+
			"has several or none", oauth.ErrInvalidAuthorizationTarget)
	}
	return client, client.RedirectURIs[0], false, nil
}

// errorResponseURI returns the error response of an authorization request
// (RFC 6749, section 4.1.2.1), with the issuer (RFC 9207, section 2).
func errorResponseURI(redirectURI, issuer, state string, e *oauth.Error) string {
	params := url.Values{"error": {e.Code}, "error_description": {e.Description}, "iss": {issuer}}
	if state != "" {
		params.Set("state", state)
	}
	return oauth.AuthorizationResponseURI(redirectURI, params)
}

// PendingAuthorization is a stored authorization request that waits for
// the user to sign in, with its client.
type PendingAuthorization struct {
	Request store.AuthorizationRequest
	Client  store.Client
}

// FindAuthorizationRequest returns a stored authorization request and its
// client, provided that the request has not expired and that bindingHash is
// the binding hash it was stored with. Every failure other than a store
// error returns ErrAuthorizationRequestNotFound.
func FindAuthorizationRequest(ctx context.Context, d Deps, tenantID uuid.UUID, id string, bindingHash []byte,
) (PendingAuthorization, error) {
	if !oauth.ValidRequestID(id) {
		return PendingAuthorization{}, ErrAuthorizationRequestNotFound
	}
	r, err := d.Store.AuthorizationRequests().Get(ctx, tenantID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return PendingAuthorization{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return PendingAuthorization{}, fmt.Errorf("looking up the authorization request: %w", err)
	case !d.Now().Before(r.ExpiresAt), subtle.ConstantTimeCompare(r.BindingHash, bindingHash) != 1:
		return PendingAuthorization{}, ErrAuthorizationRequestNotFound
	}
	client, err := d.Store.Clients().Get(ctx, tenantID, r.ClientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The client was deleted after the request was found.
		return PendingAuthorization{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return PendingAuthorization{}, fmt.Errorf("looking up the client: %w", err)
	}
	return PendingAuthorization{Request: r, Client: client}, nil
}

// Login is a completed sign-in.
type Login struct {
	// RedirectURI is the authorization response to send the browser to.
	RedirectURI string
	// SessionToken is the value of the new session cookie, which expires at
	// SessionExpiresAt.
	SessionToken     string
	SessionExpiresAt time.Time
}

// CompletePasswordLogin signs a user in with a password and answers the
// authorization request p, which FindAuthorizationRequest returned. It
// replaces the session whose token hashes to previousSession, if any, with
// a new one, and issues an authorization code bound to the request
// (ADR 0014).
//
// Wrong credentials return ErrInvalidCredentials and leave the request in
// place for another attempt; a request completed in the meantime returns
// ErrAuthorizationRequestNotFound.
func CompletePasswordLogin(ctx context.Context, d Deps, h PasswordHasher, t AuthorizationTenant,
	p PendingAuthorization, email, pw string, previousSession []byte,
) (Login, error) {
	r := p.Request
	u, err := AuthenticatePassword(ctx, d, h, t.ID, email, pw)
	if err != nil {
		return Login{}, err
	}
	// Deleting the request first makes it single use: of two concurrent
	// sign-ins, only one gets a code.
	switch err := d.Store.AuthorizationRequests().Delete(ctx, t.ID, r.ID); {
	case errors.Is(err, store.ErrNotFound):
		return Login{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return Login{}, fmt.Errorf("completing the authorization request: %w", err)
	}

	if previousSession != nil {
		if err := endSession(ctx, d, t.ID, previousSession); err != nil {
			return Login{}, err
		}
	}
	now := d.Now()
	token := oauth.NewToken()
	session := store.Session{
		ID:            d.NewID(),
		TenantID:      t.ID,
		TokenHash:     oauth.HashToken(token),
		UserID:        u.ID,
		AuthTime:      now,
		AMR:           []string{amrPassword},
		CreatedAt:     now,
		LastSeenAt:    now,
		IdleExpiresAt: now.Add(SessionIdleTimeout),
		ExpiresAt:     now.Add(SessionLifetime),
	}
	if err := d.Store.Sessions().Create(ctx, session); err != nil {
		return Login{}, fmt.Errorf("creating the session: %w", err)
	}

	code := oauth.NewToken()
	if err := d.Store.AuthorizationCodes().Create(ctx, store.AuthorizationCode{
		Hash:                oauth.HashToken(code),
		TenantID:            t.ID,
		ClientID:            r.ClientID,
		UserID:              u.ID,
		SessionID:           session.ID,
		RedirectURI:         r.RedirectURI,
		RedirectURIProvided: r.RedirectURIProvided,
		Scopes:              r.Scopes,
		Nonce:               r.Nonce,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		AuthTime:            session.AuthTime,
		AMR:                 session.AMR,
		CreatedAt:           now,
		ExpiresAt:           now.Add(AuthorizationCodeLifetime),
	}); err != nil {
		return Login{}, fmt.Errorf("storing the authorization code: %w", err)
	}

	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed in",
		slog.String("tenant_id", t.ID.String()),
		slog.String("user_id", u.ID.String()),
		slog.String("client_id", p.Client.ClientID),
		slog.String("session_id", session.ID.String()))

	// RFC 6749, section 4.1.2, and RFC 9207, section 2.
	params := url.Values{"code": {code}, "iss": {t.Issuer}}
	if r.State != "" {
		params.Set("state", r.State)
	}
	return Login{
		RedirectURI:      oauth.AuthorizationResponseURI(r.RedirectURI, params),
		SessionToken:     token,
		SessionExpiresAt: session.ExpiresAt,
	}, nil
}

// endSession deletes the session of a tenant whose token hashes to
// tokenHash, if it exists.
func endSession(ctx context.Context, d Deps, tenantID uuid.UUID, tokenHash []byte) error {
	s, err := d.Store.Sessions().GetByTokenHash(ctx, tenantID, tokenHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("looking up the previous session: %w", err)
	}
	if err := d.Store.Sessions().Delete(ctx, tenantID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("ending the previous session: %w", err)
	}
	return nil
}

// PurgeExpired deletes the expired authorization requests, sessions and
// access token records of every tenant, and the codes that expired more than
// AuthorizationCodeRetention ago. It goes on after a failure and returns
// every error.
func PurgeExpired(ctx context.Context, d Deps) error {
	now := d.Now()
	var errs []error
	purge := func(what string, deleteExpired func(context.Context, time.Time) (int64, error), before time.Time) int64 {
		n, err := deleteExpired(ctx, before)
		if err != nil {
			errs = append(errs, fmt.Errorf("deleting expired %s: %w", what, err))
		}
		return n
	}
	requests := purge("authorization requests", d.Store.AuthorizationRequests().DeleteExpired, now)
	sessions := purge("sessions", d.Store.Sessions().DeleteExpired, now)
	codes := purge("authorization codes", d.Store.AuthorizationCodes().DeleteExpired,
		now.Add(-AuthorizationCodeRetention))
	tokens := purge("access tokens", d.Store.AccessTokens().DeleteExpired, now)
	if requests+sessions+codes+tokens > 0 {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted expired records",
			slog.Int64("authorization_requests", requests),
			slog.Int64("sessions", sessions),
			slog.Int64("authorization_codes", codes),
			slog.Int64("access_tokens", tokens))
	}
	return errors.Join(errs...)
}
