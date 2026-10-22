package app

import (
	"context"
	"crypto/subtle"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
	"uuid"

	"clavisid.org/clavis/internal/oauth"
	"clavisid.org/clavis/internal/oidc"
	"clavisid.org/clavis/store"
)

// Lifetimes of the records of an authorization (ADR 0013, ADR 0014).
const (
	AuthorizationRequestLifetime = 10 * time.Minute
	AuthorizationCodeLifetime    = 60 * time.Second
	// AuthorizationCodeRetention keeps an expired code in the store this
	// long, so a replay of it is still recognized (RFC 6749, section 4.1.2)
	// and ending its session still finds the access tokens issued from it,
	// which live a day at most (ADR 0023).
	AuthorizationCodeRetention = maxTokenLifetime + time.Hour
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

// AuthorizationResponse is a response to an authorization request that goes
// back to the client through its redirect URI, with a code or an error (RFC
// 6749, section 4.1.2). Without FormPost the browser goes to URI(); with it
// the browser posts Params to RedirectURI (OAuth 2.0 Form Post Response
// Mode, section 2).
type AuthorizationResponse struct {
	RedirectURI string
	Params      url.Values
	FormPost    bool
}

// URI returns RedirectURI with the response parameters added to its query.
func (r AuthorizationResponse) URI() string {
	return oauth.AuthorizationResponseURI(r.RedirectURI, r.Params)
}

// authorizationResponse returns the response that sends params to
// redirectURI in the given response mode.
func authorizationResponse(redirectURI, responseMode string, params url.Values) AuthorizationResponse {
	return AuthorizationResponse{RedirectURI: redirectURI, Params: params,
		FormPost: responseMode == oauth.ResponseModeFormPost}
}

// RedirectError is an authorization error that goes back to the client
// through its redirect URI (RFC 6749, section 4.1.2.1).
type RedirectError struct {
	Err      *oauth.Error
	Response AuthorizationResponse
}

func (e *RedirectError) Error() string { return "authorization error: " + e.Err.Error() }

func (e *RedirectError) Unwrap() error { return e.Err }

// AuthorizationTenant is the tenant that receives an authorization request,
// with its issuer identifier, which responses carry (RFC 9207), and whether
// it offers signup (ADR 0026).
type AuthorizationTenant struct {
	ID     uuid.UUID
	Issuer string
	Signup bool
}

// Authorization is the outcome of a valid authorization request. When the
// browser's session answers the request, Response is the authorization
// response. Otherwise its RedirectURI is empty, and the request is stored
// under RequestID: it waits for the user to sign in, or to sign up when
// Signup is true (prompt=create), or, when Consent is true, for the consent
// of the session's user.
type Authorization struct {
	Response  AuthorizationResponse
	RequestID string
	Consent   bool
	Signup    bool
}

// StartAuthorization validates an authorization request (ADR 0013). When the
// session whose cookie hashes to sessionHash satisfies the request, and the
// request needs no consent (ADR 0020), it issues an authorization code at
// once: that is single sign-on. Otherwise it stores the request for the
// sign-in or the consent that follows, bound to the browser whose binding
// cookie hashes to bindingHash. signer verifies an id_token_hint.
//
// A request whose client or redirect URI is unusable returns an error that
// wraps oauth.ErrInvalidAuthorizationTarget, which must be shown to the user;
// any other invalid request returns a *RedirectError.
func StartAuthorization(ctx context.Context, d Deps, signer TokenSigner, t AuthorizationTenant, params url.Values,
	bindingHash, sessionHash []byte,
) (Authorization, error) {
	client, redirectURI, provided, err := authorizationTarget(ctx, d, t.ID, params)
	if err != nil {
		return Authorization{}, err
	}
	r, err := oauth.ParseAuthorizationRequest(params)
	fail := func(e *oauth.Error, state string) error {
		return &RedirectError{Err: e, Response: errorResponse(redirectURI, r.ResponseMode, t.Issuer, state, e)}
	}
	if err != nil {
		var oauthErr *oauth.Error
		if !errors.As(err, &oauthErr) {
			return Authorization{}, fmt.Errorf("parsing the authorization request: %w", err)
		}
		return Authorization{}, fail(oauthErr, r.State)
	}
	// Initiating User Registration via OpenID Connect 1.0, section 4.1: a
	// prompt value the tenant does not support is an invalid request.
	if r.HasPrompt(oauth.PromptCreate) && !t.Signup {
		return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorInvalidRequest,
			Description: "prompt contains an unsupported value"}, r.State)
	}
	if !slices.Contains(client.GrantTypes, oauth.GrantTypeAuthorizationCode) {
		return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorUnauthorizedClient,
			Description: "the client may not use the authorization code grant"}, r.State)
	}
	for _, scope := range r.Scopes {
		if !slices.Contains(client.Scopes, scope) {
			return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorInvalidScope,
				Description: "the client may not request every scope in the request"}, r.State)
		}
	}
	owners, err := scopeOwners(ctx, d, t.ID)
	if err != nil {
		return Authorization{}, err
	}
	if undefinedScope(r.Scopes, owners) != "" {
		return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorInvalidScope,
			Description: "the request includes a scope that no API resource defines"}, r.State)
	}
	// ADR 0018: PKCE is required unless an operator exempted this
	// confidential client.
	if r.CodeChallenge == "" && (client.Type != store.ClientConfidential || !client.PKCEExempt) {
		return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorInvalidRequest,
			Description: "code_challenge is required"}, r.State)
	}
	hintSubject, err := verifyIDTokenHint(ctx, signer, t, client, r.IDTokenHint)
	if err != nil {
		var oauthErr *oauth.Error
		if errors.As(err, &oauthErr) {
			return Authorization{}, fail(oauthErr, r.State)
		}
		return Authorization{}, err
	}
	subject, oauthErr := requiredSubject(hintSubject, r.Claims.IDToken["sub"])
	if oauthErr != nil {
		return Authorization{}, fail(oauthErr, r.State)
	}
	// ADR 0019 and OpenID Connect Core 1.0, section 5.5.1.1: an essential
	// acr with values Clavis cannot produce fails the authentication.
	if acr, ok := r.Claims.IDToken["acr"]; ok && acr.Essential && len(acr.Values) > 0 &&
		!slices.Contains(acr.Values, oidc.ACRPassword) {
		return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorAccessDenied,
			Description: "the requested authentication context class is not available"}, r.State)
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
		HintSubject:         subject,
		ResponseMode:        r.ResponseMode,
		ForceConsent:        r.HasPrompt(oauth.PromptConsent),
		UILocales:           r.UILocales,
		CreatedAt:           now,
		ExpiresAt:           now.Add(AuthorizationRequestLifetime),
	}
	if r.CodeChallenge != "" {
		stored.CodeChallenge = r.CodeChallenge
		stored.CodeChallengeMethod = oauth.CodeChallengeMethodS256
	}
	// The claims parameter belongs to OpenID Connect requests.
	if r.OpenID() {
		stored.UserInfoClaims = grantableClaims(r.Claims.UserInfo, client)
		stored.IDTokenClaims = grantableClaims(r.Claims.IDToken, client)
	}

	session, ok, err := resumeSession(ctx, d, t.ID, sessionHash, r, subject)
	switch {
	case err != nil:
		return Authorization{}, err
	case ok:
		consent, err := needsConsent(ctx, d, client, session.UserID, stored)
		switch {
		case err != nil:
			return Authorization{}, err
		case consent && r.HasPrompt(oauth.PromptNone):
			// OpenID Connect Core 1.0, section 3.1.2.6.
			return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorConsentRequired,
				Description: "the user must allow the client"}, r.State)
		case consent:
			stored.SessionID = session.ID
			if err := d.Store.AuthorizationRequests().Create(ctx, stored); err != nil {
				return Authorization{}, fmt.Errorf("storing the authorization request: %w", err)
			}
			return Authorization{RequestID: stored.ID, Consent: true}, nil
		}
		resp, err := issueCode(ctx, d, t, stored, session)
		if err != nil {
			return Authorization{}, err
		}
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed in with an existing session",
			slog.String("tenant_id", t.ID.String()),
			slog.String("user_id", session.UserID.String()),
			slog.String("client_id", client.ClientID),
			slog.String("session_id", session.ID.String()))
		return Authorization{Response: resp}, nil
	case r.HasPrompt(oauth.PromptNone):
		// OpenID Connect Core 1.0, section 3.1.2.6: the request forbids the
		// sign-in it needs.
		return Authorization{}, fail(&oauth.Error{Code: oauth.ErrorLoginRequired,
			Description: "the user must sign in"}, r.State)
	}

	// A login_hint that is not an email address cannot help the sign-in
	// form, which asks for one.
	stored.LoginHint, _ = NormalizeEmail(r.LoginHint)
	if err := d.Store.AuthorizationRequests().Create(ctx, stored); err != nil {
		return Authorization{}, fmt.Errorf("storing the authorization request: %w", err)
	}
	return Authorization{RequestID: stored.ID, Signup: r.HasPrompt(oauth.PromptCreate)}, nil
}

// verifyIDTokenHint returns the user that an id_token_hint names, or the
// zero UUID when hint is empty. The hint must be an ID token that the tenant
// issued to client, which may have expired (OpenID Connect Core 1.0, section
// 3.1.2.1). An invalid hint returns an *oauth.Error.
func verifyIDTokenHint(ctx context.Context, signer TokenSigner, t AuthorizationTenant, client store.Client,
	hint string,
) (uuid.UUID, error) {
	if hint == "" {
		return uuid.Nil(), nil
	}
	invalid := &oauth.Error{Code: oauth.ErrorInvalidRequest,
		Description: "id_token_hint is not an ID token that this provider issued to the client"}
	payload, err := signer.Verify(ctx, t.ID, hint, oidc.IDTokenType)
	switch {
	case errors.Is(err, ErrInvalidToken):
		return uuid.Nil(), invalid
	case err != nil:
		return uuid.Nil(), fmt.Errorf("verifying the id_token_hint: %w", err)
	}
	var claims oidc.IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != t.Issuer ||
		claims.Audience != client.ClientID {
		return uuid.Nil(), invalid
	}
	subject, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil(), invalid
	}
	return subject, nil
}

// requiredSubject returns the user who alone may answer a request: the
// subject of its id_token_hint, or the user it names by requesting the sub
// claim of the ID token with a value (OpenID Connect Core 1.0, sections
// 3.1.2.1 and 5.5.1). It returns the zero UUID when any user may answer, and
// an error when no user can.
func requiredSubject(hintSubject uuid.UUID, sub oauth.ClaimRequest) (uuid.UUID, *oauth.Error) {
	if !sub.ValueRequested {
		return hintSubject, nil
	}
	var subjects []uuid.UUID
	for _, v := range sub.Values {
		// Claim values are compared as strings, so only the canonical form
		// of a user ID names a user.
		if id, err := uuid.Parse(v); err == nil && id.String() == v && !slices.Contains(subjects, id) {
			subjects = append(subjects, id)
		}
	}
	switch {
	case hintSubject != uuid.Nil() && slices.Contains(subjects, hintSubject):
		return hintSubject, nil
	case hintSubject != uuid.Nil():
		return uuid.Nil(), &oauth.Error{Code: oauth.ErrorLoginRequired,
			Description: "id_token_hint and the requested sub claim name different users"}
	case len(subjects) == 0:
		return uuid.Nil(), &oauth.Error{Code: oauth.ErrorLoginRequired,
			Description: "no user has the requested sub claim"}
	case len(subjects) > 1:
		return uuid.Nil(), &oauth.Error{Code: oauth.ErrorInvalidRequest,
			Description: "the sub claim may be requested with one value only"}
	}
	return subjects[0], nil
}

// grantableClaims returns, sorted, the names in requested of the claims
// about the user that the client may receive individually (OpenID Connect
// Core 1.0, section 5.5): claims that a scope requests, when the client may
// request that scope. Other names are ignored.
func grantableClaims(requested map[string]oauth.ClaimRequest, client store.Client) []string {
	var names []string
	for name := range requested {
		if scope := oidc.ClaimScope(name); scope != "" && slices.Contains(client.Scopes, scope) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// resumeSession returns the session whose token hashes to tokenHash when it
// can answer r without signing the user in again (ADR 0013), after
// recording its use. That needs a session that has not expired, of a user
// who can still sign in and, when subject is not the zero UUID, of that
// user. It also needs a request that asks for no interaction and accepts the
// age of the authentication.
func resumeSession(ctx context.Context, d Deps, tenantID uuid.UUID, tokenHash []byte, r oauth.AuthorizationRequest,
	subject uuid.UUID,
) (store.Session, bool, error) {
	// Until account selection exists, the sign-in form answers
	// prompt=select_account: it lets the user choose the account.
	// prompt=create asks for the signup page instead of the session.
	if tokenHash == nil || r.HasPrompt(oauth.PromptLogin) || r.HasPrompt(oauth.PromptSelectAccount) ||
		r.HasPrompt(oauth.PromptCreate) {
		return store.Session{}, false, nil
	}
	s, err := d.Store.Sessions().GetByTokenHash(ctx, tenantID, tokenHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Session{}, false, nil
	case err != nil:
		return store.Session{}, false, fmt.Errorf("looking up the session: %w", err)
	}
	now := d.Now()
	switch {
	case !now.Before(s.IdleExpiresAt), !now.Before(s.ExpiresAt):
		return store.Session{}, false, nil
	// OpenID Connect Core 1.0, section 3.1.2.1: max_age=0 is equivalent to
	// prompt=login.
	case r.MaxAge == 0, r.MaxAge > 0 && now.Sub(s.AuthTime) > time.Duration(r.MaxAge)*time.Second:
		return store.Session{}, false, nil
	case subject != uuid.Nil() && subject != s.UserID:
		return store.Session{}, false, nil
	}
	u, err := d.Store.Users().Get(ctx, tenantID, s.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && u.Status != store.UserActive:
		return store.Session{}, false, nil
	case err != nil:
		return store.Session{}, false, fmt.Errorf("looking up the user of the session: %w", err)
	}
	s.LastSeenAt = now
	s.IdleExpiresAt = now.Add(SessionIdleTimeout)
	if s.IdleExpiresAt.After(s.ExpiresAt) {
		s.IdleExpiresAt = s.ExpiresAt
	}
	switch err := d.Store.Sessions().Touch(ctx, tenantID, s.ID, s.LastSeenAt, s.IdleExpiresAt); {
	case errors.Is(err, store.ErrNotFound):
		// The session ended in the meantime.
		return store.Session{}, false, nil
	case err != nil:
		return store.Session{}, false, fmt.Errorf("recording the use of the session: %w", err)
	}
	return s, true, nil
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
		// Responses go to the registered URI, never to the request's string.
		resolved, ok := oauth.ResolveRedirectURI(client.RedirectURIs, redirectURI)
		if !ok {
			return store.Client{}, "", false, fmt.Errorf("%w: redirect_uri is not registered for the client",
				oauth.ErrInvalidAuthorizationTarget)
		}
		return client, resolved, true, nil
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

// errorResponse returns the error response of an authorization request
// (RFC 6749, section 4.1.2.1), with the issuer (RFC 9207, section 2).
func errorResponse(redirectURI, responseMode, issuer, state string, e *oauth.Error) AuthorizationResponse {
	params := url.Values{"error": {e.Code}, "error_description": {e.Description}, "iss": {issuer}}
	if state != "" {
		params.Set("state", state)
	}
	return authorizationResponse(redirectURI, responseMode, params)
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
	// Response is the authorization response. Its RedirectURI is empty when
	// Consent is true: the request then waits for the user's consent.
	Response AuthorizationResponse
	Consent  bool
	// SessionToken is the value of the new session cookie, which expires at
	// SessionExpiresAt.
	SessionToken     string
	SessionExpiresAt time.Time
	// sessionID identifies the new session.
	sessionID uuid.UUID
}

// CompletePasswordLogin signs a user in with a password and answers the
// authorization request p, which FindAuthorizationRequest returned, as
// signIn describes. Wrong credentials return ErrInvalidCredentials and leave
// the request in place for another attempt; a request completed in the
// meantime returns ErrAuthorizationRequestNotFound.
func CompletePasswordLogin(ctx context.Context, d Deps, h PasswordHasher, t AuthorizationTenant,
	p PendingAuthorization, email, pw string, previousSession []byte,
) (Login, error) {
	if p.Request.SessionID != uuid.Nil() {
		// A user signed in for the request already; it waits for consent.
		return Login{}, ErrAuthorizationRequestNotFound
	}
	u, setAt, err := authenticatePassword(ctx, d, h, t.ID, email, pw)
	if err != nil {
		return Login{}, err
	}
	login, err := signIn(ctx, d, t, p, u, previousSession)
	if err != nil {
		return Login{}, err
	}
	if err := confirmPassword(ctx, d, t.ID, u, setAt, login); err != nil {
		return Login{}, err
	}
	return login, nil
}

// confirmPassword checks that the password of user u is still the one set at
// setAt, which a sign-in verified before it started the session of login. A
// password change in the meantime ended every session that existed then
// (ADR 0027), and this session must not outlive it: confirmPassword ends it,
// with the codes issued in it, and returns ErrInvalidCredentials. Whatever
// the order of the two, the session ends: either the change finds it, or
// this check finds the change.
func confirmPassword(ctx context.Context, d Deps, tenantID uuid.UUID, u store.User, setAt time.Time, login Login,
) error {
	current, err := d.Store.Passwords().Get(ctx, tenantID, u.ID)
	switch {
	case err == nil && current.SetAt.Equal(setAt):
		return nil
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("looking up password: %w", err)
	}
	if _, _, err := endSession(ctx, d, tenantID, store.Session{ID: login.sessionID}); err != nil {
		return err
	}
	d.Logger.LogAttrs(ctx, slog.LevelWarn, "the password changed during a sign-in; ended the new session",
		slog.String("tenant_id", tenantID.String()), slog.String("user_id", u.ID.String()),
		slog.String("session_id", login.sessionID.String()))
	return ErrInvalidCredentials
}

// signIn starts a session of user u, who has just authenticated with a
// password, and answers the authorization request p with it. It replaces
// the session whose token hashes to previousSession, if any, as
// replaceSession describes, and issues an authorization code bound to the
// request (ADR 0014). When the request names another user, through
// id_token_hint or the sub claim, the response is a login_required error
// instead (OpenID Connect Core 1.0, sections 3.1.2.1 and 5.5.1), and the new
// session stays. When the request needs the user's consent (ADR 0020), it
// keeps waiting, with the new session, and Login.Consent is true. A request
// completed in the meantime returns ErrAuthorizationRequestNotFound.
func signIn(ctx context.Context, d Deps, t AuthorizationTenant, p PendingAuthorization, u store.User,
	previousSession []byte,
) (Login, error) {
	r := p.Request
	otherUser := r.HintSubject != uuid.Nil() && r.HintSubject != u.ID
	consent := false
	if !otherUser {
		var err error
		if consent, err = needsConsent(ctx, d, p.Client, u.ID, r); err != nil {
			return Login{}, err
		}
	}
	// Claiming the request first makes it single use: of two concurrent
	// sign-ins, only one gets a code or the consent page. A request that
	// waits for consent keeps the session of this sign-in.
	sessionID := d.NewID()
	claim := func() error { return d.Store.AuthorizationRequests().Delete(ctx, t.ID, r.ID) }
	if consent {
		claim = func() error { return d.Store.AuthorizationRequests().SetSession(ctx, t.ID, r.ID, sessionID) }
	}
	switch err := claim(); {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
		return Login{}, ErrAuthorizationRequestNotFound
	case err != nil:
		return Login{}, fmt.Errorf("completing the authorization request: %w", err)
	}

	session, token, err := startSession(ctx, d, t.ID, sessionID, u.ID, previousSession)
	if err != nil {
		return Login{}, err
	}
	d.Logger.LogAttrs(ctx, slog.LevelInfo, "user signed in",
		slog.String("tenant_id", t.ID.String()),
		slog.String("user_id", u.ID.String()),
		slog.String("client_id", p.Client.ClientID),
		slog.String("session_id", session.ID.String()))

	login := Login{SessionToken: token, SessionExpiresAt: session.ExpiresAt, Consent: consent, sessionID: session.ID}
	switch {
	case otherUser:
		login.Response = errorResponse(r.RedirectURI, r.ResponseMode, t.Issuer, r.State, &oauth.Error{
			Code: oauth.ErrorLoginRequired, Description: "the user who signed in is not the user the request names"})
	case !consent:
		if login.Response, err = issueCode(ctx, d, t, r, session); err != nil {
			return Login{}, err
		}
	}
	return login, nil
}

// startSession stores a new session with the ID sessionID for user userID,
// who has just authenticated with a password, and returns it with the value
// of its cookie. It replaces the session whose token hashes to
// previousSession, if any, as replaceSession describes.
func startSession(ctx context.Context, d Deps, tenantID, sessionID, userID uuid.UUID, previousSession []byte,
) (store.Session, string, error) {
	if previousSession != nil {
		if err := replaceSession(ctx, d, tenantID, previousSession, sessionID, userID); err != nil {
			return store.Session{}, "", err
		}
	}
	now := d.Now()
	token := oauth.NewToken()
	session := store.Session{
		ID:            sessionID,
		TenantID:      tenantID,
		TokenHash:     oauth.HashToken(token),
		UserID:        userID,
		AuthTime:      now,
		AMR:           []string{amrPassword},
		ACR:           oidc.ACRPassword,
		CreatedAt:     now,
		LastSeenAt:    now,
		IdleExpiresAt: now.Add(SessionIdleTimeout),
		ExpiresAt:     now.Add(SessionLifetime),
	}
	if err := d.Store.Sessions().Create(ctx, session); err != nil {
		return store.Session{}, "", fmt.Errorf("creating the session: %w", err)
	}
	return session, token, nil
}

// issueCode issues an authorization code that answers r for the user of
// session (ADR 0014) and returns the authorization response.
func issueCode(ctx context.Context, d Deps, t AuthorizationTenant, r store.AuthorizationRequest, session store.Session,
) (AuthorizationResponse, error) {
	now := d.Now()
	code := oauth.NewToken()
	if err := d.Store.AuthorizationCodes().Create(ctx, store.AuthorizationCode{
		Hash:                oauth.HashToken(code),
		TenantID:            t.ID,
		ClientID:            r.ClientID,
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         r.RedirectURI,
		RedirectURIProvided: r.RedirectURIProvided,
		Scopes:              r.Scopes,
		Nonce:               r.Nonce,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		AuthTime:            session.AuthTime,
		AMR:                 session.AMR,
		ACR:                 session.ACR,
		UserInfoClaims:      r.UserInfoClaims,
		IDTokenClaims:       r.IDTokenClaims,
		CreatedAt:           now,
		ExpiresAt:           now.Add(AuthorizationCodeLifetime),
	}); err != nil {
		return AuthorizationResponse{}, fmt.Errorf("storing the authorization code: %w", err)
	}
	// RFC 6749, section 4.1.2, and RFC 9207, section 2.
	params := url.Values{"code": {code}, "iss": {t.Issuer}}
	if r.State != "" {
		params.Set("state", r.State)
	}
	return authorizationResponse(r.RedirectURI, r.ResponseMode, params), nil
}

// replaceSession ends the session of a tenant whose token hashes to
// tokenHash, if it exists, because a sign-in of the user with the ID userID
// replaces it with the session with the ID next (ADR 0023). When the same
// user signs in again, next takes over the codes of the old session, and
// with them its online access, which a logout then ends. When another user
// signs in, the old user is signed out of the browser, and the online access
// of the old session ends as at logout.
func replaceSession(ctx context.Context, d Deps, tenantID uuid.UUID, tokenHash []byte, next, userID uuid.UUID) error {
	s, err := d.Store.Sessions().GetByTokenHash(ctx, tenantID, tokenHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("looking up the previous session: %w", err)
	}
	if s.UserID != userID {
		codes, tokens, err := endSession(ctx, d, tenantID, s)
		if err != nil {
			return err
		}
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "another user signed in; signed out the previous user",
			slog.String("tenant_id", tenantID.String()),
			slog.String("user_id", s.UserID.String()),
			slog.String("session_id", s.ID.String()),
			slog.Int64("deleted_authorization_codes", codes),
			slog.Int64("revoked_access_tokens", tokens))
		return nil
	}
	// The session goes first, so no new code comes from it.
	if err := d.Store.Sessions().Delete(ctx, tenantID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("ending the previous session: %w", err)
	}
	if _, err := d.Store.AuthorizationCodes().MoveSession(ctx, tenantID, s.ID, next); err != nil {
		return fmt.Errorf("moving the codes of the previous session: %w", err)
	}
	return nil
}

// PurgeExpired deletes the expired authorization requests, sessions, access
// token records, refresh tokens, refresh token families and email
// verifications of every tenant, and the codes that expired more than
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
	families := purge("refresh tokens", d.Store.RefreshTokens().DeleteExpired, now)
	verifications := purge("email verifications", d.Store.EmailVerifications().DeleteExpired, now)
	if requests+sessions+codes+tokens+families+verifications > 0 {
		d.Logger.LogAttrs(ctx, slog.LevelInfo, "deleted expired records",
			slog.Int64("authorization_requests", requests),
			slog.Int64("sessions", sessions),
			slog.Int64("authorization_codes", codes),
			slog.Int64("access_tokens", tokens),
			slog.Int64("refresh_token_families", families),
			slog.Int64("email_verifications", verifications))
	}
	return errors.Join(errs...)
}
