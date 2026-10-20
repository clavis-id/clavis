package i18n

// Key names a message in the catalogs. Every key has a message in every
// locale with the same placeholders; Load checks it, and a test checks that
// the English catalog defines exactly the keys declared here.
type Key string

// Keys of the hosted pages.
const (
	LoginTitle                Key = "login.title"
	LoginLead                 Key = "login.lead"
	LoginEmail                Key = "login.email"
	LoginPassword             Key = "login.password"
	LoginSubmit               Key = "login.submit"
	LoginInvalidCredentials   Key = "login.invalid_credentials" //nolint:gosec // G101: a message key, not a credential.
	LoginDisabled             Key = "login.disabled"
	ConsentTitle              Key = "consent.title"
	ConsentLead               Key = "consent.lead"
	ConsentAsks               Key = "consent.asks"
	ConsentAllow              Key = "consent.allow"
	ConsentDeny               Key = "consent.deny"
	ScopeOpenID               Key = "scope.openid"
	ScopeProfile              Key = "scope.profile"
	ScopeEmail                Key = "scope.email"
	ScopeAddress              Key = "scope.address"
	ScopePhone                Key = "scope.phone"
	ScopeOfflineAccess        Key = "scope.offline_access"
	ScopeResource             Key = "scope.resource"
	FormPostTitle             Key = "form_post.title"
	FormPostContinue          Key = "form_post.continue"
	LogoutTitle               Key = "logout.title"
	LogoutLead                Key = "logout.lead"
	LogoutAccount             Key = "logout.account"
	LogoutSubmit              Key = "logout.submit"
	LogoutStay                Key = "logout.stay"
	LogoutProblem             Key = "logout.problem"
	SignedOutTitle            Key = "signed_out.title"
	SignedOutClose            Key = "signed_out.close"
	LanguageLabel             Key = "language.label"
	ErrorInvalidSignInTitle   Key = "error.invalid_sign_in.title"
	ErrorMalformedSignIn      Key = "error.malformed_sign_in"
	ErrorRejectedSignIn       Key = "error.rejected_sign_in"
	ErrorMalformedSignInForm  Key = "error.malformed_sign_in_form"
	ErrorExpiredSignInTitle   Key = "error.expired_sign_in.title"
	ErrorExpiredSignIn        Key = "error.expired_sign_in"
	ErrorInvalidConsentTitle  Key = "error.invalid_consent.title"
	ErrorMalformedConsentForm Key = "error.malformed_consent_form"
	ErrorInvalidSignOutTitle  Key = "error.invalid_sign_out.title"
	ErrorMalformedSignOut     Key = "error.malformed_sign_out"
	ErrorMalformedSignOutForm Key = "error.malformed_sign_out_form"
	ErrorBlockedTitle         Key = "error.blocked.title"
	ErrorCrossSiteSignInForm  Key = "error.cross_site_sign_in_form"
	ErrorCrossSiteConsentForm Key = "error.cross_site_consent_form"
	ErrorCrossSiteSignOutForm Key = "error.cross_site_sign_out_form"
	EmailTestSubject          Key = "email.test.subject"
	EmailTestBody             Key = "email.test.body"
	EmailTestIssuer           Key = "email.test.issuer"
	EmailTestFooter           Key = "email.test.footer"
)
