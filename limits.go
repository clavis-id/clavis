package clavis

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"clavisid.org/clavis/internal/i18n"
	"clavisid.org/clavis/internal/ratelimit"
)

// clientLimit is a limit per client address: burst events at once, then
// one every interval.
type clientLimit struct {
	burst    int
	interval time.Duration
}

// Limits per client address, kept in the memory of each instance (ADR
// 0030). They count what an attacker produces, wrong guesses and messages,
// so that the clients behind one address, such as the people of an office,
// rarely meet them.
var (
	// passwordLimit counts wrong passwords: sign-ins for authorization
	// requests and the account pages, and the current password of a
	// password change.
	passwordLimit = clientLimit{burst: 20, interval: time.Minute}
	// codeLimit counts wrong codes of email verifications.
	codeLimit = clientLimit{burst: 10, interval: time.Minute}
	// messageLimit counts the messages of signup and password reset.
	messageLimit = clientLimit{burst: 10, interval: 2 * time.Minute}
	// tokenLimit counts failed client authentications at the token,
	// revocation and introspection endpoints, and codes and refresh tokens
	// presented again.
	tokenLimit = clientLimit{burst: 60, interval: time.Second}
)

// maxLimitedClients bounds the client addresses that each limit holds at a
// time. Beyond it, new addresses are not limited: so many addresses are a
// distributed attack, which the limits per account still bound.
const maxLimitedClients = 1 << 15

// clientKey is the key of a client address in the limits.
type clientKey = [16]byte

// clientLimits holds the limits per client address of a Server.
type clientLimits struct {
	passwords *ratelimit.Limiter[clientKey]
	codes     *ratelimit.Limiter[clientKey]
	messages  *ratelimit.Limiter[clientKey]
	tokens    *ratelimit.Limiter[clientKey]
}

func newClientLimits() (clientLimits, error) {
	var l clientLimits
	for _, c := range []struct {
		limiter **ratelimit.Limiter[clientKey]
		limit   clientLimit
	}{
		{&l.passwords, passwordLimit},
		{&l.codes, codeLimit},
		{&l.messages, messageLimit},
		{&l.tokens, tokenLimit},
	} {
		var err error
		if *c.limiter, err = ratelimit.New[clientKey](c.limit.burst, c.limit.interval, maxLimitedClients); err != nil {
			return clientLimits{}, err
		}
	}
	return l, nil
}

// limitKey returns the key of the client of r in the limits per client
// address, or false when its address is unknown, which no limit holds. An
// IPv6 client counts by its /64 network, which one client usually holds
// whole.
func (s *Server) limitKey(r *http.Request) (clientKey, bool) {
	addr := clientAddr(r, s.proxies)
	if !addr.IsValid() {
		return clientKey{}, false
	}
	if addr.Is6() {
		addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return addr.As16(), true
}

// clientWait returns how long the client of r must wait before l allows
// its next event, or zero.
func (s *Server) clientWait(l *ratelimit.Limiter[clientKey], r *http.Request) time.Duration {
	k, ok := s.limitKey(r)
	if !ok {
		return 0
	}
	return l.Wait(k, s.deps.Now())
}

// countClient counts an event of the client of r in l.
func (s *Server) countClient(l *ratelimit.Limiter[clientKey], r *http.Request) {
	if k, ok := s.limitKey(r); ok {
		l.Add(k, s.deps.Now())
	}
}

// pageLimited answers a request to a hosted page whose client must wait
// before l allows its next event, and reports whether it did.
func (s *Server) pageLimited(w http.ResponseWriter, r *http.Request, t tenant, l *ratelimit.Limiter[clientKey]) bool {
	wait := s.clientWait(l, r)
	if wait == 0 {
		return false
	}
	setRetryAfter(w, wait)
	s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusTooManyRequests, i18n.ErrorTooManyRequestsTitle,
		i18n.ErrorTooManyRequests)
	return true
}

// tokenLimited answers a request to the token, revocation or introspection
// endpoint whose client must wait, and reports whether it did. OAuth 2.0
// defines no error for it: the status is 429 (RFC 6585, section 4) and the
// code temporarily_unavailable, which RFC 6749 defines for the
// authorization endpoint.
func (s *Server) tokenLimited(w http.ResponseWriter, r *http.Request) bool {
	wait := s.clientWait(s.limits.tokens, r)
	if wait == 0 {
		return false
	}
	setRetryAfter(w, wait)
	s.writeNoStoreJSON(w, r, http.StatusTooManyRequests, struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}{"temporarily_unavailable", "too many failed requests; retry later"})
	return true
}

// setRetryAfter tells the client to retry after wait, in whole seconds
// rounded up (RFC 9110, section 10.2.3).
func setRetryAfter(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.FormatInt(int64((wait+time.Second-1)/time.Second), 10))
}
