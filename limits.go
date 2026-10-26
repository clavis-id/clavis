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
// rarely meet them. An event counts before the work that may produce it, so
// that requests that arrive together cannot exceed a limit, and the work
// refunds it when it does not produce it.
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

// networkFactor multiplies the burst and the rate of a limit for the /48
// network of an IPv6 client. One party can hold a whole /48, such as a
// tunnel broker gives away, and with it 65,536 /64 networks, each of which
// would get the burst of a client; the people of one site share a /48 too,
// so it gets more than one client.
const networkFactor = 5

// maxLimitedClients bounds the client addresses, and the networks, that
// each limit holds at a time. Beyond it, new ones are not limited: so many
// addresses are a distributed attack, which the limits per account still
// bound.
const maxLimitedClients = 1 << 15

// clientKey is the key of a client address, or of a network, in the limits.
type clientKey = [16]byte

// clientLimiter is a limit per client address. An IPv6 client also counts
// against its /48 network.
type clientLimiter struct {
	clients  *ratelimit.Limiter[clientKey]
	networks *ratelimit.Limiter[clientKey]
}

func newClientLimiter(l clientLimit) (*clientLimiter, error) {
	clients, err := ratelimit.New[clientKey](l.burst, l.interval, maxLimitedClients)
	if err != nil {
		return nil, err
	}
	networks, err := ratelimit.New[clientKey](networkFactor*l.burst, l.interval/networkFactor, maxLimitedClients)
	if err != nil {
		return nil, err
	}
	return &clientLimiter{clients: clients, networks: networks}, nil
}

// clientLimits holds the limits per client address of a Server.
type clientLimits struct {
	passwords *clientLimiter
	codes     *clientLimiter
	messages  *clientLimiter
	tokens    *clientLimiter
}

func newClientLimits() (clientLimits, error) {
	var l clientLimits
	for _, c := range []struct {
		limiter **clientLimiter
		limit   clientLimit
	}{
		{&l.passwords, passwordLimit},
		{&l.codes, codeLimit},
		{&l.messages, messageLimit},
		{&l.tokens, tokenLimit},
	} {
		var err error
		if *c.limiter, err = newClientLimiter(c.limit); err != nil {
			return clientLimits{}, err
		}
	}
	return l, nil
}

// limitKeys are the keys of a client in the limits per client address.
type limitKeys struct {
	// client is the address of the client, or the /64 network of an IPv6
	// client, which one client usually holds whole.
	client clientKey
	// network is the /48 network of an IPv6 client, when ipv6 is true.
	network clientKey
	ipv6    bool
}

// limitKeys returns the keys of the client of r in the limits per client
// address, or false when its address is unknown, which no limit holds.
func (s *Server) limitKeys(r *http.Request) (limitKeys, bool) {
	addr := clientAddr(r, s.proxies)
	switch {
	case !addr.IsValid():
		return limitKeys{}, false
	case addr.Is4():
		return limitKeys{client: addr.As16()}, true
	}
	return limitKeys{
		client:  netip.PrefixFrom(addr, 64).Masked().Addr().As16(),
		network: netip.PrefixFrom(addr, 48).Masked().Addr().As16(),
		ipv6:    true,
	}, true
}

// reservation is an event of a client that a limit counted before the
// work that may produce it.
type reservation struct {
	limiter *clientLimiter
	keys    limitKeys
	counted bool
}

// reserve counts an event of the client of r in l, or returns how long the
// client must wait before l allows it.
func (s *Server) reserve(l *clientLimiter, r *http.Request) (reservation, time.Duration) {
	k, ok := s.limitKeys(r)
	if !ok {
		return reservation{}, 0
	}
	now := s.deps.Now()
	if wait := l.clients.Allow(k.client, now); wait > 0 {
		return reservation{}, wait
	}
	if k.ipv6 {
		if wait := l.networks.Allow(k.network, now); wait > 0 {
			l.clients.Refund(k.client, now)
			return reservation{}, wait
		}
	}
	return reservation{limiter: l, keys: k, counted: true}, 0
}

// settle keeps the event of res when the work produced it, and refunds it
// otherwise.
func (s *Server) settle(res reservation, happened bool) {
	if !res.counted || happened {
		return
	}
	now := s.deps.Now()
	res.limiter.clients.Refund(res.keys.client, now)
	if res.keys.ipv6 {
		res.limiter.networks.Refund(res.keys.network, now)
	}
}

// reservePage reserves an event of the client of r in l for the work of a
// hosted page. When the client must wait, it answers the request and
// returns false.
func (s *Server) reservePage(w http.ResponseWriter, r *http.Request, t tenant, l *clientLimiter,
) (reservation, bool) {
	res, wait := s.reserve(l, r)
	if wait > 0 {
		setRetryAfter(w, wait)
		s.errorPage(w, r, t, s.locale(w, r, "", ""), http.StatusTooManyRequests, i18n.ErrorTooManyRequestsTitle,
			i18n.ErrorTooManyRequests)
		return reservation{}, false
	}
	return res, true
}

// reserveTokenRequest reserves an event of the client of r in the limit of
// the token, revocation and introspection endpoints. When the client must
// wait, it answers the request and returns false. OAuth 2.0 defines no error
// for it: the status is 429 (RFC 6585, section 4) and the code
// temporarily_unavailable, which RFC 6749 defines for the authorization
// endpoint.
func (s *Server) reserveTokenRequest(w http.ResponseWriter, r *http.Request) (reservation, bool) {
	res, wait := s.reserve(s.limits.tokens, r)
	if wait > 0 {
		setRetryAfter(w, wait)
		s.writeNoStoreJSON(w, r, http.StatusTooManyRequests, struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}{"temporarily_unavailable", "too many failed requests; retry later"})
		return reservation{}, false
	}
	return res, true
}

// setRetryAfter tells the client to retry after wait, in whole seconds
// rounded up (RFC 9110, section 10.2.3).
func setRetryAfter(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.FormatInt(int64((wait+time.Second-1)/time.Second), 10))
}
