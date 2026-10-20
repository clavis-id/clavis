package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"strings"
	"time"

	gomail "github.com/wneessen/go-mail"
)

// TLSMode says how an SMTP connection is protected (ADR 0024).
type TLSMode string

const (
	// TLSStartTLS connects in plain text and upgrades the connection with
	// STARTTLS before anything else is sent. The server must offer it. This
	// is the default, on port 587.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit starts TLS as soon as it connects (RFC 8314), on port 465
	// by default.
	TLSImplicit TLSMode = "implicit"
	// TLSNone sends everything in plain text, on port 25 by default. It is
	// accepted only for a loopback host, such as a test server on the same
	// machine, and without credentials.
	TLSNone TLSMode = "none"
)

// DefaultSMTPTimeout bounds each connection when SMTPConfig.Timeout is zero.
const DefaultSMTPTimeout = 30 * time.Second

// SMTPConfig configures an SMTP Sender.
type SMTPConfig struct {
	// Host is the name or address of the SMTP server.
	Host string
	// Port is the TCP port. Zero means 587 for TLSStartTLS, 465 for
	// TLSImplicit and 25 for TLSNone.
	Port int
	// TLS is the TLS mode. Empty means TLSStartTLS.
	TLS TLSMode
	// Username and Password authenticate Clavis, with the strongest
	// mechanism the server offers. Both are empty for a server that needs
	// no authentication.
	Username string
	Password string
	// From is the sender, such as "Clavis <no-reply@example.com>".
	From string
	// Timeout bounds each connection. Zero means DefaultSMTPTimeout.
	Timeout time.Duration
	// TLSConfig, when set, replaces the default TLS configuration, for
	// example to trust a private certificate authority. Clavis still sets
	// the server name and requires TLS 1.2 or later.
	TLSConfig *tls.Config
}

// SMTP sends messages through an SMTP server, one connection per message.
type SMTP struct {
	cfg  SMTPConfig
	from *mail.Address
}

// NewSMTP validates c and returns a Sender for it.
func NewSMTP(c SMTPConfig) (*SMTP, error) {
	if c.TLS == "" {
		c.TLS = TLSStartTLS
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultSMTPTimeout
	}
	if c.Port == 0 {
		c.Port = map[TLSMode]int{TLSStartTLS: 587, TLSImplicit: 465, TLSNone: 25}[c.TLS]
	}
	var errs []error
	if c.Host == "" || strings.ContainsAny(c.Host, " \t\r\n/") {
		errs = append(errs, errors.New("host: required, a host name or an IP address"))
	}
	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Errorf("port: must be between 1 and 65535, got %d", c.Port))
	}
	switch c.TLS {
	case TLSStartTLS, TLSImplicit:
	case TLSNone:
		// ADR 0024: plain text only to this machine, and never with
		// credentials.
		if !loopback(c.Host) {
			errs = append(errs, errors.New("tls: none is allowed only for a loopback host"))
		}
		if c.Username != "" || c.Password != "" {
			errs = append(errs, errors.New("tls: none cannot send credentials"))
		}
	default:
		errs = append(errs, fmt.Errorf("tls: must be starttls, implicit or none, got %q", c.TLS))
	}
	if (c.Username == "") != (c.Password == "") {
		errs = append(errs, errors.New("username and password: set both or neither"))
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil || strings.ContainsAny(c.From, "\r\n") {
		errs = append(errs, errors.New("from: must be an email address, optionally with a display name"))
	}
	if c.Timeout < 0 {
		errs = append(errs, fmt.Errorf("timeout: must not be negative, got %s", c.Timeout))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("email: invalid SMTP configuration: %w", err)
	}
	if c.TLSConfig != nil {
		c.TLSConfig = c.TLSConfig.Clone()
	} else {
		c.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c.TLSConfig.ServerName = c.Host
	c.TLSConfig.MinVersion = max(c.TLSConfig.MinVersion, tls.VersionTLS12)
	return &SMTP{cfg: c, from: from}, nil
}

// loopback reports whether host names this machine.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

// Send delivers m. A permanent refusal by the server wraps ErrRejected.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	msg := gomail.NewMsg(gomail.WithNoDefaultUserAgent())
	if err := msg.FromFormat(s.from.Name, s.from.Address); err != nil {
		return fmt.Errorf("email: setting the sender: %w", err)
	}
	if err := msg.To(m.To); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	msg.Subject(m.Subject)
	msg.SetBodyString(gomail.TypeTextPlain, m.Text)
	if m.HTML != "" {
		msg.AddAlternativeString(gomail.TypeTextHTML, m.HTML)
	}

	// go-mail stops watching ctx once it has connected, and leaves the
	// connection open when the greeting or the TLS upgrade fails. Clavis
	// dials itself and closes the connection when Send returns or ctx ends.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dial := func(dialCtx context.Context, network, address string) (net.Conn, error) {
		var conn net.Conn
		var err error
		dialer := &net.Dialer{}
		if s.cfg.TLS == TLSImplicit {
			conn, err = (&tls.Dialer{NetDialer: dialer, Config: s.cfg.TLSConfig}).DialContext(dialCtx, network, address)
		} else {
			conn, err = dialer.DialContext(dialCtx, network, address)
		}
		if err != nil {
			return nil, fmt.Errorf("connecting to %s: %w", address, err)
		}
		context.AfterFunc(ctx, func() { _ = conn.Close() })
		return conn, nil
	}
	opts := []gomail.Option{
		gomail.WithPort(s.cfg.Port),
		gomail.WithTimeout(s.cfg.Timeout),
		gomail.WithTLSConfig(s.cfg.TLSConfig),
		gomail.WithDialContextFunc(dial),
	}
	switch s.cfg.TLS {
	case TLSImplicit:
		// The connection is TLS from the start. With this policy go-mail
		// sees it as encrypted, which authentication needs, without asking
		// for STARTTLS.
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSOpportunistic))
	case TLSNone:
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	default:
		// The connection fails rather than continue without TLS.
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	}
	if s.cfg.Username != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
			gomail.WithUsername(s.cfg.Username), gomail.WithPassword(s.cfg.Password))
	}
	client, err := gomail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("email: preparing the SMTP client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		var sendErr *gomail.SendError
		if errors.As(err, &sendErr) && !sendErr.IsTemp() {
			return fmt.Errorf("%w: %w", ErrRejected, err)
		}
		return fmt.Errorf("email: sending through %s: %w", s.cfg.Host, err)
	}
	return nil
}
