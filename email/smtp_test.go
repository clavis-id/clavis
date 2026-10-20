package email

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCertificate returns a self-signed certificate for 127.0.0.1 and the
// pool that trusts it.
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// received is a message that the fake server accepted.
type received struct {
	from, to, data, auth string
	tls                  bool
}

// fakeSMTP is an SMTP server on 127.0.0.1 that speaks enough of RFC 5321
// for the tests: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA, RSET, NOOP
// and QUIT.
type fakeSMTP struct {
	cert     tls.Certificate
	implicit bool   // TLS from the first byte
	startTLS bool   // offers STARTTLS
	user     string // offers and requires AUTH PLAIN when set
	password string
	rcptCode string // replies to RCPT with this, such as "550 5.1.1 no such user"

	mu  sync.Mutex
	got []received
}

// start serves s on a free port until the test ends, and returns the port.
func (s *fakeSMTP) start(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { s.serve(conn) })
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func (s *fakeSMTP) messages() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.got...)
}

func (s *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	secure := false
	if s.implicit {
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
		secure = true
	}
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	reply := func(lines ...string) {
		for _, l := range lines {
			_, _ = w.WriteString(l + "\r\n")
		}
		_ = w.Flush()
	}
	reply("220 127.0.0.1 fake ESMTP")
	var msg received
	authenticated := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			ext := []string{"250-127.0.0.1", "250-8BITMIME"}
			if s.startTLS && !secure {
				ext = append(ext, "250-STARTTLS")
			}
			if s.user != "" {
				ext = append(ext, "250-AUTH PLAIN")
			}
			ext = append(ext, "250 SMTPUTF8")
			reply(ext...)
		case "STARTTLS":
			reply("220 2.0.0 ready")
			conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			r, w = bufio.NewReader(conn), bufio.NewWriter(conn)
			secure = true
		case "AUTH":
			mech, resp, _ := strings.Cut(arg, " ")
			if !strings.EqualFold(mech, "PLAIN") {
				reply("504 5.5.4 unsupported")
				continue
			}
			if resp == "" {
				reply("334 ")
				if resp, err = r.ReadString('\n'); err != nil {
					return
				}
				resp = strings.TrimRight(resp, "\r\n")
			}
			creds, _ := base64.StdEncoding.DecodeString(resp)
			if string(creds) != "\x00"+s.user+"\x00"+s.password {
				reply("535 5.7.8 authentication failed")
				continue
			}
			authenticated, msg.auth = true, string(creds)
			reply("235 2.7.0 authenticated")
		case "MAIL":
			if s.user != "" && !authenticated {
				reply("530 5.7.0 authentication required")
				continue
			}
			msg.from = arg
			reply("250 2.1.0 ok")
		case "RCPT":
			if s.rcptCode != "" {
				reply(s.rcptCode)
				continue
			}
			msg.to = arg
			reply("250 2.1.5 ok")
		case "DATA":
			reply("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			msg.data, msg.tls = b.String(), secure
			s.mu.Lock()
			s.got = append(s.got, msg)
			s.mu.Unlock()
			msg = received{auth: msg.auth}
			reply("250 2.0.0 queued")
		case "RSET", "NOOP":
			reply("250 2.0.0 ok")
		case "QUIT":
			reply("221 2.0.0 bye")
			return
		default:
			reply("502 5.5.2 unknown command")
		}
	}
}

func testMessage() Message {
	return Message{To: "ada@example.com", Subject: "Your code", Text: "Your code is 123456.",
		HTML: "<p>Your code is <b>123456</b>.</p>"}
}

func TestSMTPSendsWithSTARTTLSAndAuthentication(t *testing.T) {
	t.Parallel()
	cert, pool := testCertificate(t)
	srv := &fakeSMTP{cert: cert, startTLS: true, user: "clavis", password: "s3cret"}
	port := srv.start(t)
	s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: port, Username: "clavis", Password: "s3cret",
		From: "Clavis <no-reply@example.com>", TLSConfig: &tls.Config{RootCAs: pool}})
	if err != nil {
		t.Fatalf("NewSMTP() unexpected error: %v", err)
	}
	if err := s.Send(t.Context(), testMessage()); err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}
	got := srv.messages()
	if len(got) != 1 {
		t.Fatalf("the server received %d messages, want 1", len(got))
	}
	m := got[0]
	if !m.tls || m.auth != "\x00clavis\x00s3cret" || !strings.Contains(m.from, "<no-reply@example.com>") ||
		!strings.Contains(m.to, "<ada@example.com>") {
		t.Errorf("received %+v, want a message over TLS after authentication", m)
	}
	for _, want := range []string{"Subject: Your code", `From: "Clavis" <no-reply@example.com>`,
		"To: <ada@example.com>", "multipart/alternative", "text/plain", "text/html", "Your code is 123456."} {
		if !strings.Contains(m.data, want) {
			t.Errorf("the message does not contain %q:\n%s", want, m.data)
		}
	}
	if strings.Contains(m.data, "go-mail") {
		t.Errorf("the message names the mail library:\n%s", m.data)
	}
}

func TestSMTPSendsWithImplicitTLS(t *testing.T) {
	t.Parallel()
	cert, pool := testCertificate(t)
	srv := &fakeSMTP{cert: cert, implicit: true, user: "clavis", password: "s3cret"}
	port := srv.start(t)
	s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: port, TLS: TLSImplicit, From: "no-reply@example.com",
		Username: "clavis", Password: "s3cret", TLSConfig: &tls.Config{RootCAs: pool}})
	if err != nil {
		t.Fatalf("NewSMTP() unexpected error: %v", err)
	}
	if err := s.Send(t.Context(), testMessage()); err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}
	// PLAIN authentication needs a connection that go-mail sees as encrypted.
	if got := srv.messages(); len(got) != 1 || !got[0].tls || got[0].auth != "\x00clavis\x00s3cret" {
		t.Errorf("received %+v, want one authenticated message over TLS", got)
	}
}

func TestSMTPSendsInPlainTextToALoopbackHost(t *testing.T) {
	t.Parallel()
	srv := &fakeSMTP{}
	port := srv.start(t)
	s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: port, TLS: TLSNone, From: "no-reply@example.com"})
	if err != nil {
		t.Fatalf("NewSMTP() unexpected error: %v", err)
	}
	if err := s.Send(t.Context(), Message{To: "ada@example.com", Text: "plain"}); err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}
	if got := srv.messages(); len(got) != 1 || got[0].tls {
		t.Errorf("received %+v, want one message in plain text", got)
	}
}

// ADR 0024: STARTTLS is mandatory; a server that does not offer it, or a
// certificate that does not verify, ends the connection before anything is
// sent.
func TestSMTPRequiresTLS(t *testing.T) {
	t.Parallel()
	cert, _ := testCertificate(t)
	for name, tt := range map[string]struct {
		srv *fakeSMTP
		cfg SMTPConfig
	}{
		"no STARTTLS offered": {&fakeSMTP{cert: cert}, SMTPConfig{}},
		"untrusted certificate": {&fakeSMTP{cert: cert, startTLS: true, user: "clavis", password: "s3cret"},
			SMTPConfig{Username: "clavis", Password: "s3cret"}},
	} {
		port := tt.srv.start(t)
		cfg := tt.cfg
		cfg.Host, cfg.Port, cfg.From = "127.0.0.1", port, "no-reply@example.com"
		s, err := NewSMTP(cfg)
		if err != nil {
			t.Fatalf("%s: NewSMTP() unexpected error: %v", name, err)
		}
		if err := s.Send(t.Context(), testMessage()); err == nil {
			t.Errorf("%s: Send() succeeded, want an error", name)
		}
		if got := tt.srv.messages(); len(got) != 0 {
			t.Errorf("%s: the server received %+v", name, got)
		}
	}
}

func TestSMTPReportsRejections(t *testing.T) {
	t.Parallel()
	for code, permanent := range map[string]bool{
		"550 5.1.1 no such user":        true,
		"451 4.3.0 try again later":     false,
		"452 4.2.2 mailbox temporarily": false,
	} {
		srv := &fakeSMTP{rcptCode: code}
		port := srv.start(t)
		s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: port, TLS: TLSNone, From: "no-reply@example.com"})
		if err != nil {
			t.Fatalf("NewSMTP() unexpected error: %v", err)
		}
		err = s.Send(t.Context(), testMessage())
		if err == nil || errors.Is(err, ErrRejected) != permanent {
			t.Errorf("Send() after RCPT %q = %v, want rejected %v", code, err, permanent)
		}
	}
}

func TestSMTPStopsWhenTheContextEnds(t *testing.T) {
	t.Parallel()
	// A server that accepts the connection and never answers.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()
	go func() {
		if conn, err := ln.Accept(); err == nil {
			defer conn.Close()
			_, _ = conn.Read(make([]byte, 1))
		}
	}()
	s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, TLS: TLSNone,
		From: "no-reply@example.com"})
	if err != nil {
		t.Fatalf("NewSMTP() unexpected error: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Send(ctx, testMessage()); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("Send() = %v after %v, want an error soon after the context ends", err, time.Since(start))
	}
}

func TestNewSMTPValidates(t *testing.T) {
	t.Parallel()
	valid := SMTPConfig{Host: "smtp.example.com", From: "no-reply@example.com"}
	s, err := NewSMTP(valid)
	if err != nil {
		t.Fatalf("NewSMTP() unexpected error: %v", err)
	}
	if s.cfg.Port != 587 || s.cfg.TLS != TLSStartTLS || s.cfg.Timeout != DefaultSMTPTimeout ||
		s.cfg.TLSConfig.ServerName != "smtp.example.com" || s.cfg.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("defaults = %+v", s.cfg)
	}
	for mode, port := range map[TLSMode]int{TLSImplicit: 465, TLSNone: 25} {
		c := valid
		c.Host, c.TLS = "localhost", mode
		if s, err := NewSMTP(c); err != nil || s.cfg.Port != port {
			t.Errorf("NewSMTP() with %s = %v; want port %d", mode, err, port)
		}
	}
	// A caller's TLS configuration is copied, never changed.
	own := &tls.Config{MinVersion: tls.VersionTLS13}
	c := valid
	c.TLSConfig = own
	if s, err := NewSMTP(c); err != nil || s.cfg.TLSConfig == own || s.cfg.TLSConfig.MinVersion != tls.VersionTLS13 ||
		own.ServerName != "" {
		t.Errorf("NewSMTP() with a TLS configuration = %v, %+v", err, own)
	}

	for name, edit := range map[string]func(*SMTPConfig){
		"no host":                func(c *SMTPConfig) { c.Host = "" },
		"host with a space":      func(c *SMTPConfig) { c.Host = "smtp example.com" },
		"port out of range":      func(c *SMTPConfig) { c.Port = 70000 },
		"unknown TLS mode":       func(c *SMTPConfig) { c.TLS = "ssl" },
		"plain text to a remote": func(c *SMTPConfig) { c.TLS = TLSNone },
		"plain text with credentials": func(c *SMTPConfig) {
			c.Host, c.TLS, c.Username, c.Password = "127.0.0.1", TLSNone, "u", "p"
		},
		"username without password": func(c *SMTPConfig) { c.Username = "u" },
		"no sender":                 func(c *SMTPConfig) { c.From = "" },
		"sender with a line break":  func(c *SMTPConfig) { c.From = "a@example.com\r\nBcc: b@example.com" },
		"negative timeout":          func(c *SMTPConfig) { c.Timeout = -time.Second },
	} {
		c := valid
		edit(&c)
		if _, err := NewSMTP(c); err == nil {
			t.Errorf("%s: NewSMTP() succeeded, want an error", name)
		}
	}
}

func TestLoopback(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"localhost": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true, "[::1]": true,
		"localhost.example.com": false, "10.0.0.1": false, "smtp.example.com": false, "": false,
	} {
		if got := loopback(host); got != want {
			t.Errorf("loopback(%q) = %v, want %v", host, got, want)
		}
	}
}
