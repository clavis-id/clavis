package cli

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestEmailTest(t *testing.T) {
	t.Parallel()
	run := func(environ []string, args ...string) (code int, stdout, stderr string) {
		var out, errOut bytes.Buffer
		code = Execute(t.Context(), append([]string{"email", "test"}, args...), nil, &out, &errOut, environ)
		return code, out.String(), errOut.String()
	}

	// The console driver writes the message to the log, without needing the
	// database or the key encryption key.
	code, stdout, stderr := run([]string{"CLAVIS_EMAIL_DRIVER=console", "CLAVIS_ISSUER=https://auth.example.com"},
		"--to", "ops@example.com")
	if code != 0 || !strings.Contains(stdout, "console driver sends nothing") ||
		!strings.Contains(stderr, "Clavis test message") || !strings.Contains(stderr, "https://auth.example.com") {
		t.Errorf("email test with the console driver = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The message exists in every locale.
	code, _, stderr = run([]string{"CLAVIS_EMAIL_DRIVER=console", "CLAVIS_ISSUER=https://auth.example.com"},
		"--to", "ops@example.com", "--locale", "es")
	if code != 0 || !strings.Contains(stderr, "Mensaje de prueba de Clavis") {
		t.Errorf("email test in Spanish = %d\nstderr: %s", code, stderr)
	}

	// A server that refuses the connection.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if err := ln.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}
	smtp := []string{"CLAVIS_EMAIL_DRIVER=smtp", "CLAVIS_EMAIL_FROM=no-reply@example.com",
		"CLAVIS_EMAIL_SMTP_HOST=127.0.0.1", "CLAVIS_EMAIL_SMTP_PORT=" + port, "CLAVIS_EMAIL_SMTP_TLS=none"}

	for name, tt := range map[string]struct {
		environ []string
		args    []string
		want    string
	}{
		"email disabled":       {nil, []string{"--to", "ops@example.com"}, "email is disabled"},
		"no recipient":         {[]string{"CLAVIS_EMAIL_DRIVER=console"}, nil, `"to" not set`},
		"invalid recipient":    {[]string{"CLAVIS_EMAIL_DRIVER=console"}, []string{"--to", "ops"}, "--to:"},
		"invalid email config": {[]string{"CLAVIS_EMAIL_DRIVER=smtp"}, []string{"--to", "ops@example.com"}, "email.smtp.host"},
		"delivery failure":     {smtp, []string{"--to", "ops@example.com"}, "sending the test message"},
		"unsupported locale": {[]string{"CLAVIS_EMAIL_DRIVER=console"}, []string{"--to", "ops@example.com", "--locale", "fr"},
			"--locale \"fr\": want one of en, es"},
	} {
		code, _, stderr := run(tt.environ, tt.args...)
		if code != 1 || !strings.Contains(stderr, tt.want) {
			t.Errorf("%s: email test = %d, stderr %q; want it to mention %q", name, code, stderr, tt.want)
		}
	}
}
