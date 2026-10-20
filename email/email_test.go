package email

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestMessageValidate(t *testing.T) {
	t.Parallel()
	if err := testMessage().Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	for name, edit := range map[string]func(*Message){
		"no recipient":                 func(m *Message) { m.To = "" },
		"recipient with a name":        func(m *Message) { m.To = "Ada <ada@example.com>" },
		"two recipients":               func(m *Message) { m.To = "ada@example.com, grace@example.com" },
		"recipient with a line break":  func(m *Message) { m.To = "ada@example.com\r\nBcc: x@example.com" },
		"recipient with spaces around": func(m *Message) { m.To = " ada@example.com" },
		"subject with a line break":    func(m *Message) { m.Subject = "Hi\r\nBcc: x@example.com" },
		"no text":                      func(m *Message) { m.Text = "" },
	} {
		m := testMessage()
		edit(&m)
		if err := m.Validate(); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: Validate() = %v, want ErrInvalidMessage", name, err)
		}
	}
}

func FuzzMessageValidate(f *testing.F) {
	f.Add("ada@example.com", "Your code")
	f.Add("Ada <ada@example.com>", "Hi\r\nBcc: x@example.com")
	f.Fuzz(func(t *testing.T, to, subject string) {
		m := Message{To: to, Subject: subject, Text: "text"}
		if m.Validate() == nil && (strings.ContainsAny(to, "\r\n<>,") || strings.ContainsAny(subject, "\r\n")) {
			t.Fatalf("Validate() accepted To %q and Subject %q", to, subject)
		}
	})
}

func TestConsoleWritesMessagesToTheLog(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	c := NewConsole(slog.New(slog.NewTextHandler(&logs, nil)))
	m := testMessage()
	m.Text = "Your code is 123456.\nlevel=ERROR msg=forged"
	if err := c.Send(t.Context(), m); err != nil {
		t.Fatalf("Send() unexpected error: %v", err)
	}
	out := logs.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "level=WARN") || !strings.Contains(out, "123456") ||
		!strings.Contains(out, "ada@example.com") {
		t.Errorf("the log is not one warning with the message:\n%s", out)
	}
	if err := c.Send(t.Context(), Message{To: "not an address", Text: "x"}); !errors.Is(err, ErrInvalidMessage) {
		t.Errorf("Send() of an invalid message = %v, want ErrInvalidMessage", err)
	}
}
