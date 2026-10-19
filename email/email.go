// Package email delivers the messages that Clavis sends to users, such as
// verification codes and password reset links (ADR 0024).
//
// A Sender delivers one message. NewSMTP returns a Sender for an SMTP
// server; embedders can implement Sender for any other provider. NewConsole
// writes messages to a log instead, for development only.
//
// Clavis never sends email while it serves a request: it queues the message
// and returns, and background workers call the Sender, so the time a
// response takes does not reveal whether a message went out.
package email

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// ErrInvalidMessage reports a message that cannot be sent as it is.
var ErrInvalidMessage = errors.New("email: invalid message")

// ErrRejected reports a message that the provider refused for good, for
// example because the recipient does not exist. A Sender wraps it so that
// Clavis does not retry the message.
var ErrRejected = errors.New("email: the message was rejected")

// Message is one email to one recipient.
type Message struct {
	// To is the address of the recipient, such as "ada@example.com".
	To      string
	Subject string
	// Text is the plain text body. It is required.
	Text string
	// HTML is an HTML rendering of Text, or empty.
	HTML string
}

// Validate reports whether m can be sent: To is one address without a
// display name, Subject is a single line, and Text is not empty. Errors wrap
// ErrInvalidMessage.
func (m Message) Validate() error {
	addr, err := mail.ParseAddress(m.To)
	switch {
	case err != nil || addr.Name != "" || addr.Address != m.To:
		return fmt.Errorf("%w: To must be one email address", ErrInvalidMessage)
	case strings.ContainsAny(m.Subject, "\r\n"):
		return fmt.Errorf("%w: Subject must be a single line", ErrInvalidMessage)
	case m.Text == "":
		return fmt.Errorf("%w: Text is required", ErrInvalidMessage)
	}
	return nil
}

// Sender delivers messages. Send returns once the provider has accepted m,
// or with an error; errors that wrap ErrRejected are not retried.
// Implementations must be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, m Message) error
}
