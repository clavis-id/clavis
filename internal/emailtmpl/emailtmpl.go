// Package emailtmpl renders the email messages that Clavis sends, as plain
// text with an HTML alternative (ADR 0024). Run make generate after editing
// a .templ file.
package emailtmpl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"clavisid.org/clavis/email"
)

// Content is a message to a user before it is rendered.
type Content struct {
	// Subject is the subject line.
	Subject string
	// Paragraphs are the body, in order.
	Paragraphs []string
	// Code is a one-time code for the user to type, shown on its own line,
	// or empty.
	Code string
	// LinkURL is an absolute https or http URL for the user to follow, with
	// LinkText as its label, or empty.
	LinkURL  string
	LinkText string
	// Footer says why the user receives the message, or is empty.
	Footer string
}

// Render returns the message with content c for the recipient to.
func Render(ctx context.Context, to string, c Content) (email.Message, error) {
	if err := c.validate(); err != nil {
		return email.Message{}, err
	}
	var html bytes.Buffer
	//nolint:contextcheck // A templ component takes the context in Render.
	if err := page(c).Render(ctx, &html); err != nil {
		return email.Message{}, fmt.Errorf("emailtmpl: rendering the HTML body: %w", err)
	}
	m := email.Message{To: to, Subject: c.Subject, Text: c.text(), HTML: html.String()}
	if err := m.Validate(); err != nil {
		return email.Message{}, err
	}
	return m, nil
}

func (c Content) validate() error {
	switch {
	case c.Subject == "" || strings.ContainsAny(c.Subject, "\r\n"):
		return errors.New("emailtmpl: the subject must be one line")
	case len(c.Paragraphs) == 0:
		return errors.New("emailtmpl: the message needs a paragraph")
	case (c.LinkURL == "") != (c.LinkText == ""):
		return errors.New("emailtmpl: a link needs both a URL and a label")
	}
	if c.LinkURL != "" {
		u, err := url.Parse(c.LinkURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("emailtmpl: the link must be an absolute https or http URL")
		}
	}
	return nil
}

// text returns the plain text body: the paragraphs, the code and the link,
// each separated by a blank line, then the footer.
func (c Content) text() string {
	parts := append([]string(nil), c.Paragraphs...)
	if c.Code != "" {
		parts = append(parts, "    "+c.Code)
	}
	if c.LinkURL != "" {
		parts = append(parts, c.LinkText+":\n"+c.LinkURL)
	}
	if c.Footer != "" {
		parts = append(parts, "--\n"+c.Footer)
	}
	return strings.Join(parts, "\n\n") + "\n"
}

// TestMessage returns the content of the message that `clavis email test`
// sends, which shows that the configuration delivers email.
func TestMessage(issuer string) Content {
	return Content{
		Subject: "Clavis test message",
		Paragraphs: []string{
			"This message confirms that Clavis can send email.",
			"Issuer: " + issuer,
		},
		Footer: "You received this message because an operator ran clavis email test.",
	}
}
