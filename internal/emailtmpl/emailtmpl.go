// Package emailtmpl renders the email messages that Clavis sends, as plain
// text with an HTML alternative (ADR 0024). Their text comes from the same
// catalogs as the hosted pages (ADR 0025). Run make generate after editing a
// .templ file.
package emailtmpl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"clavisid.org/clavis/email"
	"clavisid.org/clavis/internal/i18n"
)

// Content is a message to a user before it is rendered.
type Content struct {
	// Locale is the language of the text, or empty for i18n.Default.
	Locale i18n.Locale
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

// lang returns the language of c for the HTML lang attribute.
func (c Content) lang() string {
	if c.Locale == "" {
		return string(i18n.Default)
	}
	return string(c.Locale)
}

// TestMessage returns the content, in the locale of t, of the message that
// `clavis email test` sends, which shows that the configuration delivers
// email.
func TestMessage(t i18n.Printer, issuer string) Content {
	return Content{
		Locale:  t.Locale(),
		Subject: t.T(i18n.EmailTestSubject),
		Paragraphs: []string{
			t.T(i18n.EmailTestBody),
			t.T(i18n.EmailTestIssuer, "issuer", issuer),
		},
		Footer: t.T(i18n.EmailTestFooter),
	}
}
