package emailtmpl

import (
	"errors"
	"strings"
	"testing"

	"clavisid.org/clavis/email"
)

func content() Content {
	return Content{
		Subject:    "Verify your email address",
		Paragraphs: []string{"Enter this code to verify <your> address.", "It expires in 10 minutes."},
		Code:       "123456",
		LinkURL:    "https://auth.example.com/verify?code=abc&x=1",
		LinkText:   "Verify",
		Footer:     "You received this message because someone signed up with this address.",
	}
}

func TestRender(t *testing.T) {
	t.Parallel()
	m, err := Render(t.Context(), "ada@example.com", content())
	if err != nil {
		t.Fatalf("Render() unexpected error: %v", err)
	}
	wantText := "Enter this code to verify <your> address.\n\nIt expires in 10 minutes.\n\n    123456\n\n" +
		"Verify:\nhttps://auth.example.com/verify?code=abc&x=1\n\n" +
		"--\nYou received this message because someone signed up with this address.\n"
	if m.To != "ada@example.com" || m.Subject != "Verify your email address" || m.Text != wantText {
		t.Errorf("Render() = %+v\ntext:\n%s", m, m.Text)
	}
	for _, want := range []string{
		`<html lang="en">`, "<title>Verify your email address</title>", "verify &lt;your&gt; address",
		">123456</p>", `href="https://auth.example.com/verify?code=abc&amp;x=1"`, ">Verify</a>",
	} {
		if !strings.Contains(m.HTML, want) {
			t.Errorf("the HTML body does not contain %q:\n%s", want, m.HTML)
		}
	}
	for _, unwanted := range []string{"<script", "<img", "<your>"} {
		if strings.Contains(m.HTML, unwanted) {
			t.Errorf("the HTML body contains %q:\n%s", unwanted, m.HTML)
		}
	}

	// Only the parts a message has.
	m, err = Render(t.Context(), "ada@example.com", Content{Subject: "Hi", Paragraphs: []string{"Hello."}})
	if err != nil || m.Text != "Hello.\n" || strings.Contains(m.HTML, "<a ") {
		t.Errorf("Render() of a short message = %+v, %v", m, err)
	}
}

func TestRenderRejectsInvalidContent(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(*Content){
		"no subject":             func(c *Content) { c.Subject = "" },
		"subject on two lines":   func(c *Content) { c.Subject = "a\nb" },
		"no paragraph":           func(c *Content) { c.Paragraphs = nil },
		"link without a label":   func(c *Content) { c.LinkText = "" },
		"label without a link":   func(c *Content) { c.LinkURL = "" },
		"javascript link":        func(c *Content) { c.LinkURL = "javascript:alert(1)" },
		"relative link":          func(c *Content) { c.LinkURL = "/verify" },
		"link with a bad syntax": func(c *Content) { c.LinkURL = "https://a b/%zz" },
	} {
		c := content()
		edit(&c)
		if _, err := Render(t.Context(), "ada@example.com", c); err == nil {
			t.Errorf("%s: Render() succeeded, want an error", name)
		}
	}
	if _, err := Render(t.Context(), "not an address", content()); !errors.Is(err, email.ErrInvalidMessage) {
		t.Errorf("Render() for an invalid recipient = %v, want ErrInvalidMessage", err)
	}
}

func TestTestMessage(t *testing.T) {
	t.Parallel()
	m, err := Render(t.Context(), "ops@example.com", TestMessage("https://auth.example.com"))
	if err != nil || m.Subject != "Clavis test message" || !strings.Contains(m.Text, "Issuer: https://auth.example.com") {
		t.Errorf("the test message = %+v, %v", m, err)
	}
}
