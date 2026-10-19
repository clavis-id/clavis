package logging

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestNewJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, "info", "json")
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	logger.LogAttrs(context.Background(), -4, "hidden debug record")
	logger.LogAttrs(context.Background(), 0, "server started")

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("output is not a single JSON record: %v\n%s", err, buf.String())
	}
	if record["msg"] != "server started" || record["level"] != "INFO" {
		t.Errorf("unexpected record: %v", record)
	}
}

func TestNewText(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := New(&buf, "debug", "text")
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	logger.LogAttrs(context.Background(), -4, "debug record")
	if !strings.Contains(buf.String(), "level=DEBUG") {
		t.Errorf("text output %q does not contain a debug record", buf.String())
	}
}

func TestNewRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := New(&bytes.Buffer{}, "verbose", "json"); err == nil {
		t.Error("New() accepted an invalid level")
	}
	if _, err := New(&bytes.Buffer{}, "info", "xml"); err == nil {
		t.Error("New() accepted an invalid format")
	}
}

func TestSingleLine(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"":                     "",
		"plain":                "plain",
		"a\nb":                 "a b",
		"a\r\nlevel=ERROR msg": "a  level=ERROR msg",
	} {
		if got := SingleLine(in); got != want {
			t.Errorf("SingleLine(%q) = %q, want %q", in, got, want)
		}
	}
}
