// Package logging builds the structured logger used by the clavis binary.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a logger that writes to w at the given level ("debug",
// "info", "warn" or "error") using the given format ("json" or "text").
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl}

	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("log format: must be json or text, got %q", format)
	}
}

// SingleLine returns s with every carriage return and line feed replaced by
// a space, so a value from outside Clavis cannot start a forged log entry
// (CodeQL go/log-injection). Use it for the rare raw value that a log must
// show.
func SingleLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
}
