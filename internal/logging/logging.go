// Package logging builds the structured logger used by the clavis binary.
package logging

import (
	"fmt"
	"io"
	"log/slog"
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
