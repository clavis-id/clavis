package email

import (
	"context"
	"log/slog"

	"clavisid.org/clavis/internal/logging"
)

// Console writes messages to a logger instead of sending them. It is for
// development only: messages carry verification codes and password reset
// links, which then appear in the log (ADR 0024).
type Console struct {
	logger *slog.Logger
}

// NewConsole returns a Sender that writes every message to logger.
func NewConsole(logger *slog.Logger) *Console {
	return &Console{logger: logger}
}

// Send writes m to the log at the warning level, each value on one line.
func (c *Console) Send(ctx context.Context, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	c.logger.LogAttrs(ctx, slog.LevelWarn, "email not sent: the console driver writes it to the log instead",
		slog.String("to", logging.SingleLine(m.To)),
		slog.String("subject", logging.SingleLine(m.Subject)),
		slog.String("text", logging.SingleLine(m.Text)))
	return nil
}
