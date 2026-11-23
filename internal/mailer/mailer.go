// Package mailer sends email in the background (ADR 0024).
//
// A request queues a message and returns at once, so the time a response
// takes does not reveal whether a message went out. Workers deliver queued
// messages through an email.Sender and retry temporary failures. Messages
// live only in memory: a restart loses those not sent yet, and their codes
// never reach the store.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"clavisid.org/clavis/email"
)

// Defaults of a Mailer.
const (
	// QueueSize bounds the messages waiting for a worker.
	QueueSize = 256
	// Workers is how many messages are delivered at the same time.
	Workers = 2
	// AttemptTimeout bounds one delivery attempt, whatever the Sender does.
	AttemptTimeout = time.Minute
)

// retryDelays are the waits before the second and third attempts. A message
// that fails three times is dropped.
var retryDelays = []time.Duration{5 * time.Second, 30 * time.Second}

// ErrQueueFull reports a message dropped because the queue is full.
var ErrQueueFull = errors.New("mailer: the queue is full")

// Mailer queues messages and delivers them in the background. It is safe for
// concurrent use.
type Mailer struct {
	sender  email.Sender
	logger  *slog.Logger
	queue   chan email.Message
	workers int
}

// New returns a Mailer that delivers through sender. Run starts delivery.
func New(sender email.Sender, logger *slog.Logger) *Mailer {
	return &Mailer{sender: sender, logger: logger, queue: make(chan email.Message, QueueSize), workers: Workers}
}

// Enqueue queues m for delivery and returns at once. It fails for a message
// that cannot be sent, and with ErrQueueFull when the queue is full.
func (m *Mailer) Enqueue(ctx context.Context, msg email.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	select {
	case m.queue <- msg:
		return nil
	default:
		m.logger.LogAttrs(ctx, slog.LevelError, "email dropped: the queue is full",
			slog.Int("queue_size", cap(m.queue)))
		return ErrQueueFull
	}
}

// Run delivers queued messages until ctx is canceled, then waits for its
// workers. Messages still queued are lost.
func (m *Mailer) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range m.workers {
		wg.Go(func() {
			// A stopped Mailer takes no more messages, even when some wait.
			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
				case msg := <-m.queue:
					m.deliver(ctx, msg)
				}
			}
		})
	}
	wg.Wait()
	if n := len(m.queue); n > 0 {
		m.logger.LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn, "email queue stopped; messages not sent",
			slog.Int("messages", n))
	}
}

// deliver sends msg, retrying temporary failures after retryDelays. The log
// never shows the content, which can hold a code.
func (m *Mailer) deliver(ctx context.Context, msg email.Message) {
	for attempt := 1; ; attempt++ {
		err := m.attempt(ctx, msg)
		switch {
		case err == nil:
			m.logger.LogAttrs(ctx, slog.LevelDebug, "email sent", slog.Int("attempts", attempt))
			return
		case ctx.Err() != nil:
			return
		case errors.Is(err, email.ErrRejected), errors.Is(err, email.ErrInvalidMessage),
			attempt > len(retryDelays):
			m.logger.LogAttrs(ctx, slog.LevelError, "email not delivered",
				slog.Int("attempts", attempt), slog.String("error", err.Error()))
			return
		}
		delay := retryDelays[attempt-1]
		m.logger.LogAttrs(ctx, slog.LevelWarn, "email delivery failed; retrying",
			slog.Int("attempt", attempt), slog.Duration("retry_in", delay), slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (m *Mailer) attempt(ctx context.Context, msg email.Message) error {
	ctx, cancel := context.WithTimeout(ctx, AttemptTimeout)
	defer cancel()
	if err := m.sender.Send(ctx, msg); err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	return nil
}
