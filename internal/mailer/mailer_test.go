package mailer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"clavisid.org/clavis/email"
)

// fakeSender fails each message with the errors in fail, in order, and then
// accepts it. With block set, Send waits until its context ends.
type fakeSender struct {
	mu    sync.Mutex
	fail  []error
	block bool
	tries int
	sent  []email.Message
}

func (s *fakeSender) Send(ctx context.Context, m email.Message) error {
	s.mu.Lock()
	s.tries++
	if s.block {
		s.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	defer s.mu.Unlock()
	if len(s.fail) > 0 {
		err := s.fail[0]
		s.fail = s.fail[1:]
		return err
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *fakeSender) state() (tries int, sent []email.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tries, append([]email.Message(nil), s.sent...)
}

func message() email.Message {
	return email.Message{To: "ada@example.com", Subject: "Your code", Text: "Your code is 123456."}
}

// run starts m in a bubble and returns a function that stops it.
func run(t *testing.T, m *Mailer) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

func TestMailerRetriesTemporaryFailures(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		sender := &fakeSender{fail: []error{errors.New("connection refused"), errors.New("451 try later")}}
		m := New(sender, slog.New(slog.NewTextHandler(&logs, nil)))
		stop := run(t, m)
		defer stop()
		if err := m.Enqueue(t.Context(), message()); err != nil {
			t.Fatalf("Enqueue() unexpected error: %v", err)
		}
		synctest.Wait()
		if tries, sent := sender.state(); tries != 1 || len(sent) != 0 {
			t.Fatalf("after the first attempt: %d tries, %d sent", tries, len(sent))
		}
		time.Sleep(retryDelays[0])
		synctest.Wait()
		time.Sleep(retryDelays[1])
		synctest.Wait()
		if tries, sent := sender.state(); tries != 3 || len(sent) != 1 || sent[0] != message() {
			t.Errorf("after the retries: %d tries, sent %+v", tries, sent)
		}
		if strings.Count(logs.String(), "retrying") != 2 || strings.Contains(logs.String(), "123456") {
			t.Errorf("logs:\n%s", logs.String())
		}
	})
}

func TestMailerGivesUp(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		fail  []error
		tries int
	}{
		"rejected":         {[]error{email.ErrRejected}, 1},
		"invalid":          {[]error{email.ErrInvalidMessage}, 1},
		"three failures":   {[]error{errors.New("a"), errors.New("b"), errors.New("c")}, 3},
		"wrapped rejected": {[]error{errors.Join(errors.New("550 no such user"), email.ErrRejected)}, 1},
	} {
		synctest.Test(t, func(t *testing.T) {
			var logs bytes.Buffer
			sender := &fakeSender{fail: tt.fail}
			m := New(sender, slog.New(slog.NewTextHandler(&logs, nil)))
			stop := run(t, m)
			defer stop()
			if err := m.Enqueue(t.Context(), message()); err != nil {
				t.Fatalf("%s: Enqueue() unexpected error: %v", name, err)
			}
			time.Sleep(time.Hour)
			synctest.Wait()
			if tries, sent := sender.state(); tries != tt.tries || len(sent) != 0 {
				t.Errorf("%s: %d tries, %d sent; want %d tries", name, tries, len(sent), tt.tries)
			}
			if !strings.Contains(logs.String(), "email not delivered") {
				t.Errorf("%s: logs:\n%s", name, logs.String())
			}
		})
	}
}

func TestMailerBoundsEachAttempt(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		sender := &fakeSender{block: true}
		m := New(sender, slog.New(slog.DiscardHandler))
		stop := run(t, m)
		defer stop()
		if err := m.Enqueue(t.Context(), message()); err != nil {
			t.Fatalf("Enqueue() unexpected error: %v", err)
		}
		time.Sleep(AttemptTimeout)
		synctest.Wait()
		if tries, _ := sender.state(); tries != 1 {
			t.Fatalf("after one attempt timeout: %d tries", tries)
		}
		time.Sleep(retryDelays[0])
		synctest.Wait()
		if tries, _ := sender.state(); tries != 2 {
			t.Errorf("a timed out attempt is retried: %d tries, want 2", tries)
		}
	})
}

func TestEnqueue(t *testing.T) {
	t.Parallel()
	m := New(&fakeSender{}, slog.New(slog.DiscardHandler))
	if err := m.Enqueue(t.Context(), email.Message{To: "not an address", Text: "x"}); !errors.Is(err,
		email.ErrInvalidMessage) {
		t.Errorf("Enqueue() of an invalid message = %v, want ErrInvalidMessage", err)
	}
	// Without Run, the queue fills up.
	for i := range QueueSize {
		if err := m.Enqueue(t.Context(), message()); err != nil {
			t.Fatalf("Enqueue() %d unexpected error: %v", i, err)
		}
	}
	if err := m.Enqueue(t.Context(), message()); !errors.Is(err, ErrQueueFull) {
		t.Errorf("Enqueue() on a full queue = %v, want ErrQueueFull", err)
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		sender := &fakeSender{block: true}
		m := New(sender, slog.New(slog.NewTextHandler(&logs, nil)))
		stop := run(t, m)
		for range 3 {
			if err := m.Enqueue(t.Context(), message()); err != nil {
				t.Fatalf("Enqueue() unexpected error: %v", err)
			}
		}
		synctest.Wait()
		// Both workers are busy; one message waits. Stopping cancels the
		// attempts and reports the message left behind.
		stop()
		if tries, _ := sender.state(); tries != Workers {
			t.Errorf("%d tries before stopping, want %d", tries, Workers)
		}
		if !strings.Contains(logs.String(), "messages=1") {
			t.Errorf("logs:\n%s", logs.String())
		}
	})
}
