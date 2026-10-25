package ratelimit

import (
	"sync"
	"testing"
	"time"
)

var start = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func mustNew(t *testing.T, burst int, interval time.Duration, maxKeys int) *Limiter[string] {
	t.Helper()
	l, err := New[string](burst, interval, maxKeys)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	return l
}

func TestNewRejectsInvalidLimits(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		burst    int
		interval time.Duration
		maxKeys  int
	}{
		{0, time.Second, 1},
		{1, 0, 1},
		{1, -time.Second, 1},
		{1, time.Second, 0},
	} {
		if _, err := New[string](tt.burst, tt.interval, tt.maxKeys); err == nil {
			t.Errorf("New(%d, %v, %d) succeeded, want an error", tt.burst, tt.interval, tt.maxKeys)
		}
	}
}

// A key gets a burst at once, then one event every interval.
func TestBurstThenSteadyRate(t *testing.T) {
	t.Parallel()
	l := mustNew(t, 3, time.Minute, 10)
	for i := range 3 {
		if wait := l.Allow("a", start); wait != 0 {
			t.Fatalf("event %d of the burst waits %v, want none", i+1, wait)
		}
	}
	if wait := l.Allow("a", start); wait != time.Minute {
		t.Fatalf("an event after the burst waits %v, want 1m", wait)
	}
	if wait := l.Allow("a", start.Add(20*time.Second)); wait != 40*time.Second {
		t.Errorf("an event 20s later waits %v, want 40s", wait)
	}
	at := start.Add(time.Minute)
	if wait := l.Allow("a", at); wait != 0 {
		t.Fatalf("an event an interval later waits %v, want none", wait)
	}
	if wait := l.Allow("a", at); wait != time.Minute {
		t.Errorf("a second event an interval later waits %v, want 1m", wait)
	}
	// After a pause the whole burst is back.
	at = at.Add(3 * time.Minute)
	for i := range 3 {
		if wait := l.Allow("a", at); wait != 0 {
			t.Fatalf("event %d after a pause waits %v, want none", i+1, wait)
		}
	}
}

// Wait counts nothing, Add counts whether or not the event is allowed, and
// keys are separate.
func TestWaitAndAdd(t *testing.T) {
	t.Parallel()
	l := mustNew(t, 2, time.Minute, 10)
	for range 5 {
		if wait := l.Wait("a", start); wait != 0 {
			t.Fatalf("Wait() of a new key = %v, want none", wait)
		}
	}
	l.Add("a", start)
	l.Add("a", start)
	if wait := l.Wait("a", start); wait != time.Minute {
		t.Errorf("Wait() after a burst = %v, want 1m", wait)
	}
	l.Add("a", start)
	if wait := l.Wait("a", start); wait != 2*time.Minute {
		t.Errorf("Wait() after an event beyond the burst = %v, want 2m", wait)
	}
	if wait := l.Wait("b", start); wait != 0 {
		t.Errorf("Wait() of another key = %v, want none", wait)
	}
}

// Keys whose burst is whole again are forgotten; beyond maxKeys, new keys
// are not limited until room is made.
func TestKeysAreBounded(t *testing.T) {
	t.Parallel()
	l := mustNew(t, 1, time.Minute, 2)
	l.Add("a", start)
	l.Add("b", start)
	l.Add("c", start)
	if wait := l.Wait("c", start); wait != 0 {
		t.Errorf("a key beyond the bound waits %v, want it not limited", wait)
	}
	if wait := l.Wait("a", start); wait != time.Minute {
		t.Errorf("a key within the bound waits %v, want 1m", wait)
	}
	// Once the burst of a and b is whole, they make room for c.
	at := start.Add(time.Minute)
	l.Add("c", at)
	if wait := l.Wait("c", at); wait != time.Minute {
		t.Errorf("a key after the sweep waits %v, want 1m", wait)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.whole) != 1 {
		t.Errorf("the limiter holds %d keys, want 1", len(l.whole))
	}
}

// Concurrent events of one key get exactly the burst.
func TestConcurrentEvents(t *testing.T) {
	t.Parallel()
	const burst, n = 5, 50
	l := mustNew(t, burst, time.Hour, 10)
	allowed := make(chan bool, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { allowed <- l.Allow("a", start) == 0 })
	}
	wg.Wait()
	close(allowed)
	count := 0
	for ok := range allowed {
		if ok {
			count++
		}
	}
	if count != burst {
		t.Errorf("%d concurrent events allowed, want %d", count, burst)
	}
}
