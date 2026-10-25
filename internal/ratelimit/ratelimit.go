// Package ratelimit limits events per key in memory, such as the wrong
// passwords that each client address sends (ADR 0030).
package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// Limiter limits the events of each key to a burst followed by a steady
// rate, with the generic cell rate algorithm: for each key it keeps the time
// at which the burst of the key is whole again. A key whose time has passed
// is like a key never seen, so the Limiter forgets it, and memory holds only
// the keys that are being limited. It holds at most a fixed number of keys;
// beyond them, new keys are not limited.
//
// A Limiter is safe for concurrent use.
type Limiter[K comparable] struct {
	interval time.Duration
	// tolerance is how far the time of a key may be ahead of now for an
	// event to be allowed: burst - 1 intervals.
	tolerance time.Duration
	maxKeys   int

	mu    sync.Mutex
	whole map[K]time.Time
	// sweep is when keys whose time has passed are next removed.
	sweep time.Time
}

// New returns a Limiter that allows burst events of a key at once and one
// more every interval after them, and that holds at most maxKeys keys.
// Every argument must be positive.
func New[K comparable](burst int, interval time.Duration, maxKeys int) (*Limiter[K], error) {
	if burst <= 0 || interval <= 0 || maxKeys <= 0 {
		return nil, fmt.Errorf("ratelimit: invalid limit: burst %d, interval %v, %d keys", burst, interval, maxKeys)
	}
	return &Limiter[K]{
		interval:  interval,
		tolerance: time.Duration(burst-1) * interval,
		maxKeys:   maxKeys,
		whole:     make(map[K]time.Time),
	}, nil
}

// Wait returns how long key must wait after now for its next event to be
// allowed, or zero when it is allowed now. It counts nothing.
func (l *Limiter[K]) Wait(key K, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.wait(key, now)
}

// Add counts an event of key at now, whether or not it is allowed.
func (l *Limiter[K]) Add(key K, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.add(key, now)
}

// Allow counts an event of key at now and returns zero when the event is
// allowed. Otherwise it counts nothing and returns how long key must wait.
func (l *Limiter[K]) Allow(key K, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if wait := l.wait(key, now); wait > 0 {
		return wait
	}
	l.add(key, now)
	return 0
}

func (l *Limiter[K]) wait(key K, now time.Time) time.Duration {
	whole, ok := l.whole[key]
	if !ok {
		return 0
	}
	return max(whole.Sub(now)-l.tolerance, 0)
}

func (l *Limiter[K]) add(key K, now time.Time) {
	whole, ok := l.whole[key]
	if !ok {
		if !l.room(now) {
			return
		}
		whole = now
	}
	l.whole[key] = later(whole, now).Add(l.interval)
}

// room reports whether there is room for a new key. When it is time to, it
// first forgets the keys whose time has passed. Those keys live at most a
// burst of intervals after their last event, which is how often it sweeps.
func (l *Limiter[K]) room(now time.Time) bool {
	if !now.Before(l.sweep) {
		for key, whole := range l.whole {
			if !whole.After(now) {
				delete(l.whole, key)
			}
		}
		l.sweep = now.Add(l.tolerance + l.interval)
	}
	return len(l.whole) < l.maxKeys
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
