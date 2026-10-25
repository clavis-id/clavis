package storetest

import (
	"errors"
	"sync"
	"testing"
	"time"

	"clavisid.org/clavis/store"
)

func runLimitCounters(t *testing.T, open OpenFunc) {
	newStore := func(t *testing.T) (store.LimitCounters, store.Store, store.Tenant) {
		t.Helper()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		return s.LimitCounters(), s, tn
	}
	newKey := func(tn store.Tenant) store.LimitKey {
		return store.LimitKey{TenantID: tn.ID, Kind: "sign_in", Key: []byte("hash of ada@example.com")}
	}
	start := time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.UTC)
	const window = 15 * time.Minute
	// add counts an event at the given time after start and checks the
	// counter that Add returns and that Get returns afterwards.
	add := func(t *testing.T, lc store.LimitCounters, k store.LimitKey, after time.Duration, lockAt int,
		want store.LimitCount,
	) {
		t.Helper()
		want.EndsAt = want.EndsAt.Truncate(time.Microsecond)
		got, err := lc.Add(t.Context(), k, start.Add(after), window, lockAt)
		if err != nil || got != want {
			t.Fatalf("Add() %v after the start = %+v, %v; want %+v", after, got, err, want)
		}
		if got, err := lc.Get(t.Context(), k); err != nil || got != want {
			t.Fatalf("Get() after Add() = %+v, %v; want %+v", got, err, want)
		}
	}

	t.Run("CountsInAWindow", func(t *testing.T) {
		t.Parallel()
		lc, _, tn := newStore(t)
		k := newKey(tn)
		ends := start.Add(window)
		add(t, lc, k, 0, 10, store.LimitCount{Count: 1, EndsAt: ends})
		add(t, lc, k, time.Minute, 10, store.LimitCount{Count: 2, EndsAt: ends})
		add(t, lc, k, window-time.Microsecond, 10, store.LimitCount{Count: 3, EndsAt: ends})
		// A counter that ended starts again.
		add(t, lc, k, window, 10, store.LimitCount{Count: 1, EndsAt: start.Add(2 * window)})
	})

	t.Run("ReachingLockAtHoldsTheKeyForAWindow", func(t *testing.T) {
		t.Parallel()
		lc, _, tn := newStore(t)
		k := newKey(tn)
		add(t, lc, k, 0, 3, store.LimitCount{Count: 1, EndsAt: start.Add(window)})
		add(t, lc, k, time.Minute, 3, store.LimitCount{Count: 2, EndsAt: start.Add(window)})
		locked := start.Add(2*time.Minute + window)
		add(t, lc, k, 2*time.Minute, 3, store.LimitCount{Count: 3, EndsAt: locked})
		// Later events count without moving the end.
		add(t, lc, k, 3*time.Minute, 3, store.LimitCount{Count: 4, EndsAt: locked})
		add(t, lc, k, window+time.Minute, 3, store.LimitCount{Count: 5, EndsAt: locked})
		add(t, lc, k, 2*time.Minute+window, 3, store.LimitCount{Count: 1, EndsAt: locked.Add(window)})

		// lockAt 1 holds the key from the first event.
		other := store.LimitKey{TenantID: tn.ID, Kind: "email", Key: k.Key}
		add(t, lc, other, 0, 1, store.LimitCount{Count: 1, EndsAt: start.Add(window)})
		add(t, lc, other, time.Minute, 1, store.LimitCount{Count: 2, EndsAt: start.Add(window)})
	})

	t.Run("ConcurrentEventsGetDistinctCounts", func(t *testing.T) {
		t.Parallel()
		lc, _, tn := newStore(t)
		k := newKey(tn)
		const n = 8
		counts := make(chan int, n)
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				c, err := lc.Add(t.Context(), k, start, window, n)
				if err != nil {
					t.Errorf("Add() unexpected error: %v", err)
				}
				counts <- c.Count
			})
		}
		wg.Wait()
		close(counts)
		seen := make(map[int]bool)
		for c := range counts {
			seen[c] = true
		}
		for want := 1; want <= n; want++ {
			if !seen[want] {
				t.Errorf("no concurrent Add() returned %d; got %v", want, seen)
			}
		}
	})

	t.Run("KeysAreSeparate", func(t *testing.T) {
		t.Parallel()
		lc, s, tn := newStore(t)
		other := newTenant("other")
		mustCreate(t, s.Tenants(), other)
		k := newKey(tn)
		add(t, lc, k, 0, 10, store.LimitCount{Count: 1, EndsAt: start.Add(window)})
		add(t, lc, k, 0, 10, store.LimitCount{Count: 2, EndsAt: start.Add(window)})
		for _, separate := range []store.LimitKey{
			{TenantID: other.ID, Kind: k.Kind, Key: k.Key},
			{TenantID: tn.ID, Kind: "email", Key: k.Key},
			{TenantID: tn.ID, Kind: k.Kind, Key: []byte("hash of grace@example.com")},
		} {
			if _, err := lc.Get(t.Context(), separate); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get(%+v) = %v, want ErrNotFound", separate, err)
			}
			add(t, lc, separate, time.Minute, 10, store.LimitCount{Count: 1, EndsAt: start.Add(time.Minute + window)})
		}
		if got, err := lc.Get(t.Context(), k); err != nil || got.Count != 2 {
			t.Errorf("Get() of the first key = %+v, %v; want a count of 2", got, err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		lc, _, tn := newStore(t)
		k := newKey(tn)
		add(t, lc, k, 0, 10, store.LimitCount{Count: 1, EndsAt: start.Add(window)})
		if err := lc.Delete(t.Context(), k); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := lc.Get(t.Context(), k); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() = %v, want ErrNotFound", err)
		}
		if err := lc.Delete(t.Context(), k); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second Delete() = %v, want ErrNotFound", err)
		}
		add(t, lc, k, time.Minute, 10, store.LimitCount{Count: 1, EndsAt: start.Add(time.Minute + window)})
	})

	t.Run("UnknownTenantAndTenantDeletion", func(t *testing.T) {
		t.Parallel()
		lc, s, tn := newStore(t)
		unknown := newKey(newTenant("unknown"))
		if _, err := lc.Add(t.Context(), unknown, start, window, 10); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Add() for an unknown tenant = %v, want ErrNotFound", err)
		}
		k := newKey(tn)
		add(t, lc, k, 0, 10, store.LimitCount{Count: 1, EndsAt: start.Add(window)})
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting the tenant: %v", err)
		}
		if _, err := lc.Get(t.Context(), k); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after the tenant was deleted = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		t.Parallel()
		lc, s, tn := newStore(t)
		other := newTenant("other")
		mustCreate(t, s.Tenants(), other)
		now := start.Add(window)
		ended, endsNow, alive, otherTenant := newKey(tn), newKey(tn), newKey(tn), newKey(other)
		ended.Key, endsNow.Key, alive.Key = []byte("ended"), []byte("ends now"), []byte("alive")
		for k, at := range map[*store.LimitKey]time.Time{
			&ended: start.Add(-time.Minute), &endsNow: start, &alive: start.Add(time.Microsecond),
			&otherTenant: start.Add(-time.Minute),
		} {
			if _, err := lc.Add(t.Context(), *k, at, window, 10); err != nil {
				t.Fatalf("Add() unexpected error: %v", err)
			}
		}
		n, err := lc.DeleteExpired(t.Context(), now)
		if err != nil || n != 3 {
			t.Fatalf("DeleteExpired() = %d, %v; want 3", n, err)
		}
		for _, k := range []store.LimitKey{ended, endsNow, otherTenant} {
			if _, err := lc.Get(t.Context(), k); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get(%s) after DeleteExpired() = %v, want ErrNotFound", k.Key, err)
			}
		}
		if _, err := lc.Get(t.Context(), alive); err != nil {
			t.Errorf("Get() of a counter that has not ended = %v, want it kept", err)
		}
	})
}
