package storetest

import (
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"

	"clavisid.org/clavis/store"
)

func runEmailVerifications(t *testing.T, open OpenFunc) {
	newStore := func(t *testing.T) (store.Store, store.Tenant) {
		t.Helper()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		return s, tn
	}
	get := func(t *testing.T, s store.Store, tenantID uuid.UUID, id string) (store.EmailVerification, error) {
		t.Helper()
		return s.EmailVerifications().Get(t.Context(), tenantID, id)
	}

	t.Run("CreateAndGet", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		want := newEmailVerification(tn)
		mustCreateEmailVerification(t, s, want)
		got, err := get(t, s, tn.ID, want.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeEmailVerification(want), got); diff != "" {
			t.Errorf("Get() mismatch (-want +got):\n%s", diff)
		}

		// A verified one, without an authorization request.
		verified := newEmailVerification(tn)
		verified.AuthorizationRequestID = ""
		verified.Attempts = 2
		verified.VerifiedAt = verified.CreatedAt.Add(time.Minute)
		mustCreateEmailVerification(t, s, verified)
		got, err = get(t, s, tn.ID, verified.ID)
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if diff := cmp.Diff(normalizeEmailVerification(verified), got); diff != "" {
			t.Errorf("Get() of a verified one mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("AttemptsAndVerification", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		v := newEmailVerification(tn)
		mustCreateEmailVerification(t, s, v)
		ev := s.EmailVerifications()
		for want := 1; want <= 2; want++ {
			if n, err := ev.AddAttempt(t.Context(), tn.ID, v.ID); err != nil || n != want {
				t.Fatalf("AddAttempt() = %d, %v; want %d", n, err, want)
			}
		}
		at := time.Date(2026, 10, 21, 12, 5, 0, 123456789, time.UTC)
		if err := ev.MarkVerified(t.Context(), tn.ID, v.ID, at); err != nil {
			t.Fatalf("MarkVerified() unexpected error: %v", err)
		}
		got, err := get(t, s, tn.ID, v.ID)
		if err != nil || got.Attempts != 2 || !got.VerifiedAt.Equal(at.Truncate(time.Microsecond)) {
			t.Errorf("Get() after MarkVerified() = %+v, %v; want 2 attempts, verified at %v", got, err, at)
		}
		if err := ev.MarkVerified(t.Context(), tn.ID, v.ID, at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second MarkVerified() = %v, want ErrNotFound", err)
		}
		if _, err := ev.AddAttempt(t.Context(), tn.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AddAttempt() after MarkVerified() = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConcurrentAttemptsGetDistinctCounts", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		v := newEmailVerification(tn)
		mustCreateEmailVerification(t, s, v)
		const n = 8
		counts := make(chan int, n)
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				c, err := s.EmailVerifications().AddAttempt(t.Context(), tn.ID, v.ID)
				if err != nil {
					t.Errorf("AddAttempt() unexpected error: %v", err)
				}
				counts <- c
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
				t.Errorf("no concurrent AddAttempt() returned %d; got %v", want, seen)
			}
		}
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		v := newEmailVerification(tn)
		mustCreateEmailVerification(t, s, v)
		ev := s.EmailVerifications()
		if err := ev.Delete(t.Context(), tn.ID, v.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := get(t, s, tn.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() = %v, want ErrNotFound", err)
		}
		if err := ev.Delete(t.Context(), tn.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second Delete() = %v, want ErrNotFound", err)
		}
	})

	t.Run("NotFoundAndConflict", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		ev := s.EmailVerifications()
		missing := newEmailVerification(tn).ID
		if _, err := get(t, s, tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() = %v, want ErrNotFound", err)
		}
		if _, err := ev.AddAttempt(t.Context(), tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AddAttempt() = %v, want ErrNotFound", err)
		}
		if err := ev.MarkVerified(t.Context(), tn.ID, missing, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MarkVerified() = %v, want ErrNotFound", err)
		}
		if err := ev.Delete(t.Context(), tn.ID, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() = %v, want ErrNotFound", err)
		}
		v := newEmailVerification(tn)
		mustCreateEmailVerification(t, s, v)
		if err := ev.Create(t.Context(), v); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID = %v, want ErrConflict", err)
		}
		unknown := newEmailVerification(newTenant("unknown"))
		if err := ev.Create(t.Context(), unknown); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown tenant = %v, want ErrNotFound", err)
		}
	})

	t.Run("TenantIsolationAndDeletion", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		other := newTenant("other")
		mustCreate(t, s.Tenants(), other)
		v := newEmailVerification(tn)
		mustCreateEmailVerification(t, s, v)
		ev := s.EmailVerifications()
		if _, err := get(t, s, other.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() for another tenant = %v, want ErrNotFound", err)
		}
		if _, err := ev.AddAttempt(t.Context(), other.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AddAttempt() for another tenant = %v, want ErrNotFound", err)
		}
		if err := ev.MarkVerified(t.Context(), other.ID, v.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MarkVerified() for another tenant = %v, want ErrNotFound", err)
		}
		if err := ev.Delete(t.Context(), other.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() for another tenant = %v, want ErrNotFound", err)
		}
		if got, err := get(t, s, tn.ID, v.ID); err != nil || got.Attempts != 0 || !got.VerifiedAt.IsZero() {
			t.Errorf("the verification after calls for another tenant = %+v, %v; want it unchanged", got, err)
		}
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting the tenant: %v", err)
		}
		if _, err := get(t, s, tn.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after the tenant was deleted = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		other := newTenant("other")
		mustCreate(t, s.Tenants(), other)
		now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
		expired, expiresNow, alive, otherTenant := newEmailVerification(tn), newEmailVerification(tn),
			newEmailVerification(tn), newEmailVerification(other)
		expired.ExpiresAt = now.Add(-time.Minute)
		expiresNow.ExpiresAt = now
		alive.ExpiresAt = now.Add(time.Microsecond)
		otherTenant.ExpiresAt = now.Add(-time.Minute)
		for _, v := range []store.EmailVerification{expired, expiresNow, alive, otherTenant} {
			mustCreateEmailVerification(t, s, v)
		}
		n, err := s.EmailVerifications().DeleteExpired(t.Context(), now)
		if err != nil || n != 3 {
			t.Fatalf("DeleteExpired() = %d, %v; want 3 removed", n, err)
		}
		if _, err := get(t, s, tn.ID, alive.ID); err != nil {
			t.Errorf("Get() of the verification that has not expired = %v, want nil", err)
		}
		for _, v := range []store.EmailVerification{expired, expiresNow} {
			if _, err := get(t, s, tn.ID, v.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get() of an expired verification = %v, want ErrNotFound", err)
			}
		}
	})
}

// newEmailVerification returns an unverified signup verification of tn with
// every other field set.
func newEmailVerification(tn store.Tenant) store.EmailVerification {
	created := time.Date(2026, 10, 21, 12, 0, 0, 123456789, time.UTC)
	id := uuid.NewV7().String()
	return store.EmailVerification{
		ID:          id,
		TenantID:    tn.ID,
		Purpose:     store.VerifySignup,
		Email:       "ada@example.com",
		CodeHash:    hashOf("code " + id),
		LinkHash:    hashOf("link " + id),
		BindingHash: hashOf("binding " + id),
		// Not a reference: any request ID is stored as is.
		AuthorizationRequestID: "Q2xhdmlzIHJlcXVlc3QgaWQ",
		CreatedAt:              created,
		ExpiresAt:              created.Add(15 * time.Minute),
	}
}

func mustCreateEmailVerification(t *testing.T, s store.Store, v store.EmailVerification) {
	t.Helper()
	if err := s.EmailVerifications().Create(t.Context(), v); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
}

// normalizeEmailVerification returns v as a store returns it.
func normalizeEmailVerification(v store.EmailVerification) store.EmailVerification {
	for _, ts := range []*time.Time{&v.CreatedAt, &v.ExpiresAt} {
		*ts = ts.UTC().Truncate(time.Microsecond)
	}
	if !v.VerifiedAt.IsZero() {
		v.VerifiedAt = v.VerifiedAt.UTC().Truncate(time.Microsecond)
	}
	return v
}
