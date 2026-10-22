package storetest

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"

	"clavisid.org/clavis/store"
)

func runAuditEvents(t *testing.T, open OpenFunc) {
	// newEvents returns n events of tn whose IDs and times increase.
	newEvents := func(tn store.Tenant, n int) []store.AuditEvent {
		ids := make([]uuid.UUID, n)
		for i := range ids {
			ids[i] = uuid.NewV7()
		}
		slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
		events := make([]store.AuditEvent, n)
		base := time.Date(2026, 10, 22, 12, 0, 0, 123456789, time.UTC)
		for i := range events {
			events[i] = store.AuditEvent{
				ID:         ids[i],
				TenantID:   tn.ID,
				OccurredAt: base.Add(time.Duration(i) * time.Minute),
				Type:       "user.signed_in",
				Actor:      store.ActorUser,
				ClientID:   "app",
				IP:         "203.0.113.7",
				UserAgent:  "Mozilla/5.0",
				Details:    map[string]string{"method": "pwd"},
			}
		}
		return events
	}
	create := func(t *testing.T, s store.Store, events ...store.AuditEvent) {
		t.Helper()
		for _, e := range events {
			if err := s.AuditEvents().Create(t.Context(), e); err != nil {
				t.Fatalf("Create() unexpected error: %v", err)
			}
		}
	}
	list := func(t *testing.T, s store.Store, tenantID uuid.UUID, q store.AuditQuery) []store.AuditEvent {
		t.Helper()
		got, err := s.AuditEvents().List(t.Context(), tenantID, q)
		if err != nil {
			t.Fatalf("List(%+v) unexpected error: %v", q, err)
		}
		return got
	}
	normalized := func(events ...store.AuditEvent) []store.AuditEvent {
		out := make([]store.AuditEvent, len(events))
		for i, e := range events {
			e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
			out[i] = e
		}
		return out
	}

	t.Run("CreateAndListNewestFirst", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		events := newEvents(tn, 3)
		events[0].UserID, events[0].SessionID = uuid.NewV7(), uuid.NewV7()
		events[1].Actor, events[1].ClientID, events[1].IP, events[1].UserAgent = store.ActorOperator, "", "", ""
		events[2].Details = map[string]string{}
		create(t, s, events...)
		want := normalized(events[2], events[1], events[0])
		if diff := cmp.Diff(want, list(t, s, tn.ID, store.AuditQuery{Limit: 10})); diff != "" {
			t.Errorf("List() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("FiltersAndPages", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		ada, grace := uuid.NewV7(), uuid.NewV7()
		events := newEvents(tn, 5)
		for i := range events {
			events[i].UserID = ada
		}
		events[1].UserID = grace
		events[3].Type = "user.signed_out"
		create(t, s, events...)

		ids := func(events []store.AuditEvent) []uuid.UUID {
			out := make([]uuid.UUID, len(events))
			for i, e := range events {
				out[i] = e.ID
			}
			return out
		}
		for name, tt := range map[string]struct {
			q    store.AuditQuery
			want []store.AuditEvent
		}{
			"user":         {store.AuditQuery{UserID: grace, Limit: 10}, []store.AuditEvent{events[1]}},
			"type":         {store.AuditQuery{Type: "user.signed_out", Limit: 10}, []store.AuditEvent{events[3]}},
			"first page":   {store.AuditQuery{Limit: 2}, []store.AuditEvent{events[4], events[3]}},
			"next page":    {store.AuditQuery{Before: events[3].ID, Limit: 2}, []store.AuditEvent{events[2], events[1]}},
			"last page":    {store.AuditQuery{Before: events[1].ID, Limit: 2}, []store.AuditEvent{events[0]}},
			"user, paged":  {store.AuditQuery{UserID: ada, Before: events[2].ID, Limit: 10}, []store.AuditEvent{events[0]}},
			"no match":     {store.AuditQuery{Type: "client.created", Limit: 10}, nil},
			"another user": {store.AuditQuery{UserID: uuid.NewV7(), Limit: 10}, nil},
		} {
			if diff := cmp.Diff(ids(tt.want), ids(list(t, s, tn.ID, tt.q))); diff != "" {
				t.Errorf("%s: List() IDs mismatch (-want +got):\n%s", name, diff)
			}
		}
		for _, limit := range []int{0, -1, store.MaxPageSize + 1} {
			if _, err := s.AuditEvents().List(t.Context(), tn.ID, store.AuditQuery{Limit: limit}); !errors.Is(err, store.ErrInvalidArgument) {
				t.Errorf("List(limit=%d) = %v, want ErrInvalidArgument", limit, err)
			}
		}
	})

	t.Run("ConflictAndUnknownTenant", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		e := newEvents(tn, 1)[0]
		create(t, s, e)
		if err := s.AuditEvents().Create(t.Context(), e); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create() with a duplicate ID = %v, want ErrConflict", err)
		}
		unknown := newEvents(newTenant("unknown"), 1)[0]
		if err := s.AuditEvents().Create(t.Context(), unknown); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Create() for an unknown tenant = %v, want ErrNotFound", err)
		}
	})

	t.Run("TenantIsolationAndDeletion", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn, other := newTenant("acme"), newTenant("other")
		mustCreate(t, s.Tenants(), tn)
		mustCreate(t, s.Tenants(), other)
		u := newUser(tn.ID, "ada@example.com")
		mustCreateUser(t, s.Users(), u)
		e := newEvents(tn, 1)[0]
		e.UserID = u.ID
		create(t, s, e)
		if got := list(t, s, other.ID, store.AuditQuery{Limit: 10}); len(got) != 0 {
			t.Errorf("List() for another tenant = %v, want none", got)
		}
		// Events outlive the users they are about.
		if err := s.Users().Delete(t.Context(), tn.ID, u.ID); err != nil {
			t.Fatalf("deleting the user: %v", err)
		}
		if got := list(t, s, tn.ID, store.AuditQuery{UserID: u.ID, Limit: 10}); len(got) != 1 {
			t.Errorf("events after the user was deleted = %d, want 1", len(got))
		}
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting the tenant: %v", err)
		}
		if got := list(t, s, tn.ID, store.AuditQuery{Limit: 10}); len(got) != 0 {
			t.Errorf("events after the tenant was deleted = %d, want none", len(got))
		}
	})

	t.Run("DeleteBefore", func(t *testing.T) {
		t.Parallel()
		s := open(t)
		tn, other := newTenant("acme"), newTenant("other")
		mustCreate(t, s.Tenants(), tn)
		mustCreate(t, s.Tenants(), other)
		events := newEvents(tn, 3)
		foreign := newEvents(other, 1)[0]
		create(t, s, append(events, foreign)...)
		// The first event of each tenant occurred before events[1].
		n, err := s.AuditEvents().DeleteBefore(t.Context(), events[1].OccurredAt)
		if err != nil || n != 2 {
			t.Fatalf("DeleteBefore() = %d, %v; want 2 removed", n, err)
		}
		got := list(t, s, tn.ID, store.AuditQuery{Limit: 10})
		if len(got) != 2 || got[1].ID != events[1].ID {
			t.Errorf("events left = %+v, want the two from events[1] on", got)
		}
	})
}
