package postgres

import (
	"context"
	"fmt"
	"time"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

type limitCounters struct {
	q *db.Queries
}

func (r limitCounters) Add(ctx context.Context, k store.LimitKey, now time.Time, window time.Duration, lockAt int,
) (store.LimitCount, error) {
	row, err := r.q.AddLimitHit(ctx, db.AddLimitHitParams{
		TenantID:       k.TenantID,
		Kind:           k.Kind,
		KeyHash:        k.Key,
		EndsAt:         now.Add(window),
		Now:            now,
		HitsBeforeLock: int64(lockAt) - 1,
	})
	if err != nil {
		return store.LimitCount{}, mapError("counting a limit event", err)
	}
	return store.LimitCount{Count: int(row.Hits), EndsAt: row.EndsAt.UTC()}, nil
}

func (r limitCounters) Get(ctx context.Context, k store.LimitKey) (store.LimitCount, error) {
	row, err := r.q.GetLimitCounter(ctx, db.GetLimitCounterParams{TenantID: k.TenantID, Kind: k.Kind, KeyHash: k.Key})
	if err != nil {
		return store.LimitCount{}, mapError("getting limit counter", err)
	}
	return store.LimitCount{Count: int(row.Hits), EndsAt: row.EndsAt.UTC()}, nil
}

func (r limitCounters) Delete(ctx context.Context, k store.LimitKey) error {
	n, err := r.q.DeleteLimitCounter(ctx, db.DeleteLimitCounterParams{TenantID: k.TenantID, Kind: k.Kind,
		KeyHash: k.Key})
	if err != nil {
		return mapError("deleting limit counter", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting limit counter: %w", store.ErrNotFound)
	}
	return nil
}

func (r limitCounters) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredLimitCounters(ctx, now)
	return n, mapError("deleting expired limit counters", err)
}
