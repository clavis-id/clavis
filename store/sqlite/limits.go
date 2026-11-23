package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type limitCounters struct {
	db *sql.DB
	q  *db.Queries
}

// Add reads and writes the counter in one transaction, which holds the
// write lock: sqlc cannot pass parameters to the DO UPDATE clause of an
// upsert in SQLite.
func (r limitCounters) Add(ctx context.Context, k store.LimitKey, now time.Time, window time.Duration, lockAt int,
) (store.LimitCount, error) {
	const op = "counting a limit event"
	var c store.LimitCount
	err := inTx(ctx, r.db, r.q, op, func(q *db.Queries) error {
		row, err := q.GetLimitCounter(ctx, db.GetLimitCounterParams{TenantID: k.TenantID.String(), Kind: k.Kind,
			KeyHash: k.Key})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			c = store.LimitCount{Count: 1, EndsAt: now.Add(window)}
		case err != nil:
			return mapError(op, err)
		case row.EndsAt <= now.UnixMicro():
			c = store.LimitCount{Count: 1, EndsAt: now.Add(window)}
		default:
			c = store.LimitCount{Count: int(row.Hits) + 1, EndsAt: time.UnixMicro(row.EndsAt)}
			if c.Count == lockAt {
				c.EndsAt = now.Add(window)
			}
		}
		return mapError(op, q.PutLimitCounter(ctx, db.PutLimitCounterParams{
			TenantID: k.TenantID.String(),
			Kind:     k.Kind,
			KeyHash:  k.Key,
			Hits:     int64(c.Count),
			EndsAt:   c.EndsAt.UnixMicro(),
		}))
	})
	if err != nil {
		return store.LimitCount{}, err
	}
	return store.LimitCount{Count: c.Count, EndsAt: time.UnixMicro(c.EndsAt.UnixMicro()).UTC()}, nil
}

func (r limitCounters) Get(ctx context.Context, k store.LimitKey) (store.LimitCount, error) {
	row, err := r.q.GetLimitCounter(ctx, db.GetLimitCounterParams{TenantID: k.TenantID.String(), Kind: k.Kind,
		KeyHash: k.Key})
	if err != nil {
		return store.LimitCount{}, mapError("getting limit counter", err)
	}
	return store.LimitCount{Count: int(row.Hits), EndsAt: time.UnixMicro(row.EndsAt).UTC()}, nil
}

func (r limitCounters) Delete(ctx context.Context, k store.LimitKey) error {
	n, err := r.q.DeleteLimitCounter(ctx, db.DeleteLimitCounterParams{TenantID: k.TenantID.String(), Kind: k.Kind,
		KeyHash: k.Key})
	if err != nil {
		return mapError("deleting limit counter", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting limit counter: %w", store.ErrNotFound)
	}
	return nil
}

func (r limitCounters) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredLimitCounters(ctx, now.UnixMicro())
	return n, mapError("deleting expired limit counters", err)
}
