package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

type refreshTokens struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

func (r refreshTokens) Create(ctx context.Context, f store.RefreshTokenFamily, t store.RefreshToken) error {
	if t.TenantID != f.TenantID || t.FamilyID != f.ID {
		return fmt.Errorf("postgres: creating refresh token family: %w: the token belongs to another family",
			store.ErrInvalidArgument)
	}
	return r.inTx(ctx, "creating refresh token family", func(q *db.Queries) error {
		if err := q.CreateRefreshTokenFamily(ctx, db.CreateRefreshTokenFamilyParams{
			ID:             f.ID,
			TenantID:       f.TenantID,
			ClientID:       f.ClientID,
			UserID:         f.UserID,
			SessionID:      optionalID(f.SessionID),
			CodeHash:       f.CodeHash,
			Scopes:         orEmpty(f.Scopes),
			AuthTime:       f.AuthTime,
			Amr:            orEmpty(f.AMR),
			Acr:            f.ACR,
			UserinfoClaims: orEmpty(f.UserInfoClaims),
			IDTokenClaims:  orEmpty(f.IDTokenClaims),
			CreatedAt:      f.CreatedAt,
			IdleExpiresAt:  f.IdleExpiresAt,
			ExpiresAt:      f.ExpiresAt,
		}); err != nil {
			return mapError("creating refresh token family", err)
		}
		return createRefreshToken(ctx, q, t)
	})
}

func createRefreshToken(ctx context.Context, q *db.Queries, t store.RefreshToken) error {
	err := q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		Hash:      t.Hash,
		TenantID:  t.TenantID,
		FamilyID:  t.FamilyID,
		IssuedAt:  t.IssuedAt,
		ExpiresAt: t.ExpiresAt,
	})
	return mapError("creating refresh token", err)
}

func (r refreshTokens) Get(ctx context.Context, tenantID uuid.UUID, hash []byte,
) (store.RefreshToken, store.RefreshTokenFamily, error) {
	row, err := r.q.GetRefreshToken(ctx, db.GetRefreshTokenParams{TenantID: tenantID, Hash: hash})
	if err != nil {
		return store.RefreshToken{}, store.RefreshTokenFamily{}, mapError("getting refresh token", err)
	}
	t, f := row.RefreshToken, row.RefreshTokenFamily
	family := store.RefreshTokenFamily{
		ID:             f.ID,
		TenantID:       f.TenantID,
		ClientID:       f.ClientID,
		UserID:         f.UserID,
		CodeHash:       f.CodeHash,
		Scopes:         f.Scopes,
		AuthTime:       f.AuthTime.UTC(),
		AMR:            f.Amr,
		ACR:            f.Acr,
		UserInfoClaims: f.UserinfoClaims,
		IDTokenClaims:  f.IDTokenClaims,
		CreatedAt:      f.CreatedAt.UTC(),
		IdleExpiresAt:  f.IdleExpiresAt.UTC(),
		ExpiresAt:      f.ExpiresAt.UTC(),
		RevokedAt:      utcOrZero(f.RevokedAt),
	}
	if f.SessionID != nil {
		family.SessionID = *f.SessionID
	}
	return store.RefreshToken{
		Hash:      t.Hash,
		TenantID:  t.TenantID,
		FamilyID:  t.FamilyID,
		IssuedAt:  t.IssuedAt.UTC(),
		ExpiresAt: t.ExpiresAt.UTC(),
		RotatedAt: utcOrZero(t.RotatedAt),
	}, family, nil
}

func (r refreshTokens) Rotate(ctx context.Context, tenantID uuid.UUID, hash []byte, next store.RefreshToken) error {
	if next.TenantID != tenantID {
		return fmt.Errorf("postgres: rotating refresh token: %w: the successor belongs to another tenant",
			store.ErrInvalidArgument)
	}
	const op = "rotating refresh token"
	return r.inTx(ctx, op, func(q *db.Queries) error {
		// The family row is locked first, as in the cascade from a deleted
		// family to its tokens, so the two cannot deadlock.
		extended, err := q.ExtendRefreshTokenFamily(ctx, db.ExtendRefreshTokenFamilyParams{
			IdleExpiresAt: next.ExpiresAt,
			TenantID:      tenantID,
			ID:            next.FamilyID,
		})
		if err != nil {
			return mapError(op, err)
		}
		rotated := int64(0)
		if extended == 1 {
			rotated, err = q.RotateRefreshToken(ctx, db.RotateRefreshTokenParams{
				RotatedAt: &next.IssuedAt,
				TenantID:  tenantID,
				Hash:      hash,
				FamilyID:  next.FamilyID,
			})
			if err != nil {
				return mapError(op, err)
			}
		}
		if rotated == 0 {
			n, err := q.CountRefreshTokensInFamily(ctx, db.CountRefreshTokensInFamilyParams{
				TenantID: tenantID,
				Hash:     hash,
				FamilyID: next.FamilyID,
			})
			switch {
			case err != nil:
				return mapError(op, err)
			case n == 0:
				return fmt.Errorf("postgres: %s: %w", op, store.ErrNotFound)
			}
			return fmt.Errorf("postgres: %s: rotated already or revoked: %w", op, store.ErrConflict)
		}
		return createRefreshToken(ctx, q, next)
	})
}

func (r refreshTokens) RevokeFamily(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	n, err := r.q.RevokeRefreshTokenFamily(ctx, db.RevokeRefreshTokenFamilyParams{
		RevokedAt: &at,
		TenantID:  tenantID,
		ID:        id,
	})
	if err != nil {
		return mapError("revoking refresh token family", err)
	}
	if n == 1 {
		return nil
	}
	// The family was revoked already, or does not exist.
	exists, err := r.q.CountRefreshTokenFamilies(ctx, db.CountRefreshTokenFamiliesParams{TenantID: tenantID, ID: id})
	switch {
	case err != nil:
		return mapError("revoking refresh token family", err)
	case exists == 0:
		return fmt.Errorf("postgres: revoking refresh token family: %w", store.ErrNotFound)
	}
	return nil
}

func (r refreshTokens) RevokeByCode(ctx context.Context, tenantID uuid.UUID, codeHash []byte, at time.Time,
) (int64, error) {
	n, err := r.q.RevokeRefreshTokenFamiliesByCode(ctx, db.RevokeRefreshTokenFamiliesByCodeParams{
		RevokedAt: &at,
		TenantID:  tenantID,
		CodeHash:  codeHash,
	})
	if err != nil {
		return 0, mapError("revoking refresh token families", err)
	}
	return n, nil
}

func (r refreshTokens) RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID, at time.Time,
) (int64, error) {
	n, err := r.q.RevokeRefreshTokenFamiliesByUserAndClient(ctx, db.RevokeRefreshTokenFamiliesByUserAndClientParams{
		RevokedAt: &at,
		TenantID:  tenantID,
		UserID:    userID,
		ClientID:  clientID,
	})
	if err != nil {
		return 0, mapError("revoking refresh token families", err)
	}
	return n, nil
}

func (r refreshTokens) RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error) {
	n, err := r.q.RevokeRefreshTokenFamiliesByUser(ctx, db.RevokeRefreshTokenFamiliesByUserParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID,
		UserID:    userID,
	})
	if err != nil {
		return 0, mapError("revoking the refresh token families of a user", err)
	}
	return n, nil
}

func (r refreshTokens) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	if _, err := r.q.DeleteExpiredRefreshTokens(ctx, now); err != nil {
		return 0, mapError("deleting expired refresh tokens", err)
	}
	n, err := r.q.DeleteExpiredRefreshTokenFamilies(ctx, now)
	if err != nil {
		return 0, mapError("deleting expired refresh token families", err)
	}
	return n, nil
}

// inTx runs fn in a transaction, which it commits when fn succeeds.
func (r refreshTokens) inTx(ctx context.Context, op string, fn func(*db.Queries) error) (err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return mapError(op, err)
	}
	defer func() {
		if err == nil {
			return
		}
		// A transaction that already ended needs no rollback.
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			err = errors.Join(err, fmt.Errorf("postgres: %s: rolling back: %w", op, rbErr))
		}
	}()
	if err := fn(r.q.WithTx(tx)); err != nil {
		return err
	}
	return mapError(op, tx.Commit(ctx))
}
