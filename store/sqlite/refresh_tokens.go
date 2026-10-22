package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type refreshTokens struct {
	db *sql.DB
	q  *db.Queries
}

func (r refreshTokens) Create(ctx context.Context, f store.RefreshTokenFamily, t store.RefreshToken) error {
	if t.TenantID != f.TenantID || t.FamilyID != f.ID {
		return fmt.Errorf("sqlite: creating refresh token family: %w: the token belongs to another family",
			store.ErrInvalidArgument)
	}
	lists, err := encodeLists(f.Scopes, f.AMR, f.UserInfoClaims, f.IDTokenClaims)
	if err != nil {
		return fmt.Errorf("sqlite: creating refresh token family: %w", err)
	}
	return r.inTx(ctx, "creating refresh token family", func(q *db.Queries) error {
		if err := q.CreateRefreshTokenFamily(ctx, db.CreateRefreshTokenFamilyParams{
			ID:             f.ID.String(),
			TenantID:       f.TenantID.String(),
			ClientID:       f.ClientID.String(),
			UserID:         f.UserID.String(),
			SessionID:      optionalID(f.SessionID),
			CodeHash:       f.CodeHash,
			Scopes:         lists[0],
			AuthTime:       f.AuthTime.UnixMicro(),
			Amr:            lists[1],
			Acr:            f.ACR,
			UserinfoClaims: lists[2],
			IDTokenClaims:  lists[3],
			CreatedAt:      f.CreatedAt.UnixMicro(),
			IdleExpiresAt:  f.IdleExpiresAt.UnixMicro(),
			ExpiresAt:      f.ExpiresAt.UnixMicro(),
		}); err != nil {
			return mapError("creating refresh token family", err)
		}
		return createRefreshToken(ctx, q, t)
	})
}

func createRefreshToken(ctx context.Context, q *db.Queries, t store.RefreshToken) error {
	err := q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		Hash:      t.Hash,
		TenantID:  t.TenantID.String(),
		FamilyID:  t.FamilyID.String(),
		IssuedAt:  t.IssuedAt.UnixMicro(),
		ExpiresAt: t.ExpiresAt.UnixMicro(),
	})
	return mapError("creating refresh token", err)
}

func (r refreshTokens) Get(ctx context.Context, tenantID uuid.UUID, hash []byte,
) (store.RefreshToken, store.RefreshTokenFamily, error) {
	row, err := r.q.GetRefreshToken(ctx, db.GetRefreshTokenParams{TenantID: tenantID.String(), Hash: hash})
	if err != nil {
		return store.RefreshToken{}, store.RefreshTokenFamily{}, mapError("getting refresh token", err)
	}
	t, f := row.RefreshToken, row.RefreshTokenFamily
	ids, err := parseIDs("refresh token", t.TenantID, t.FamilyID, f.ClientID, f.UserID)
	if err != nil {
		return store.RefreshToken{}, store.RefreshTokenFamily{}, err
	}
	session, err := parseOptionalIDs("refresh token family", f.SessionID)
	if err != nil {
		return store.RefreshToken{}, store.RefreshTokenFamily{}, err
	}
	lists, err := decodeLists(f.Scopes, f.Amr, f.UserinfoClaims, f.IDTokenClaims)
	if err != nil {
		return store.RefreshToken{}, store.RefreshTokenFamily{},
			fmt.Errorf("sqlite: corrupt list in a refresh token family: %w", err)
	}
	token := store.RefreshToken{
		Hash:      t.Hash,
		TenantID:  ids[0],
		FamilyID:  ids[1],
		IssuedAt:  time.UnixMicro(t.IssuedAt).UTC(),
		ExpiresAt: time.UnixMicro(t.ExpiresAt).UTC(),
		RotatedAt: timeOrZero(t.RotatedAt),
	}
	return token, store.RefreshTokenFamily{
		ID:             ids[1],
		TenantID:       ids[0],
		ClientID:       ids[2],
		UserID:         ids[3],
		SessionID:      session[0],
		CodeHash:       f.CodeHash,
		Scopes:         lists[0],
		AuthTime:       time.UnixMicro(f.AuthTime).UTC(),
		AMR:            lists[1],
		ACR:            f.Acr,
		UserInfoClaims: lists[2],
		IDTokenClaims:  lists[3],
		CreatedAt:      time.UnixMicro(f.CreatedAt).UTC(),
		IdleExpiresAt:  time.UnixMicro(f.IdleExpiresAt).UTC(),
		ExpiresAt:      time.UnixMicro(f.ExpiresAt).UTC(),
		RevokedAt:      timeOrZero(f.RevokedAt),
	}, nil
}

func (r refreshTokens) Rotate(ctx context.Context, tenantID uuid.UUID, hash []byte, next store.RefreshToken) error {
	if next.TenantID != tenantID {
		return fmt.Errorf("sqlite: rotating refresh token: %w: the successor belongs to another tenant",
			store.ErrInvalidArgument)
	}
	const op = "rotating refresh token"
	return r.inTx(ctx, op, func(q *db.Queries) error {
		// The family comes first, as in the cascade from a deleted family
		// to its tokens.
		extended, err := q.ExtendRefreshTokenFamily(ctx, db.ExtendRefreshTokenFamilyParams{
			IdleExpiresAt: next.ExpiresAt.UnixMicro(),
			TenantID:      tenantID.String(),
			ID:            next.FamilyID.String(),
		})
		if err != nil {
			return mapError(op, err)
		}
		rotated := int64(0)
		if extended == 1 {
			rotated, err = q.RotateRefreshToken(ctx, db.RotateRefreshTokenParams{
				RotatedAt: optionalTime(next.IssuedAt),
				TenantID:  tenantID.String(),
				Hash:      hash,
				FamilyID:  next.FamilyID.String(),
			})
			if err != nil {
				return mapError(op, err)
			}
		}
		if rotated == 0 {
			n, err := q.CountRefreshTokensInFamily(ctx, db.CountRefreshTokensInFamilyParams{
				TenantID: tenantID.String(),
				Hash:     hash,
				FamilyID: next.FamilyID.String(),
			})
			switch {
			case err != nil:
				return mapError(op, err)
			case n == 0:
				return fmt.Errorf("sqlite: %s: %w", op, store.ErrNotFound)
			}
			return fmt.Errorf("sqlite: %s: rotated already or revoked: %w", op, store.ErrConflict)
		}
		return createRefreshToken(ctx, q, next)
	})
}

func (r refreshTokens) RevokeFamily(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	n, err := r.q.RevokeRefreshTokenFamily(ctx, db.RevokeRefreshTokenFamilyParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		ID:        id.String(),
	})
	if err != nil {
		return mapError("revoking refresh token family", err)
	}
	if n == 1 {
		return nil
	}
	// The family was revoked already, or does not exist.
	exists, err := r.q.CountRefreshTokenFamilies(ctx, db.CountRefreshTokenFamiliesParams{
		TenantID: tenantID.String(),
		ID:       id.String(),
	})
	switch {
	case err != nil:
		return mapError("revoking refresh token family", err)
	case exists == 0:
		return fmt.Errorf("sqlite: revoking refresh token family: %w", store.ErrNotFound)
	}
	return nil
}

func (r refreshTokens) RevokeByCode(ctx context.Context, tenantID uuid.UUID, codeHash []byte, at time.Time,
) (int64, error) {
	n, err := r.q.RevokeRefreshTokenFamiliesByCode(ctx, db.RevokeRefreshTokenFamiliesByCodeParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
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
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		UserID:    userID.String(),
		ClientID:  clientID.String(),
	})
	if err != nil {
		return 0, mapError("revoking refresh token families", err)
	}
	return n, nil
}

func (r refreshTokens) RevokeByUser(ctx context.Context, tenantID, userID uuid.UUID, at time.Time) (int64, error) {
	n, err := r.q.RevokeRefreshTokenFamiliesByUser(ctx, db.RevokeRefreshTokenFamiliesByUserParams{
		RevokedAt: optionalTime(at),
		TenantID:  tenantID.String(),
		UserID:    userID.String(),
	})
	if err != nil {
		return 0, mapError("revoking the refresh token families of a user", err)
	}
	return n, nil
}

func (r refreshTokens) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	if _, err := r.q.DeleteExpiredRefreshTokens(ctx, now.UnixMicro()); err != nil {
		return 0, mapError("deleting expired refresh tokens", err)
	}
	n, err := r.q.DeleteExpiredRefreshTokenFamilies(ctx, now.UnixMicro())
	if err != nil {
		return 0, mapError("deleting expired refresh token families", err)
	}
	return n, nil
}

// inTx runs fn in a transaction, which it commits when fn succeeds. Open
// starts transactions with BEGIN IMMEDIATE, so they take the write lock at
// once and concurrent writers wait for it.
func (r refreshTokens) inTx(ctx context.Context, op string, fn func(*db.Queries) error) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return mapError(op, err)
	}
	defer func() {
		if err == nil {
			return
		}
		if rbErr := rollback(tx, op); rbErr != nil {
			err = errors.Join(err, rbErr)
		}
	}()
	if err := fn(r.q.WithTx(tx)); err != nil {
		return err
	}
	return mapError(op, tx.Commit())
}

// rollback rolls tx back, ignoring a transaction that already ended.
func rollback(tx *sql.Tx, op string) error {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("sqlite: %s: rolling back: %w", op, err)
	}
	return nil
}
