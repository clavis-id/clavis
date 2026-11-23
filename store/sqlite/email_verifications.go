package sqlite

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type emailVerifications struct {
	q *db.Queries
}

func (r emailVerifications) Create(ctx context.Context, v store.EmailVerification) error {
	err := r.q.CreateEmailVerification(ctx, db.CreateEmailVerificationParams{
		ID:                     v.ID,
		TenantID:               v.TenantID.String(),
		Purpose:                string(v.Purpose),
		Email:                  v.Email,
		CodeHash:               v.CodeHash,
		LinkHash:               v.LinkHash,
		BindingHash:            v.BindingHash,
		AuthorizationRequestID: v.AuthorizationRequestID,
		Attempts:               int64(v.Attempts),
		VerifiedAt:             optionalTime(v.VerifiedAt),
		CreatedAt:              v.CreatedAt.UnixMicro(),
		ExpiresAt:              v.ExpiresAt.UnixMicro(),
	})
	return mapError("creating email verification", err)
}

func (r emailVerifications) Get(ctx context.Context, tenantID uuid.UUID, id string) (store.EmailVerification, error) {
	row, err := r.q.GetEmailVerification(ctx, db.GetEmailVerificationParams{TenantID: tenantID.String(), ID: id})
	if err != nil {
		return store.EmailVerification{}, mapError("getting email verification", err)
	}
	ids, err := parseIDs("email verification", row.TenantID)
	if err != nil {
		return store.EmailVerification{}, err
	}
	return store.EmailVerification{
		ID:                     row.ID,
		TenantID:               ids[0],
		Purpose:                store.EmailVerificationPurpose(row.Purpose),
		Email:                  row.Email,
		CodeHash:               row.CodeHash,
		LinkHash:               row.LinkHash,
		BindingHash:            row.BindingHash,
		AuthorizationRequestID: row.AuthorizationRequestID,
		Attempts:               int(row.Attempts),
		VerifiedAt:             timeOrZero(row.VerifiedAt),
		CreatedAt:              time.UnixMicro(row.CreatedAt).UTC(),
		ExpiresAt:              time.UnixMicro(row.ExpiresAt).UTC(),
	}, nil
}

func (r emailVerifications) AddAttempt(ctx context.Context, tenantID uuid.UUID, id string) (int, error) {
	n, err := r.q.AddEmailVerificationAttempt(ctx, db.AddEmailVerificationAttemptParams{
		TenantID: tenantID.String(),
		ID:       id,
	})
	if err != nil {
		return 0, mapError("counting an email verification attempt", err)
	}
	return int(n), nil
}

func (r emailVerifications) MarkVerified(ctx context.Context, tenantID uuid.UUID, id string, at time.Time) error {
	n, err := r.q.MarkEmailVerificationVerified(ctx, db.MarkEmailVerificationVerifiedParams{
		VerifiedAt: optionalTime(at),
		TenantID:   tenantID.String(),
		ID:         id,
	})
	if err != nil {
		return mapError("marking an email verification verified", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: marking an email verification verified: %w", store.ErrNotFound)
	}
	return nil
}

func (r emailVerifications) Delete(ctx context.Context, tenantID uuid.UUID, id string) error {
	n, err := r.q.DeleteEmailVerification(ctx, db.DeleteEmailVerificationParams{TenantID: tenantID.String(), ID: id})
	if err != nil {
		return mapError("deleting email verification", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting email verification: %w", store.ErrNotFound)
	}
	return nil
}

func (r emailVerifications) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredEmailVerifications(ctx, now.UnixMicro())
	return n, mapError("deleting expired email verifications", err)
}
