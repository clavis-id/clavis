package postgres

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

type authorizationRequests struct {
	q *db.Queries
}

func (r authorizationRequests) Create(ctx context.Context, a store.AuthorizationRequest) error {
	err := r.q.CreateAuthorizationRequest(ctx, db.CreateAuthorizationRequestParams{
		ID:                  a.ID,
		TenantID:            a.TenantID,
		ClientID:            a.ClientID,
		BindingHash:         a.BindingHash,
		RedirectUri:         a.RedirectURI,
		RedirectUriProvided: a.RedirectURIProvided,
		Scopes:              orEmpty(a.Scopes),
		State:               a.State,
		Nonce:               a.Nonce,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
		CreatedAt:           a.CreatedAt,
		ExpiresAt:           a.ExpiresAt,
	})
	return mapError("creating authorization request", err)
}

func (r authorizationRequests) Get(ctx context.Context, tenantID uuid.UUID, id string) (store.AuthorizationRequest, error) {
	row, err := r.q.GetAuthorizationRequest(ctx, db.GetAuthorizationRequestParams{TenantID: tenantID, ID: id})
	if err != nil {
		return store.AuthorizationRequest{}, mapError("getting authorization request", err)
	}
	return store.AuthorizationRequest{
		ID:                  row.ID,
		TenantID:            row.TenantID,
		ClientID:            row.ClientID,
		BindingHash:         row.BindingHash,
		RedirectURI:         row.RedirectUri,
		RedirectURIProvided: row.RedirectUriProvided,
		Scopes:              row.Scopes,
		State:               row.State,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		CreatedAt:           row.CreatedAt.UTC(),
		ExpiresAt:           row.ExpiresAt.UTC(),
	}, nil
}

func (r authorizationRequests) Delete(ctx context.Context, tenantID uuid.UUID, id string) error {
	n, err := r.q.DeleteAuthorizationRequest(ctx, db.DeleteAuthorizationRequestParams{TenantID: tenantID, ID: id})
	if err != nil {
		return mapError("deleting authorization request", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting authorization request: %w", store.ErrNotFound)
	}
	return nil
}

func (r authorizationRequests) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredAuthorizationRequests(ctx, now)
	if err != nil {
		return 0, mapError("deleting expired authorization requests", err)
	}
	return n, nil
}

type sessions struct {
	q *db.Queries
}

func (r sessions) Create(ctx context.Context, s store.Session) error {
	err := r.q.CreateSession(ctx, db.CreateSessionParams{
		ID:            s.ID,
		TenantID:      s.TenantID,
		TokenHash:     s.TokenHash,
		UserID:        s.UserID,
		AuthTime:      s.AuthTime,
		Amr:           orEmpty(s.AMR),
		Acr:           s.ACR,
		CreatedAt:     s.CreatedAt,
		LastSeenAt:    s.LastSeenAt,
		IdleExpiresAt: s.IdleExpiresAt,
		ExpiresAt:     s.ExpiresAt,
	})
	return mapError("creating session", err)
}

func (r sessions) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash []byte) (store.Session, error) {
	row, err := r.q.GetSessionByTokenHash(ctx, db.GetSessionByTokenHashParams{TenantID: tenantID, TokenHash: tokenHash})
	if err != nil {
		return store.Session{}, mapError("getting session", err)
	}
	return store.Session{
		ID:            row.ID,
		TenantID:      row.TenantID,
		TokenHash:     row.TokenHash,
		UserID:        row.UserID,
		AuthTime:      row.AuthTime.UTC(),
		AMR:           row.Amr,
		ACR:           row.Acr,
		CreatedAt:     row.CreatedAt.UTC(),
		LastSeenAt:    row.LastSeenAt.UTC(),
		IdleExpiresAt: row.IdleExpiresAt.UTC(),
		ExpiresAt:     row.ExpiresAt.UTC(),
	}, nil
}

func (r sessions) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteSession(ctx, db.DeleteSessionParams{TenantID: tenantID, ID: id})
	if err != nil {
		return mapError("deleting session", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: deleting session: %w", store.ErrNotFound)
	}
	return nil
}

func (r sessions) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredSessions(ctx, now)
	if err != nil {
		return 0, mapError("deleting expired sessions", err)
	}
	return n, nil
}

type authorizationCodes struct {
	q *db.Queries
}

func (r authorizationCodes) Create(ctx context.Context, c store.AuthorizationCode) error {
	err := r.q.CreateAuthorizationCode(ctx, db.CreateAuthorizationCodeParams{
		Hash:                c.Hash,
		TenantID:            c.TenantID,
		ClientID:            c.ClientID,
		UserID:              c.UserID,
		SessionID:           c.SessionID,
		RedirectUri:         c.RedirectURI,
		RedirectUriProvided: c.RedirectURIProvided,
		Scopes:              orEmpty(c.Scopes),
		Nonce:               c.Nonce,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		AuthTime:            c.AuthTime,
		Amr:                 orEmpty(c.AMR),
		Acr:                 c.ACR,
		CreatedAt:           c.CreatedAt,
		ExpiresAt:           c.ExpiresAt,
	})
	return mapError("creating authorization code", err)
}

func (r authorizationCodes) Get(ctx context.Context, tenantID uuid.UUID, hash []byte) (store.AuthorizationCode, error) {
	row, err := r.q.GetAuthorizationCode(ctx, db.GetAuthorizationCodeParams{TenantID: tenantID, Hash: hash})
	if err != nil {
		return store.AuthorizationCode{}, mapError("getting authorization code", err)
	}
	return store.AuthorizationCode{
		Hash:                row.Hash,
		TenantID:            row.TenantID,
		ClientID:            row.ClientID,
		UserID:              row.UserID,
		SessionID:           row.SessionID,
		RedirectURI:         row.RedirectUri,
		RedirectURIProvided: row.RedirectUriProvided,
		Scopes:              row.Scopes,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		AuthTime:            row.AuthTime.UTC(),
		AMR:                 row.Amr,
		ACR:                 row.Acr,
		CreatedAt:           row.CreatedAt.UTC(),
		ExpiresAt:           row.ExpiresAt.UTC(),
	}, nil
}

func (r authorizationCodes) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredAuthorizationCodes(ctx, before)
	if err != nil {
		return 0, mapError("deleting expired authorization codes", err)
	}
	return n, nil
}
