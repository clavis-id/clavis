package sqlite

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type authorizationRequests struct {
	q *db.Queries
}

func (r authorizationRequests) Create(ctx context.Context, a store.AuthorizationRequest) error {
	lists, err := encodeLists(a.Scopes, a.UserInfoClaims, a.IDTokenClaims)
	if err != nil {
		return fmt.Errorf("sqlite: creating authorization request: %w", err)
	}
	err = r.q.CreateAuthorizationRequest(ctx, db.CreateAuthorizationRequestParams{
		ID:                  a.ID,
		TenantID:            a.TenantID.String(),
		ClientID:            a.ClientID.String(),
		BindingHash:         a.BindingHash,
		RedirectUri:         a.RedirectURI,
		RedirectUriProvided: boolInt(a.RedirectURIProvided),
		Scopes:              lists[0],
		State:               a.State,
		Nonce:               a.Nonce,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
		LoginHint:           a.LoginHint,
		HintSubject:         optionalID(a.HintSubject),
		UserinfoClaims:      lists[1],
		IDTokenClaims:       lists[2],
		ForceConsent:        boolInt(a.ForceConsent),
		SessionID:           optionalID(a.SessionID),
		CreatedAt:           a.CreatedAt.UnixMicro(),
		ExpiresAt:           a.ExpiresAt.UnixMicro(),
	})
	return mapError("creating authorization request", err)
}

func (r authorizationRequests) Get(ctx context.Context, tenantID uuid.UUID, id string) (store.AuthorizationRequest, error) {
	row, err := r.q.GetAuthorizationRequest(ctx, db.GetAuthorizationRequestParams{TenantID: tenantID.String(), ID: id})
	if err != nil {
		return store.AuthorizationRequest{}, mapError("getting authorization request", err)
	}
	ids, err := parseIDs("authorization request", row.TenantID, row.ClientID)
	if err != nil {
		return store.AuthorizationRequest{}, err
	}
	optional, err := parseOptionalIDs("authorization request", row.HintSubject, row.SessionID)
	if err != nil {
		return store.AuthorizationRequest{}, err
	}
	lists, err := decodeLists(row.Scopes, row.UserinfoClaims, row.IDTokenClaims)
	if err != nil {
		return store.AuthorizationRequest{}, fmt.Errorf("sqlite: corrupt list in an authorization request: %w", err)
	}
	a := store.AuthorizationRequest{
		ID:                  row.ID,
		TenantID:            ids[0],
		ClientID:            ids[1],
		BindingHash:         row.BindingHash,
		RedirectURI:         row.RedirectUri,
		RedirectURIProvided: row.RedirectUriProvided != 0,
		Scopes:              lists[0],
		State:               row.State,
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		LoginHint:           row.LoginHint,
		UserInfoClaims:      lists[1],
		IDTokenClaims:       lists[2],
		HintSubject:         optional[0],
		ForceConsent:        row.ForceConsent != 0,
		SessionID:           optional[1],
		CreatedAt:           time.UnixMicro(row.CreatedAt).UTC(),
		ExpiresAt:           time.UnixMicro(row.ExpiresAt).UTC(),
	}
	return a, nil
}

func (r authorizationRequests) SetSession(ctx context.Context, tenantID uuid.UUID, id string, sessionID uuid.UUID) error {
	n, err := r.q.SetAuthorizationRequestSession(ctx, db.SetAuthorizationRequestSessionParams{
		SessionID: optionalID(sessionID),
		TenantID:  tenantID.String(),
		ID:        id,
	})
	if err != nil {
		return mapError("setting the session of an authorization request", err)
	}
	if n == 0 {
		// Tell a request that has a session from one that does not exist.
		if _, err := r.Get(ctx, tenantID, id); err != nil {
			return err
		}
		return fmt.Errorf("sqlite: setting the session of an authorization request: %w", store.ErrConflict)
	}
	return nil
}

func (r authorizationRequests) Delete(ctx context.Context, tenantID uuid.UUID, id string) error {
	n, err := r.q.DeleteAuthorizationRequest(ctx, db.DeleteAuthorizationRequestParams{TenantID: tenantID.String(), ID: id})
	if err != nil {
		return mapError("deleting authorization request", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting authorization request: %w", store.ErrNotFound)
	}
	return nil
}

func (r authorizationRequests) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredAuthorizationRequests(ctx, now.UnixMicro())
	if err != nil {
		return 0, mapError("deleting expired authorization requests", err)
	}
	return n, nil
}

type sessions struct {
	q *db.Queries
}

func (r sessions) Create(ctx context.Context, s store.Session) error {
	amr, err := encodeList(s.AMR)
	if err != nil {
		return fmt.Errorf("sqlite: creating session: %w", err)
	}
	err = r.q.CreateSession(ctx, db.CreateSessionParams{
		ID:            s.ID.String(),
		TenantID:      s.TenantID.String(),
		TokenHash:     s.TokenHash,
		UserID:        s.UserID.String(),
		AuthTime:      s.AuthTime.UnixMicro(),
		Amr:           amr,
		Acr:           s.ACR,
		CreatedAt:     s.CreatedAt.UnixMicro(),
		LastSeenAt:    s.LastSeenAt.UnixMicro(),
		IdleExpiresAt: s.IdleExpiresAt.UnixMicro(),
		ExpiresAt:     s.ExpiresAt.UnixMicro(),
	})
	return mapError("creating session", err)
}

func (r sessions) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash []byte) (store.Session, error) {
	row, err := r.q.GetSessionByTokenHash(ctx, db.GetSessionByTokenHashParams{
		TenantID:  tenantID.String(),
		TokenHash: tokenHash,
	})
	if err != nil {
		return store.Session{}, mapError("getting session", err)
	}
	ids, err := parseIDs("session", row.ID, row.TenantID, row.UserID)
	if err != nil {
		return store.Session{}, err
	}
	amr, err := decodeList(row.Amr)
	if err != nil {
		return store.Session{}, fmt.Errorf("sqlite: corrupt amr in session %s: %w", ids[0], err)
	}
	return store.Session{
		ID:            ids[0],
		TenantID:      ids[1],
		TokenHash:     row.TokenHash,
		UserID:        ids[2],
		AuthTime:      time.UnixMicro(row.AuthTime).UTC(),
		AMR:           amr,
		ACR:           row.Acr,
		CreatedAt:     time.UnixMicro(row.CreatedAt).UTC(),
		LastSeenAt:    time.UnixMicro(row.LastSeenAt).UTC(),
		IdleExpiresAt: time.UnixMicro(row.IdleExpiresAt).UTC(),
		ExpiresAt:     time.UnixMicro(row.ExpiresAt).UTC(),
	}, nil
}

func (r sessions) Touch(ctx context.Context, tenantID, id uuid.UUID, lastSeenAt, idleExpiresAt time.Time) error {
	n, err := r.q.TouchSession(ctx, db.TouchSessionParams{
		LastSeenAt:    lastSeenAt.UnixMicro(),
		IdleExpiresAt: idleExpiresAt.UnixMicro(),
		TenantID:      tenantID.String(),
		ID:            id.String(),
	})
	if err != nil {
		return mapError("touching session", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: touching session: %w", store.ErrNotFound)
	}
	return nil
}

func (r sessions) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := r.q.DeleteSession(ctx, db.DeleteSessionParams{TenantID: tenantID.String(), ID: id.String()})
	if err != nil {
		return mapError("deleting session", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deleting session: %w", store.ErrNotFound)
	}
	return nil
}

func (r sessions) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredSessions(ctx, now.UnixMicro())
	if err != nil {
		return 0, mapError("deleting expired sessions", err)
	}
	return n, nil
}

type authorizationCodes struct {
	q *db.Queries
}

func (r authorizationCodes) Create(ctx context.Context, c store.AuthorizationCode) error {
	lists, err := encodeLists(c.Scopes, c.AMR, c.UserInfoClaims, c.IDTokenClaims)
	if err != nil {
		return fmt.Errorf("sqlite: creating authorization code: %w", err)
	}
	err = r.q.CreateAuthorizationCode(ctx, db.CreateAuthorizationCodeParams{
		Hash:                c.Hash,
		TenantID:            c.TenantID.String(),
		ClientID:            c.ClientID.String(),
		UserID:              c.UserID.String(),
		SessionID:           c.SessionID.String(),
		RedirectUri:         c.RedirectURI,
		RedirectUriProvided: boolInt(c.RedirectURIProvided),
		Scopes:              lists[0],
		Nonce:               c.Nonce,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		AuthTime:            c.AuthTime.UnixMicro(),
		Amr:                 lists[1],
		Acr:                 c.ACR,
		UserinfoClaims:      lists[2],
		IDTokenClaims:       lists[3],
		CreatedAt:           c.CreatedAt.UnixMicro(),
		ExpiresAt:           c.ExpiresAt.UnixMicro(),
	})
	return mapError("creating authorization code", err)
}

func (r authorizationCodes) Get(ctx context.Context, tenantID uuid.UUID, hash []byte) (store.AuthorizationCode, error) {
	row, err := r.q.GetAuthorizationCode(ctx, db.GetAuthorizationCodeParams{TenantID: tenantID.String(), Hash: hash})
	if err != nil {
		return store.AuthorizationCode{}, mapError("getting authorization code", err)
	}
	ids, err := parseIDs("authorization code", row.TenantID, row.ClientID, row.UserID, row.SessionID)
	if err != nil {
		return store.AuthorizationCode{}, err
	}
	lists, err := decodeLists(row.Scopes, row.Amr, row.UserinfoClaims, row.IDTokenClaims)
	if err != nil {
		return store.AuthorizationCode{}, fmt.Errorf("sqlite: corrupt list in an authorization code: %w", err)
	}
	return store.AuthorizationCode{
		Hash:                row.Hash,
		TenantID:            ids[0],
		ClientID:            ids[1],
		UserID:              ids[2],
		SessionID:           ids[3],
		RedirectURI:         row.RedirectUri,
		RedirectURIProvided: row.RedirectUriProvided != 0,
		Scopes:              lists[0],
		Nonce:               row.Nonce,
		CodeChallenge:       row.CodeChallenge,
		CodeChallengeMethod: row.CodeChallengeMethod,
		AuthTime:            time.UnixMicro(row.AuthTime).UTC(),
		AMR:                 lists[1],
		ACR:                 row.Acr,
		UserInfoClaims:      lists[2],
		IDTokenClaims:       lists[3],
		CreatedAt:           time.UnixMicro(row.CreatedAt).UTC(),
		ExpiresAt:           time.UnixMicro(row.ExpiresAt).UTC(),
		RedeemedAt:          timeOrZero(row.RedeemedAt),
	}, nil
}

// encodeList encodes a list as a JSON array; a nil slice becomes an empty
// array.
func encodeList(list []string) (string, error) {
	b, err := json.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("encoding a list: %w", err)
	}
	return string(b), nil
}

func decodeList(encoded string) ([]string, error) {
	var list []string
	if err := json.Unmarshal([]byte(encoded), &list); err != nil {
		return nil, fmt.Errorf("decoding a list: %w", err)
	}
	return list, nil
}

// encodeLists encodes several lists with encodeList, in order.
func encodeLists(lists ...[]string) ([]string, error) {
	encoded := make([]string, len(lists))
	for i, list := range lists {
		var err error
		if encoded[i], err = encodeList(list); err != nil {
			return nil, err
		}
	}
	return encoded, nil
}

// decodeLists decodes several lists with decodeList, in order.
func decodeLists(encoded ...string) ([][]string, error) {
	lists := make([][]string, len(encoded))
	for i, e := range encoded {
		var err error
		if lists[i], err = decodeList(e); err != nil {
			return nil, err
		}
	}
	return lists, nil
}

// parseOptionalIDs parses nullable UUID columns of a record of the given
// kind; NULL becomes the zero UUID.
func parseOptionalIDs(kind string, columns ...sql.NullString) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, len(columns))
	for i, column := range columns {
		if !column.Valid {
			continue
		}
		id, err := uuid.Parse(column.String)
		if err != nil {
			return nil, fmt.Errorf("sqlite: corrupt id %q in %s: %w", column.String, kind, err)
		}
		ids[i] = id
	}
	return ids, nil
}

// parseIDs parses the UUID columns of a record of the given kind.
func parseIDs(kind string, columns ...string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, len(columns))
	for i, column := range columns {
		id, err := uuid.Parse(column)
		if err != nil {
			return nil, fmt.Errorf("sqlite: corrupt id %q in %s: %w", column, kind, err)
		}
		ids[i] = id
	}
	return ids, nil
}

func (r authorizationCodes) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredAuthorizationCodes(ctx, before.UnixMicro())
	if err != nil {
		return 0, mapError("deleting expired authorization codes", err)
	}
	return n, nil
}
