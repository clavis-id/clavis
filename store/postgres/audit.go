package postgres

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/postgres/internal/db"
)

type auditEvents struct {
	q *db.Queries
}

func (r auditEvents) Create(ctx context.Context, e store.AuditEvent) error {
	details, err := json.Marshal(e.Details)
	if err != nil {
		return fmt.Errorf("postgres: creating audit event: encoding the details: %w", err)
	}
	err = r.q.CreateAuditEvent(ctx, db.CreateAuditEventParams{
		ID:         e.ID,
		TenantID:   e.TenantID,
		OccurredAt: e.OccurredAt,
		Type:       e.Type,
		Actor:      string(e.Actor),
		UserID:     optionalID(e.UserID),
		ClientID:   e.ClientID,
		SessionID:  optionalID(e.SessionID),
		Ip:         e.IP,
		UserAgent:  e.UserAgent,
		Details:    details,
	})
	return mapError("creating audit event", err)
}

func (r auditEvents) List(ctx context.Context, tenantID uuid.UUID, q store.AuditQuery) ([]store.AuditEvent, error) {
	if q.Limit < 1 || q.Limit > store.MaxPageSize {
		return nil, fmt.Errorf("postgres: listing audit events: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, q.Limit, store.MaxPageSize)
	}
	rows, err := r.q.ListAuditEvents(ctx, db.ListAuditEventsParams{
		TenantID: tenantID,
		UserID:   optionalID(q.UserID),
		Type:     q.Type,
		Before:   optionalID(q.Before),
		PageSize: int32(q.Limit),
	})
	if err != nil {
		return nil, mapError("listing audit events", err)
	}
	events := make([]store.AuditEvent, 0, len(rows))
	for _, row := range rows {
		var details map[string]string
		if err := json.Unmarshal(row.Details, &details); err != nil {
			return nil, fmt.Errorf("postgres: corrupt details of audit event %s: %w", row.ID, err)
		}
		events = append(events, store.AuditEvent{
			ID:         row.ID,
			TenantID:   row.TenantID,
			OccurredAt: row.OccurredAt.UTC(),
			Type:       row.Type,
			Actor:      store.AuditActor(row.Actor),
			UserID:     idOrZero(row.UserID),
			ClientID:   row.ClientID,
			SessionID:  idOrZero(row.SessionID),
			IP:         row.Ip,
			UserAgent:  row.UserAgent,
			Details:    details,
		})
	}
	return events, nil
}

func (r auditEvents) DeleteBefore(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.q.DeleteAuditEventsBefore(ctx, before)
	return n, mapError("deleting audit events", err)
}

// idOrZero returns the ID of a nullable column, or the zero UUID for NULL.
func idOrZero(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil()
	}
	return *id
}
