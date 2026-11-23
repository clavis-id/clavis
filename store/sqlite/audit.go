package sqlite

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"
	"uuid"

	"clavisid.org/clavis/store"
	"clavisid.org/clavis/store/sqlite/internal/db"
)

type auditEvents struct {
	q *db.Queries
}

func (r auditEvents) Create(ctx context.Context, e store.AuditEvent) error {
	details, err := json.Marshal(e.Details)
	if err != nil {
		return fmt.Errorf("sqlite: creating audit event: encoding the details: %w", err)
	}
	err = r.q.CreateAuditEvent(ctx, db.CreateAuditEventParams{
		ID:         e.ID.String(),
		TenantID:   e.TenantID.String(),
		OccurredAt: e.OccurredAt.UnixMicro(),
		Type:       e.Type,
		Actor:      string(e.Actor),
		UserID:     optionalID(e.UserID),
		ClientID:   e.ClientID,
		SessionID:  optionalID(e.SessionID),
		Ip:         e.IP,
		UserAgent:  e.UserAgent,
		Details:    string(details),
	})
	return mapError("creating audit event", err)
}

func (r auditEvents) List(ctx context.Context, tenantID uuid.UUID, q store.AuditQuery) ([]store.AuditEvent, error) {
	if q.Limit < 1 || q.Limit > store.MaxPageSize {
		return nil, fmt.Errorf("sqlite: listing audit events: %w: limit %d is outside [1, %d]",
			store.ErrInvalidArgument, q.Limit, store.MaxPageSize)
	}
	rows, err := r.q.ListAuditEvents(ctx, db.ListAuditEventsParams{
		TenantID: tenantID.String(),
		UserID:   optionalID(q.UserID),
		Type:     q.Type,
		Before:   optionalID(q.Before),
		PageSize: int64(q.Limit),
	})
	if err != nil {
		return nil, mapError("listing audit events", err)
	}
	events := make([]store.AuditEvent, 0, len(rows))
	for _, row := range rows {
		ids, err := parseIDs("audit event", row.ID, row.TenantID)
		if err != nil {
			return nil, err
		}
		optional, err := parseOptionalIDs("audit event", row.UserID, row.SessionID)
		if err != nil {
			return nil, err
		}
		var details map[string]string
		if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
			return nil, fmt.Errorf("sqlite: corrupt details of audit event %s: %w", ids[0], err)
		}
		events = append(events, store.AuditEvent{
			ID:         ids[0],
			TenantID:   ids[1],
			OccurredAt: time.UnixMicro(row.OccurredAt).UTC(),
			Type:       row.Type,
			Actor:      store.AuditActor(row.Actor),
			UserID:     optional[0],
			ClientID:   row.ClientID,
			SessionID:  optional[1],
			IP:         row.Ip,
			UserAgent:  row.UserAgent,
			Details:    details,
		})
	}
	return events, nil
}

func (r auditEvents) DeleteBefore(ctx context.Context, before time.Time) (int64, error) {
	n, err := r.q.DeleteAuditEventsBefore(ctx, before.UnixMicro())
	return n, mapError("deleting audit events", err)
}
