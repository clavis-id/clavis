package cli

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"uuid"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/internal/app"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/store"
)

// defaultAuditLimit is how many events `clavis audit list` shows unless told
// otherwise.
const defaultAuditLimit = 50

func newAuditCommand(environ []string) *cobra.Command {
	var configPath, tenant string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read the audit log",
		Long: "Read the audit log of a tenant directly in the configured database. Clavis records sign-ins,\n" +
			"changes to accounts, consent, token revocations and changes to clients as audit events, and\n" +
			"the server deletes them after audit.retention.\n\n" + configHelp,
		Args: cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")
	cmd.PersistentFlags().StringVar(&tenant, "tenant", app.DefaultTenantSlug, "slug of the tenant")

	var user, eventType, before string
	var limit int
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List audit events, newest first",
		Long: "List the audit events of a tenant, newest first. When more events match, the command\n" +
			"says how to show the next ones with --before.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > store.MaxPageSize {
				return fmt.Errorf("--limit must be between 1 and %d", store.MaxPageSize)
			}
			q := store.AuditQuery{Type: eventType, Limit: limit}
			if before != "" {
				id, err := uuid.Parse(before)
				if err != nil {
					return fmt.Errorf("--before must be the ID of an event: %w", err)
				}
				q.Before = id
			}
			return withTenant(cmd, config.LoadDatabase, configPathOrEnv(configPath, environ), environ, tenant, false,
				func(ctx context.Context, _ config.Config, d app.Deps, t store.Tenant) error {
					if user != "" {
						id, err := auditUser(ctx, d, t, user)
						if err != nil {
							return err
						}
						q.UserID = id
					}
					page, err := app.ListAuditEvents(ctx, d, t.ID, q)
					if err != nil {
						return err
					}
					if asJSON {
						err = writeAuditJSON(cmd.OutOrStdout(), page)
					} else {
						err = writeAuditTable(cmd.OutOrStdout(), page)
					}
					if err != nil || len(page.Events) < limit {
						return err
					}
					next := page.Events[len(page.Events)-1].ID
					return write(cmd.ErrOrStderr(), fmt.Sprintf("More events may match: add --before %s.\n", next))
				})
		},
	}
	list.Flags().StringVar(&user, "user", "", "only events about this user, by email address or ID")
	list.Flags().StringVar(&eventType, "type", "", "only events of this type, such as "+app.EventSignInFailed)
	list.Flags().IntVar(&limit, "limit", defaultAuditLimit, "how many events to show")
	list.Flags().StringVar(&before, "before", "", "only events older than the event with this ID")
	list.Flags().BoolVar(&asJSON, "json", false, "write one JSON object per event, with every field")

	cmd.AddCommand(list)
	return cmd
}

// auditUser returns the ID of the user that value names: an ID as it is,
// since the user may have been deleted, or the address of an existing user.
func auditUser(ctx context.Context, d app.Deps, t store.Tenant, value string) (uuid.UUID, error) {
	if id, err := uuid.Parse(value); err == nil {
		return id, nil
	}
	u, err := app.FindUser(ctx, d, t.ID, value)
	if err != nil {
		return uuid.Nil(), fmt.Errorf("%w; pass the ID of a deleted user", err)
	}
	return u.ID, nil
}

// writeAuditTable writes the events of page as a table. Sessions and user
// agents are left out, which --json shows.
func writeAuditTable(out io.Writer, page app.AuditEventPage) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIME\tTYPE\tACTOR\tUSER\tCLIENT\tIP\tDETAILS\tID")
	for _, e := range page.Events {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.OccurredAt.Format(time.RFC3339), e.Type,
			e.Actor, orDash(auditUserName(page, e)), orDash(e.ClientID), orDash(e.IP), orDash(auditDetails(e)), e.ID)
	}
	return flush(tw)
}

// auditUserName names the user of e by address, or by ID when the user no
// longer exists, or returns "" when the event is about no user.
func auditUserName(page app.AuditEventPage, e store.AuditEvent) string {
	switch {
	case e.UserID == uuid.Nil():
		return ""
	case page.Emails[e.UserID] != "":
		return page.Emails[e.UserID]
	}
	return e.UserID.String()
}

// auditDetails returns the details of e as name=value pairs, sorted by name.
func auditDetails(e store.AuditEvent) string {
	pairs := make([]string, 0, len(e.Details))
	for _, name := range slices.Sorted(maps.Keys(e.Details)) {
		pairs = append(pairs, name+"="+e.Details[name])
	}
	return strings.Join(pairs, " ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// auditEventJSON is an audit event as `clavis audit list --json` writes it.
type auditEventJSON struct {
	ID         uuid.UUID         `json:"id"`
	OccurredAt time.Time         `json:"occurred_at"`
	Type       string            `json:"type"`
	Actor      store.AuditActor  `json:"actor"`
	UserID     string            `json:"user_id,omitzero"`
	UserEmail  string            `json:"user_email,omitzero"`
	ClientID   string            `json:"client_id,omitzero"`
	SessionID  string            `json:"session_id,omitzero"`
	IP         string            `json:"ip,omitzero"`
	UserAgent  string            `json:"user_agent,omitzero"`
	Details    map[string]string `json:"details,omitzero"`
}

// writeAuditJSON writes the events of page as JSON Lines.
func writeAuditJSON(out io.Writer, page app.AuditEventPage) error {
	for _, e := range page.Events {
		v := auditEventJSON{ID: e.ID, OccurredAt: e.OccurredAt, Type: e.Type, Actor: e.Actor,
			UserEmail: page.Emails[e.UserID], ClientID: e.ClientID, IP: e.IP, UserAgent: e.UserAgent,
			Details: e.Details}
		if e.UserID != uuid.Nil() {
			v.UserID = e.UserID.String()
		}
		if e.SessionID != uuid.Nil() {
			v.SessionID = e.SessionID.String()
		}
		if err := json.MarshalWrite(out, v, json.Deterministic(true)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		if err := write(out, "\n"); err != nil {
			return err
		}
	}
	return nil
}
